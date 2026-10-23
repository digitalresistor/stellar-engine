# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Answer rules that read their limits and lists from the repository.

The model in `models` checks formats. These rules need the checkout, such
as the prefix limit in the Stage 0 validation block, and report readable
sentences that name the field, so the wizard can re-ask only that section
and `stellar init --non-interactive` can print them all at once.
"""

import pathlib
import re

from stellar_engine import paths
from stellar_engine import repo as repo_lib
from stellar_engine.config import derive
from stellar_engine.config import models
from stellar_engine.preflight import regions
from stellar_engine.render import stages

# Project and service account IDs share this limit, enforced by the
# validation blocks in `modules/project` and `modules/iam-service-account`.
ID_MAX_LENGTH = 30

_BOOTSTRAP_STAGE = paths.STAGES[0]

_IDENT = r"[A-Za-z_][A-Za-z0-9_-]*"
_INDEX = r'\[(?:[0-9]+|"(?:[^"\\]|\\.)*")\]'
_MODULE_SEGMENT_RE = re.compile(rf"module\.{_IDENT}(?:{_INDEX})?\.")
_RESOURCE_RE = re.compile(
    rf"(?P<type>{_IDENT})\.(?P<name>{_IDENT})(?:{_INDEX})?"
)


def import_address_problems(address: str) -> list[str]:
    """Checks the syntax of a Terraform resource address for an import.

    A valid address is zero or more `module.<name>[<index>]` segments
    followed by `<type>.<name>[<index>]`, each index optional and either an
    integer or a quoted string, for example
    `module.billing-export-project[0].google_project.project[0]`.

    Args:
        address: The `to` address of an import block.

    Returns:
        Readable problems, empty when the address is valid.
    """
    if not address or address != address.strip():
        return [f"Import address {address!r} is empty or has spaces."]
    position = 0
    while match := _MODULE_SEGMENT_RE.match(address, position):
        position = match.end()
    if address.startswith("data.", position):
        return [f"Import address {address!r} is a data source."]
    resource = _RESOURCE_RE.fullmatch(address, position)
    if resource is None:
        return [
            f"Import address {address!r} is not a resource address such as "
            "module.<name>[<index>].<type>.<name>[<index>]."
        ]
    if resource.group("type") == "module":
        return [f"Import address {address!r} names a module, not a resource."]
    return []


def problems(answers: models.Answers, repo: repo_lib.Repo) -> list[str]:
    """Checks answers against the limits and lists in the repository.

    Args:
        answers: Answers that already passed model validation.
        repo: The engine checkout that renders them.

    Returns:
        Readable problems, each naming the field, empty when the answers
        are valid.
    """
    found = []
    limit = repo.prefix_max_length()
    if len(answers.prefix) > limit:
        found.append(
            f"prefix {answers.prefix} is longer than the {limit} characters "
            "Stage 0 allows."
        )
    regimes = repo.regime_names()
    regime = answers.compliance.regime
    if regime not in regimes:
        found.append(
            f"compliance.regime {regime} is not one of {', '.join(regimes)}."
        )
    known_groups = repo.default_groups()
    unknown = sorted(set(answers.groups) - set(known_groups))
    if unknown:
        found.append(
            f"groups keys {', '.join(unknown)} are not Stage 0 groups; use "
            f"{', '.join(sorted(known_groups))}."
        )
    found.extend(_region_problems(answers))
    found.extend(_tenant_problems(answers, repo))
    for stage, imports in answers.imports.items():
        for address in imports:
            found.extend(
                f"imports.{stage}: {problem}"
                for problem in import_address_problems(address)
            )
    found.extend(_stage0_import_id_problems(answers, repo))
    found.extend(stages.override_problems(answers, repo))
    return found


def _stage0_import_id_problems(answers, repo):
    """Checks each Stage 0 project import ID against the derived ID.

    The `modules/project` call sets `project_id` from the prefix and the
    project name, and a different `project_id` forces a new project. An
    import of any other ID would make Terraform replace, and so delete, the
    adopted project.
    """
    imports = answers.imports.get(_BOOTSTRAP_STAGE, {})
    found = []
    for project in repo.stage0_projects():
        import_id = imports.get(project.address)
        expected = derive.stage0_project_id(answers, project)
        if import_id is not None and import_id != expected:
            found.append(
                f"imports.{_BOOTSTRAP_STAGE}: {project.address} imports "
                f"{import_id}, but Stage 0 names that project {expected} "
                f"from prefix {answers.prefix}, so Terraform would replace "
                f"the imported project; set the import ID to {expected}."
            )
    return found


def _region_problems(answers):
    if answers.compliance.allow_unlisted_region:
        return []
    allowed = regions.supported_regions(answers.compliance.regime)
    if allowed is None or answers.region in allowed:
        return []
    return [
        f"region {answers.region} is not an Assured Workloads region for "
        f"{answers.compliance.regime}; use one of {', '.join(sorted(allowed))}"
        " or set compliance.allow_unlisted_region after checking "
        f"{regions.LOCATIONS_DOC}."
    ]


def _tenant_problems(answers, repo):
    found = []
    limit = repo.tenant_key_max_length()
    for tenant in answers.resman.tenants:
        if len(tenant) > limit:
            found.append(
                f"resman.tenants key {tenant} is longer than the {limit} "
                "characters Stage 1 allows."
            )
    for kind, ids in (
        ("project ID", derive.tenant_project_ids(answers)),
        ("service account ID", derive.tenant_service_account_ids(answers)),
    ):
        for tenant, names in ids.items():
            found.extend(
                f"resman.tenants.{tenant}: Stage 1 {kind} {name} is "
                f"{len(name)} characters, over the {ID_MAX_LENGTH} limit; "
                "shorten the prefix, env key or tenant key."
                for name in names
                if len(name) > ID_MAX_LENGTH
            )
    return found


def home_references(answers: models.Answers, home: pathlib.Path) -> list[str]:
    """Finds answer values that point into the home folder.

    stellar derives home-relative values such as `outputs_location` at
    render time, so a copied or moved home repoints on the next render. A
    stored path into the home would keep pointing at the old location. The
    recorded `engine.path` is exempt.

    Args:
        answers: The answers to save.
        home: The home folder.

    Returns:
        Readable problems naming each offending field.
    """
    root = home.expanduser().resolve()
    # stellar records the engine checkout itself and render compares it
    # with the checkout in use, so a home that holds the engine, such as a
    # private home repository with the engine as a submodule, is fine.
    data = answers.model_dump(
        mode="json", exclude_none=True, exclude={"engine"}
    )
    return [
        f"{field} points into the home {root}; stellar derives home paths "
        "at render time, so remove it."
        for field, value in _strings(data, "")
        if _is_inside(value, root)
    ]


def _strings(value, field):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, f"{field}.{key}" if field else key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{field}[{index}]")
    elif isinstance(value, str):
        yield field, value


def _is_inside(value, root):
    # Only absolute and home-directory paths are unambiguous; a relative
    # value such as a tenant key is not a path.
    if not value.startswith(("/", "~")):
        return False
    path = pathlib.Path(value).expanduser().resolve()
    return path == root or path.is_relative_to(root)
