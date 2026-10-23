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

"""Writes Terraform `import` blocks for resources that already exist.

Some organizations pre-create the Stage 0 projects, because linking a
project to their billing account needs a human. Terraform must adopt those
projects instead of creating them, so the answers list each resource
address with its import ID and the renderer turns them into a
`<stage>-imports.tf` file in the workspace. The file is a real file owned
by the environment; `workspace.sync` never links or removes it.

Stage 0 also adopts the organization policies that `stellar imports scan`
records in `existing_org_policies`, replacing `0-bootstrap/import.sh`.
"""

from collections.abc import Mapping, Sequence
import os
import pathlib
import tempfile

from stellar_engine import paths
from stellar_engine.config import models
from stellar_engine.config import validate as validate_lib
from stellar_engine.render import hcl

FILENAME_TEMPLATE = "{stage}-imports.tf"
WARNING_PREFIX = "Warning: "
# Marks files this module wrote, so it never replaces or removes an
# operator's own file of the same name.
_MARKER = "# stellar render writes this file from envs/"
_FILE_MODE = 0o644
# `module "billing-export-project"` in `0-bootstrap/billing.tf` has
# `count = 0` unless `local.billing_mode` is "org", which needs `no_iam`
# false and `is_org_level` true.
_BILLING_EXPORT_MODULE = "module.billing-export-project[0]."
_BOOTSTRAP_STAGE = paths.STAGES[0]
# The stage locals that the import file adds; the prefix keeps them apart
# from the locals of the stage code.
_POLICIES_LOCAL = "stellar_existing_org_policies"
_IMPORTS_LOCAL = "stellar_org_policy_imports"
_ORG_POLICY_COMMENT = (
    "# stellar imports scan found these organization policies, which Stage 0",
    "# declares. The first apply passes bootstrap_user, so Stage 0 manages no",
    "# organization policies yet and nothing is imported. The final apply",
    "# adopts the policies that already exist instead of failing to create",
    "# them. The filter drops constraints that the regime templates omit.",
)


class ImportBlockError(Exception):
    """Raised when import blocks cannot be rendered or written."""


def filename(stage: str) -> str:
    """Returns the import file name of a stage.

    For example `0-bootstrap-imports.tf` for `0-bootstrap` or its alias `0`.

    Raises:
        ValueError: If the stage name is unknown.
    """
    return FILENAME_TEMPLATE.format(stage=paths.resolve_stage(stage))


def problems(answers: models.Answers, stage: str) -> list[str]:
    """Returns the errors that stop the import blocks of a stage.

    Args:
        answers: The environment answers.
        stage: Stage name or alias.

    Returns:
        One readable sentence per invalid address.
    """
    stage = paths.resolve_stage(stage)
    return [
        f"imports.{stage}: {problem}"
        for address in answers.imports.get(stage, {})
        for problem in validate_lib.import_address_problems(address)
    ]


def warnings(answers: models.Answers, stage: str) -> list[str]:
    """Returns non-fatal findings about the import blocks of a stage.

    An import into a resource that the configuration does not create fails
    at plan time, so the operator learns before running Terraform.

    Args:
        answers: The environment answers.
        stage: Stage name or alias.

    Returns:
        Readable sentences, each starting with `WARNING_PREFIX`.
    """
    stage = paths.resolve_stage(stage)
    billing = answers.billing
    if stage != "0-bootstrap" or (not billing.no_iam and billing.is_org_level):
        return []
    return [
        f"{WARNING_PREFIX}imports.{stage}: {address} targets the billing "
        "export project, which Stage 0 only creates when billing.no_iam is "
        "false and billing.is_org_level is true, so the import would fail."
        for address in answers.imports.get(stage, {})
        if address.startswith(_BILLING_EXPORT_MODULE)
    ]


def validate(answers: models.Answers, stage: str) -> list[str]:
    """Returns the problems followed by the warnings of a stage's imports.

    Warnings start with `WARNING_PREFIX`; use `problems` and `warnings` to
    tell them apart programmatically.

    Args:
        answers: The environment answers.
        stage: Stage name or alias.
    """
    return problems(answers, stage) + warnings(answers, stage)


def header(stage: str, prefix: str, *, org_policies: bool = False) -> list[str]:
    """Returns the generated header of a stage's import file.

    Args:
        stage: Stage name or alias.
        prefix: Environment prefix.
        org_policies: Whether the file also imports `existing_org_policies`.
    """
    stage = paths.resolve_stage(stage)
    sources = f"imports.{stage}"
    if org_policies:
        sources += " and existing_org_policies"
    return [
        f"{_MARKER}{prefix}/answers.yaml {sources}.",
        "# Edit answers.yaml and rerun stellar render; the next render "
        "replaces manual edits.",
    ]


def _org_policy_blocks(names: Sequence[str]) -> list[str]:
    """Returns the locals and the `import` block of the organization policies.

    The import block mirrors the `import_defaults` block in
    `0-bootstrap/organization.tf`, which targets the same resources.
    """
    listed = [f"    {hcl.quote(name)}," for name in sorted(set(names))]
    locals_block = "\n".join(
        [
            *_ORG_POLICY_COMMENT,
            "locals {",
            f"  {_POLICIES_LOCAL} = [",
            *listed,
            "  ]",
            f"  {_IMPORTS_LOCAL} = toset([",
            f"    for name in local.{_POLICIES_LOCAL} :",
            "    name if contains(keys(local.org_policies), name)",
            "  ])",
            "}",
        ]
    )
    import_block = "\n".join(
        [
            "import {",
            "  for_each = (",
            "    var.bootstrap_user == null",
            f"    ? local.{_IMPORTS_LOCAL}",
            "    : toset([])",
            "  )",
            '  id = "organizations/${var.organization.id}/policies/'
            '${each.key}"',
            "  to = module.organization.google_org_policy_policy.default"
            "[each.key]",
            "}",
        ]
    )
    return [locals_block, import_block]


def dumps(
    imports: Mapping[str, str],
    header: Sequence[str],
    org_policies: Sequence[str] = (),
) -> str:
    """Renders one `import` block per entry, sorted by address.

    Args:
        imports: Resource address mapped to import ID.
        header: Comment lines emitted at the top of the file.
        org_policies: Constraints of existing organization policies that
            Stage 0 imports on its final apply, only for `0-bootstrap`.

    Returns:
        The HCL text in `terraform fmt` canonical form, empty when there
        are no imports and no organization policies.

    Raises:
        ImportBlockError: If an address is not a resource address.
    """
    if not imports and not org_policies:
        return ""
    found = [
        problem
        for address in imports
        for problem in validate_lib.import_address_problems(address)
    ]
    if found:
        raise ImportBlockError(" ".join(found))
    blocks = ["\n".join(header)] if header else []
    # `to` is a reference, not a string, so the address stays unquoted.
    blocks.extend(
        "\n".join(
            [
                "import {",
                f"  to = {address}",
                f"  id = {hcl.quote(imports[address])}",
                "}",
            ]
        )
        for address in sorted(imports)
    )
    if org_policies:
        blocks.extend(_org_policy_blocks(org_policies))
    return "\n\n".join(blocks) + "\n"


def text(answers: models.Answers, stage: str) -> str:
    """Returns the import file of a stage for the answers.

    Args:
        answers: The environment answers.
        stage: Stage name or alias.

    Returns:
        The file text, empty when the stage imports nothing.

    Raises:
        ImportBlockError: If an address is not a resource address.
    """
    stage = paths.resolve_stage(stage)
    policies = (
        answers.existing_org_policies if stage == _BOOTSTRAP_STAGE else []
    )
    return dumps(
        answers.imports.get(stage, {}),
        header(stage, answers.prefix, org_policies=bool(policies)),
        policies,
    )


def _is_generated(path: pathlib.Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    with path.open(encoding="utf-8") as handle:
        return handle.readline().startswith(_MARKER)


def _write_atomic(path: pathlib.Path, text: str) -> None:
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(temp, _FILE_MODE)
        os.replace(temp, path)
    except BaseException:
        pathlib.Path(temp).unlink(missing_ok=True)
        raise


def write(
    workspace: pathlib.Path, stage: str, answers: models.Answers
) -> pathlib.Path | None:
    """Writes or removes the import file of a stage in its workspace.

    Every render replaces the file, so it always matches the answers.
    When the stage has no imports and no organization policies to adopt, a
    previously generated file is removed, because a stale import block
    would adopt a resource the answers no longer name.

    Args:
        workspace: The stage workspace directory.
        stage: Stage name or alias.
        answers: The environment answers.

    Returns:
        The written file, or None when the stage imports nothing.

    Raises:
        ImportBlockError: If an address is invalid, or a file of the same
            name exists that stellar did not generate.
    """
    stage = paths.resolve_stage(stage)
    target = workspace / filename(stage)
    content = text(answers, stage)
    exists = target.exists() or target.is_symlink()
    if not content:
        if exists and _is_generated(target):
            target.unlink()
        return None
    if exists and not _is_generated(target):
        raise ImportBlockError(
            f"stellar did not write {target}; move it away or delete it, "
            "then rerun stellar render."
        )
    _write_atomic(target, content)
    return target
