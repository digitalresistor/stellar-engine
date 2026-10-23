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


def header(stage: str, prefix: str) -> list[str]:
    """Returns the generated header of a stage's import file.

    Args:
        stage: Stage name or alias.
        prefix: Environment prefix.
    """
    stage = paths.resolve_stage(stage)
    return [
        f"{_MARKER}{prefix}/answers.yaml imports.{stage}.",
        "# Edit answers.yaml and rerun stellar render; the next render "
        "replaces manual edits.",
    ]


def dumps(imports: Mapping[str, str], header: Sequence[str]) -> str:
    """Renders one `import` block per entry, sorted by address.

    Args:
        imports: Resource address mapped to import ID.
        header: Comment lines emitted at the top of the file.

    Returns:
        The HCL text in `terraform fmt` canonical form, empty when there
        are no imports.

    Raises:
        ImportBlockError: If an address is not a resource address.
    """
    if not imports:
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
    return "\n\n".join(blocks) + "\n"


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
    When the stage has no imports, a previously generated file is removed,
    because a stale import block would adopt a resource the answers no
    longer name.

    Args:
        workspace: The stage workspace directory.
        stage: Stage name or alias.
        answers: The environment answers.

    Returns:
        The written file, or None when the stage has no imports.

    Raises:
        ImportBlockError: If an address is invalid, or a file of the same
            name exists that stellar did not generate.
    """
    stage = paths.resolve_stage(stage)
    target = workspace / filename(stage)
    entries = answers.imports.get(stage, {})
    exists = target.exists() or target.is_symlink()
    if not entries:
        if exists and _is_generated(target):
            target.unlink()
        return None
    if exists and not _is_generated(target):
        raise ImportBlockError(
            f"stellar did not write {target}; move it away or delete it, "
            "then rerun stellar render."
        )
    _write_atomic(target, dumps(entries, header(stage, answers.prefix)))
    return target
