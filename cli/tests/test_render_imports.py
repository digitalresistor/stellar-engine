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

"""Tests for the Terraform import blocks of pre-created resources."""

import shutil
import stat

import hcl2
import pytest

import conftest
import render_fixtures
from stellar_engine import workspace
from stellar_engine.render import imports

_AUTOMATION = "module.automation-project.google_project.project[0]"
_LOGGING = "module.log-export-project.google_project.project[0]"
_BILLING = "module.billing-export-project[0].google_project.project[0]"


def _with_imports(name="lab", stage="0-bootstrap", entries=None, **updates):
    data = {stage: entries} if entries is not None else {}
    return render_fixtures.load_answers(name, imports=data, **updates)


def test_filename():
    assert imports.filename("0") == "0-bootstrap-imports.tf"
    assert imports.filename("1-resman") == "1-resman-imports.tf"
    with pytest.raises(ValueError, match="2-networking"):
        imports.filename("2-networking")


def test_dumps_snapshot(snapshot):
    answers = render_fixtures.load_answers("lab")
    text = imports.dumps(
        answers.imports["0-bootstrap"],
        imports.header("0-bootstrap", answers.prefix),
    )
    assert text == snapshot


def test_dumps_sorts_and_quotes():
    text = imports.dumps({_LOGGING: "b", _AUTOMATION: 'a"${x}'}, ["# header"])
    assert text == (
        "# header\n\n"
        "import {\n"
        f"  to = {_AUTOMATION}\n"
        '  id = "a\\"$${x}"\n'
        "}\n\n"
        "import {\n"
        f"  to = {_LOGGING}\n"
        '  id = "b"\n'
        "}\n"
    )


def test_dumps_parses_as_hcl():
    parsed = hcl2.loads(imports.dumps({_BILLING: "p", _AUTOMATION: "q"}, []))
    assert [block["id"] for block in parsed["import"]] == ['"q"', '"p"']


def test_dumps_empty():
    assert imports.dumps({}, ["# header"]) == ""


@pytest.mark.parametrize(
    "address",
    [
        "google_project",
        "module.automation-project",
        "module.x.data.google_project.p",
        'google_project.project["a"] extra',
        "google_project.project[0",
        "",
    ],
)
def test_dumps_rejects_invalid_address(address):
    with pytest.raises(imports.ImportBlockError):
        imports.dumps({address: "id"}, [])


def test_valid_address_forms():
    answers = _with_imports(
        entries={
            _BILLING: "p",
            'module.a["k"].google_project.project["x"]': "q",
            "google_project.plain": "r",
        },
        billing={"account_id": conftest.BILLING},
    )
    assert imports.validate(answers, "0") == []


def test_problems_name_the_stage():
    answers = _with_imports(entries={"module.only": "x"})
    found = imports.problems(answers, "0")
    assert len(found) == 1
    assert found[0].startswith("imports.0-bootstrap: ")
    assert imports.warnings(answers, "0") == []


def test_warns_on_billing_export_without_billing_iam():
    answers = _with_imports(entries={_BILLING: "lab1-prod-billing-exp-0"})
    assert answers.billing.no_iam
    found = imports.validate(answers, "0-bootstrap")
    assert len(found) == 1
    assert found[0].startswith(imports.WARNING_PREFIX)
    assert "billing.no_iam" in found[0]
    assert imports.problems(answers, "0-bootstrap") == []


def test_warns_on_billing_export_outside_the_org():
    answers = _with_imports("il4", entries={_BILLING: "il4-prod-billing-exp-0"})
    assert len(imports.warnings(answers, "0")) == 1


def test_no_warning_when_billing_export_exists():
    answers = _with_imports(
        entries={_BILLING: "lab1-prod-billing-exp-0"},
        billing={"account_id": conftest.BILLING},
    )
    assert imports.validate(answers, "0") == []


def test_write_creates_file(tmp_path):
    answers = render_fixtures.load_answers("lab")
    path = imports.write(tmp_path, "0", answers)
    assert path is not None
    assert path == tmp_path / "0-bootstrap-imports.tf"
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    text = path.read_text(encoding="utf-8")
    assert text == imports.dumps(
        answers.imports["0-bootstrap"], imports.header("0", "lab1")
    )
    assert text.startswith(
        "# stellar render writes this file from envs/lab1/answers.yaml "
        "imports.0-bootstrap.\n"
    )


def test_write_replaces_generated_file(tmp_path):
    imports.write(tmp_path, "0", render_fixtures.load_answers("lab"))
    answers = _with_imports(entries={_AUTOMATION: "other-id"})
    path = imports.write(tmp_path, "0", answers)
    assert path is not None
    assert '"other-id"' in path.read_text(encoding="utf-8")
    assert _LOGGING not in path.read_text(encoding="utf-8")


def test_write_removes_generated_file_when_empty(tmp_path):
    path = imports.write(tmp_path, "0", render_fixtures.load_answers("lab"))
    assert path is not None
    assert imports.write(tmp_path, "0", _with_imports()) is None
    assert not path.exists()
    # Nothing to remove the second time.
    assert imports.write(tmp_path, "0", _with_imports()) is None


def test_write_ignores_other_stages(tmp_path):
    assert (
        imports.write(tmp_path, "1-resman", render_fixtures.load_answers("lab"))
        is None
    )
    assert list(tmp_path.iterdir()) == []


def test_write_refuses_operator_file(tmp_path):
    target = tmp_path / "0-bootstrap-imports.tf"
    target.write_text("# mine\n", encoding="utf-8")
    with pytest.raises(imports.ImportBlockError, match="did not write"):
        imports.write(tmp_path, "0", render_fixtures.load_answers("lab"))
    assert target.read_text(encoding="utf-8") == "# mine\n"


def test_write_keeps_operator_file_when_empty(tmp_path):
    target = tmp_path / "0-bootstrap-imports.tf"
    target.write_text("# mine\n", encoding="utf-8")
    assert imports.write(tmp_path, "0", _with_imports()) is None
    assert target.read_text(encoding="utf-8") == "# mine\n"


def test_write_refuses_symlink(tmp_path):
    real = tmp_path / "real.tf"
    real.write_text(
        imports.dumps({_AUTOMATION: "x"}, imports.header("0", "lab1")),
        encoding="utf-8",
    )
    (tmp_path / "0-bootstrap-imports.tf").symlink_to(real)
    with pytest.raises(imports.ImportBlockError):
        imports.write(tmp_path, "0", render_fixtures.load_answers("lab"))


def test_write_rejects_invalid_address(tmp_path):
    answers = _with_imports(entries={"module.only": "x"})
    with pytest.raises(imports.ImportBlockError):
        imports.write(tmp_path, "0", answers)
    assert list(tmp_path.iterdir()) == []


def test_workspace_sync_keeps_imports_file(tmp_path):
    answers = render_fixtures.load_answers("lab")
    env = render_fixtures.env_paths(answers, home=tmp_path)
    workspace.sync(env, conftest.REPO_ROOT, "0-bootstrap")
    path = imports.write(env.workspace("0"), "0", answers)
    assert path is not None
    report = workspace.sync(env, conftest.REPO_ROOT, "0-bootstrap")
    assert path.name not in report.removed + report.conflicts
    assert path.is_file()
    assert not path.is_symlink()


@pytest.mark.terraform
@pytest.mark.skipif(
    shutil.which("terraform") is None,
    reason="terraform is missing",
)
def test_imports_validate_in_bootstrap_workspace(tmp_path):
    answers = _with_imports(
        entries={
            _AUTOMATION: "lab1-prod-iac-core-0",
            _LOGGING: "lab1-prod-audit-logs-0",
            _BILLING: "lab1-prod-billing-exp-0",
        }
    )
    env = render_fixtures.env_paths(answers, home=tmp_path)
    workspace.sync(env, conftest.REPO_ROOT, "0-bootstrap")
    ws = env.workspace("0-bootstrap")
    imports.write(ws, "0", answers)
    init = render_fixtures.terraform(
        ws, "init", "-backend=false", "-input=false"
    )
    assert init.returncode == 0, init.stderr
    validate = render_fixtures.terraform(ws, "validate")
    assert validate.returncode == 0, validate.stderr
    # The same check rejects an address the configuration does not define,
    # so the success above proves the addresses are real.
    wrong = _with_imports(entries={"module.no-such.google_project.p": "x"})
    imports.write(ws, "0", wrong)
    invalid = render_fixtures.terraform(ws, "validate")
    assert invalid.returncode != 0
    assert "no-such" in invalid.stderr + invalid.stdout
