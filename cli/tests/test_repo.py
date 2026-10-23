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

"""Sync tests that keep the CLI aligned with the repository and the DDG.

These tests read the real checkout. When one fails, the repository changed in
a way the CLI must follow, or the documentation drifted from the code.
"""

import json
import re
import subprocess

import pytest

import conftest
from stellar_engine import paths
from stellar_engine import repo as repo_lib
from stellar_engine.preflight import checks
from stellar_engine.preflight import regions

_DDG_ROLE_RE = re.compile(r"\((roles/[a-zA-Z.]+)\)")


def _ddg_prerequisites(root):
    text = (root / "docs/ddg.md").read_text(encoding="utf-8")
    start = text.index("## Prerequisites")
    return text[start : text.index("\n## ", start + 1)]


def _slug(heading):
    slug = re.sub(r"[^\w\- ]", "", heading.strip().lower())
    return slug.replace(" ", "-")


def test_find_root_from_nested_directory(repo):
    nested = repo.bootstrap_dir
    assert repo_lib.find_root(nested) == repo.root


def test_find_root_outside_checkout(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_lib, "__file__", str(tmp_path / "repo.py"))
    with pytest.raises(repo_lib.RepoError):
        repo_lib.find_root(tmp_path)


def test_required_roles_match_ddg(repo):
    ddg_roles = set(_DDG_ROLE_RE.findall(_ddg_prerequisites(repo.root)))
    script_roles = set(repo.required_roles())
    assert ddg_roles, "No roles found in the DDG prerequisites section"
    # setIAM.yaml.sample also grants projectDeleter, which the DDG documents
    # in docs/prerequisites.md rather than in its role list.
    assert script_roles - ddg_roles == {"roles/resourcemanager.projectDeleter"}
    assert ddg_roles <= script_roles


def test_required_apis(repo):
    apis = repo.required_apis()
    assert "cloudresourcemanager.googleapis.com" in apis
    assert all(api.endswith(".googleapis.com") for api in apis)


def test_prerequisites_doc_lists_every_script_api(repo):
    text = (repo.root / "docs/prerequisites.md").read_text(encoding="utf-8")
    for api in repo.required_apis():
        assert f"`{api}`" in text


def test_ddg_requires_monitoring_api(repo):
    assert "monitoring.googleapis.com" in _ddg_prerequisites(repo.root)
    assert checks.EXTRA_APIS == ("monitoring.googleapis.com",)


def test_prefix_limit_matches_resman(repo):
    resman = (
        paths.stage_dir(repo.root, paths.RESMAN) / "variables.tf"
    ).read_text(encoding="utf-8")
    assert repo.prefix_max_length() == 7
    assert "Use a maximum of 7 characters for prefix." in resman


def test_tenant_key_limit_matches_resman(repo):
    variables = (
        paths.stage_dir(repo.root, paths.RESMAN) / "variables.tf"
    ).read_text(encoding="utf-8")
    assert repo.tenant_key_max_length() == 6
    assert "Tenant keys must be less than 7 characters." in variables


@pytest.mark.parametrize(
    ("condition", "limit"),
    [("length(k) < 9", 8), ("length(k) <= 9", 9)],
)
def test_tenant_key_limit_reads_both_bounds(tmp_path, condition, limit):
    resman = paths.stage_dir(tmp_path, paths.RESMAN)
    resman.mkdir(parents=True)
    (resman / "variables.tf").write_text(
        'variable "tenants" {\n  validation {\n'
        f"    condition = alltrue([for k, _ in var.tenants : {condition}])\n"
        "  }\n}\n",
        encoding="utf-8",
    )
    assert repo_lib.Repo(tmp_path).tenant_key_max_length() == limit


def test_tenant_key_limit_missing_raises(tmp_path):
    resman = paths.stage_dir(tmp_path, paths.RESMAN)
    resman.mkdir(parents=True)
    (resman / "variables.tf").write_text("", encoding="utf-8")
    with pytest.raises(repo_lib.RepoError):
        repo_lib.Repo(tmp_path).tenant_key_max_length()


def test_default_groups(repo):
    groups = repo.default_groups()
    assert groups["gcp-support"] == "gcp-devops"
    assert {
        "gcp-billing-admins",
        "gcp-devops",
        "gcp-organization-admins",
        "gcp-security-admins",
        "gcp-vpc-network-admins",
    } <= set(groups.values())


def test_log_sinks_and_custom_resources(repo):
    assert "audit-logs" in repo.log_sink_names()
    assert "storage_viewer" in repo.custom_role_ids()
    assert "custom.kmsRotation" in repo.custom_constraint_names()


# The pattern `0-bootstrap/import.sh` greps for a declared constraint.
_IMPORT_SH_KEY_RE = re.compile(r"^([^\s#:%-][^:\s]*):", re.MULTILINE)


def _import_sh_keys(repo):
    keys = set()
    for directory in ("data/org-policies", "data/custom-org-policies"):
        for path in (repo.bootstrap_dir / directory).rglob("*"):
            if path.is_file():
                keys.update(_IMPORT_SH_KEY_RE.findall(path.read_text()))
    return keys


def test_declared_org_policies_match_import_sh(repo):
    declared = repo.declared_org_policies()
    assert declared == sorted(set(declared))
    assert set(declared) == _import_sh_keys(repo)


def test_declared_org_policies_read_templated_files(repo):
    declared = set(repo.declared_org_policies())
    # Keys from data/custom-org-policies, one behind a regime directive.
    assert {
        "iam.allowedPolicyMemberDomains",
        "compute.managed.restrictProtocolForwardingCreationForTypes",
        "gcp.resourceLocations",
    } <= declared
    # Keys from data/org-policies, including a custom constraint.
    assert {"compute.skipDefaultNetworkCreation", "custom.kmsRotation"} <= (
        declared
    )
    assert not any(name.startswith(("%", "-")) for name in declared)


def test_declared_org_policies_follow_the_file_pattern(tmp_path):
    bootstrap = paths.stage_dir(tmp_path, paths.BOOTSTRAP)
    plain = bootstrap / "data/org-policies"
    templated = bootstrap / "data/custom-org-policies"
    plain.mkdir(parents=True)
    templated.mkdir(parents=True)
    (plain / "a_policy.yaml").write_text("b.one:\n  rules: []\n")
    (plain / "notes.yaml").write_text("ignored.key: {}\n")
    (templated / "c_policy.yaml").write_text(
        "---\n# c.comment:\n%{ if x ~}\nc.two:\n  rules:\n"
        "  - allow:\n      values:\n        - ${v}\n%{ endif ~}\n"
    )
    repo = repo_lib.Repo(tmp_path)
    assert repo.declared_org_policies() == ["b.one", "c.two"]


def test_declared_org_policies_cover_import_defaults(repo):
    # The `import_defaults` import block in organization.tf lists the
    # policies of a new organization; the scan must keep each of them.
    text = (repo.bootstrap_dir / "organization.tf").read_text()
    block = text.split("var.org_policies_config.import_defaults", 1)[1]
    block = block.split(": toset([])", 1)[0]
    listed = re.findall(r'^\s*"([^"]+)",', block, re.MULTILINE)
    assert listed
    assert repo.scan_org_policies(listed).kept == tuple(sorted(listed))


def test_scan_org_policies(repo):
    scan = repo.scan_org_policies(
        [
            "storage.uniformBucketLevelAccess",
            "custom.kmsRotation",
            "unmanaged.constraint",
            "iam.allowedPolicyMemberDomains",
            "iam.allowedPolicyMemberDomains",
        ]
    )
    assert scan == repo_lib.OrgPolicyScan(
        kept=(
            "iam.allowedPolicyMemberDomains",
            "storage.uniformBucketLevelAccess",
        ),
        custom=("custom.kmsRotation",),
        undeclared=("unmanaged.constraint",),
    )


def test_scan_org_policies_treat_foreign_custom_as_undeclared(repo):
    scan = repo.scan_org_policies(["custom.kmsRotation", "custom.myOrgRule"])
    assert scan.custom == ("custom.kmsRotation",)
    assert scan.undeclared == ("custom.myOrgRule",)


_MODERATE_GATED = "compute.managed.restrictProtocolForwardingCreationForTypes"


def test_declared_org_policies_follow_the_regime(repo):
    every = set(repo.declared_org_policies())
    moderate = set(repo.declared_org_policies("FEDRAMP_MODERATE"))
    assert set(repo.declared_org_policies("IL5")) == every
    assert _MODERATE_GATED in every - moderate
    # The FedRAMP Moderate branch of an if and else pair still counts.
    assert "gcp.resourceLocations" in moderate
    scan = repo.scan_org_policies([_MODERATE_GATED], "FEDRAMP_MODERATE")
    assert scan.undeclared == (_MODERATE_GATED,)


def test_templated_keys_follow_regime_conditions():
    text = (
        '%{ if !contains(["A"], regime) ~}\nnot.a: 1\n%{ else ~}\n'
        'only.a: 1\n%{ endif ~}\n%{ if contains(["B", "C"], regime) ~}\n'
        "b.or.c: 1\n%{ endif ~}\n%{ if other ~}\nunknown: 1\n%{ endif ~}\n"
        "%{ for d in ds ~}\n- ${d}\n%{ endfor ~}\nalways: 1\n"
    )
    assert repo_lib._templated_keys(text, "A") == {
        "only.a",
        "unknown",
        "always",
    }
    assert repo_lib._templated_keys(text, "B") == {
        "not.a",
        "b.or.c",
        "unknown",
        "always",
    }
    assert repo_lib._templated_keys(text, None) == {
        "not.a",
        "only.a",
        "b.or.c",
        "unknown",
        "always",
    }


_TEMPLATE_VARS = (
    'organization_id = "1", domain_name = "example.com", '
    'customer_id = "C0", drs_tag_name = "x/y", allowed_domains = ["C0"]'
)


@pytest.mark.terraform
@pytest.mark.parametrize("regime", ["FEDRAMP_MODERATE", "IL5"])
def test_templated_keys_match_templatefile(repo, regime, tmp_path):
    # Sync test: Terraform renders the templated files the way
    # `local._org_policies_raw` does, and the keys must match ours.
    directory = repo.bootstrap_dir / "data/custom-org-policies"
    expression = (
        "jsonencode(sort(flatten([for f in fileset("
        f'"{directory}", "*_policy.yaml") : try(keys(yamldecode('
        f'templatefile("{directory}/${{f}}", {{{_TEMPLATE_VARS}, '
        f'regime = "{regime}"}}))), [])])))'
    )
    console = subprocess.run(
        ["terraform", f"-chdir={tmp_path}", "console", "-no-color"],
        input=expression,
        capture_output=True,
        text=True,
        check=False,
    )
    assert console.returncode == 0, console.stderr
    rendered = set(json.loads(json.loads(console.stdout)))
    ours = set()
    for path in directory.glob("*_policy.yaml"):
        ours |= repo_lib._templated_keys(path.read_text(), regime)
    assert rendered == ours


def test_authoritative_roles(repo):
    roles = repo.authoritative_org_roles()
    assert "roles/resourcemanager.organizationAdmin" in roles
    assert "roles/browser" in roles
    assert "roles/billing.creator" in roles
    assert "roles/orgpolicy.policyAdmin" not in roles


def test_conditional_bindings_keep_their_holders(repo):
    bindings = repo.authoritative_bindings()
    assert (
        repo_lib.Holder(repo_lib.HolderKind.DOMAIN)
        in (bindings["roles/browser"])
    )
    assert (
        repo_lib.Holder(repo_lib.HolderKind.BOOTSTRAP_USER)
        in (bindings["roles/logging.admin"])
    )


def _write_stage0(root, organization_iam):
    bootstrap = paths.stage_dir(root, paths.BOOTSTRAP)
    bootstrap.mkdir(parents=True)
    (bootstrap / "automation.tf").write_text(
        'module "automation-project" { source = "x"\n name = "iac-core-0" }\n'
        'module "automation-tf-bootstrap-sa" {\n'
        '  source = "x"\n  iam = { "roles/x" = [] }\n  name = "bootstrap-0"\n'
        "}\n"
    )
    (bootstrap / "organization-iam.tf").write_text(organization_iam)
    module = root / "modules/project"
    module.mkdir(parents=True)
    (module / "versions.tf").write_text(
        'terraform { required_version = ">= 1.11.0, < 2.0.0" }\n'
    )
    return repo_lib.Repo(root)


def test_parsing_ignores_layout(tmp_path):
    fake = _write_stage0(
        tmp_path,
        "locals {\n"
        '  iam_delete_roles = ["roles/billing.creator"]\n'
        "  iam_sa_bindings = { (module.automation-tf-bootstrap-sa.iam_email)"
        ' = { additive = [], authoritative = ["roles/owner"] } }\n'
        "  iam_user_bootstrap_bindings = var.bootstrap_user == null ? {} : {\n"
        '    "user:${var.bootstrap_user}" = {\n'
        "      authoritative = [\n"
        '        "roles/logging.admin"]\n'
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert fake.automation_service_accounts() == {
        "automation-tf-bootstrap-sa": "bootstrap-0"
    }
    assert fake.authoritative_bindings() == {
        "roles/billing.creator": set(),
        "roles/logging.admin": {
            repo_lib.Holder(repo_lib.HolderKind.BOOTSTRAP_USER)
        },
        "roles/owner": {
            repo_lib.Holder(repo_lib.HolderKind.SERVICE_ACCOUNT, "bootstrap-0")
        },
    }
    assert fake.min_terraform_version() == "1.11.0"


def test_unknown_principal_raises(tmp_path):
    fake = _write_stage0(
        tmp_path,
        'locals {\n  iam_x_bindings = { "group:x@example.com" = {'
        ' authoritative = ["roles/owner"] } }\n}\n',
    )
    with pytest.raises(repo_lib.RepoError, match="Unknown principal"):
        fake.authoritative_bindings()


def test_min_terraform_version(repo):
    floor = repo.min_terraform_version()
    assert re.fullmatch(r"\d+\.\d+\.\d+", floor)
    assert tuple(int(part) for part in floor.split(".")) >= (1, 10, 2)


def test_regimes_exist_in_stage0_mapping(repo):
    names = repo.regime_names()
    assert "CJIS" in names
    assert {regime.value for regime in regions.Regime} <= set(names)


@pytest.mark.parametrize(
    "doc",
    sorted(
        {
            value
            for name, value in vars(checks).items()
            if name.startswith(("DOC_", "DDG_")) and "#" in value
        }
    ),
)
def test_doc_links_resolve(doc):
    path, anchor = doc.split("#")
    text = (conftest.REPO_ROOT / path).read_text(encoding="utf-8")
    slugs = {
        _slug(line.lstrip("#"))
        for line in text.splitlines()
        if line.startswith("#")
    }
    assert anchor in slugs, f"{doc} has no matching heading"


def test_stage0_projects(repo):
    projects = repo.stage0_projects()
    assert [project.name for project in projects] == [
        "iac-core-0",
        "audit-logs-0",
        "billing-exp-0",
    ]
    assert [project.module for project in projects] == [
        "automation-project",
        "log-export-project",
        repo_lib.BILLING_EXPORT_MODULE,
    ]
    assert repo.stage0_project_names() == [p.name for p in projects]


@pytest.mark.parametrize(
    ("no_iam", "is_org_level", "expected"),
    [(False, True, True), (True, True, False), (False, False, False)],
)
def test_stage0_project_created_follows_billing_mode(
    repo, no_iam, is_org_level, expected
):
    automation, _, billing_export = repo.stage0_projects()
    flags = {"no_iam": no_iam, "is_org_level": is_org_level}
    assert repo_lib.stage0_project_created(automation, **flags)
    assert repo_lib.stage0_project_created(billing_export, **flags) is expected
