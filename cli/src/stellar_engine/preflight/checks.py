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

"""Preflight checks for the prerequisites in `docs/ddg.md`.

Each check takes a `Context` and returns a list of `CheckResult`. Checks never
change anything; when a prerequisite is missing they explain how to fix it.
"""

from collections.abc import Mapping
import dataclasses
import re

from packaging import version

from stellar_engine import repo as repo_lib
from stellar_engine import tools as tools_lib
from stellar_engine.gcp import api
from stellar_engine.preflight import inputs as inputs_lib
from stellar_engine.preflight import regions
from stellar_engine.preflight import result

Category = result.Category
CheckResult = result.CheckResult
Status = result.Status

DDG_PREREQUISITES = "docs/ddg.md#prerequisites"
DOC_WORKSTATION = "docs/prerequisites.md#local-workstation"
DOC_ORGANIZATION = "docs/prerequisites.md#google-cloud-organization"
DOC_BOOTSTRAP = "docs/prerequisites.md#bootstrap-project"
DOC_APIS = "docs/prerequisites.md#required-apis"
DOC_IAM = "docs/prerequisites.md#initial-iam-grants"
DOC_GROUPS = "docs/prerequisites.md#administrative-groups"
DOC_FEATURES = "docs/prerequisites.md#organization-features-and-quotas"
DOC_TROUBLESHOOTING = "docs/ddg.md#appendices"

# DDG prerequisite that enableServices.sh does not cover yet.
EXTRA_APIS = ("monitoring.googleapis.com",)
BILLING_ADMIN_ROLE = "roles/billing.admin"
IMPERSONATION_ENV_VARS = (
    "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
    "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
)
_SCHEME_RE = re.compile(r"^[a-zA-Z]+:")
_PREFIX_RE = re.compile(r"^[a-z](?:[a-z0-9-]*[a-z0-9])?$")
_REGION_RE = re.compile(r"^us-[a-z]+[0-9]+$")
_MAX_LISTED = 10


@dataclasses.dataclass
class Context:
    """State shared by the checks of one preflight run.

    Attributes:
        inputs: Values supplied by the operator.
        cloud: Read-only Google Cloud facade.
        tools: Local tool queries.
        repo: Deployment facts parsed from the repository.
        environ: Process environment, for impersonation variables.
        org: Organization resolved by the organization check.
        principal: Identity resolved by the identity check.
    """

    inputs: inputs_lib.PreflightInputs
    cloud: api.CloudApi
    tools: tools_lib.LocalTools
    repo: repo_lib.Repo
    environ: Mapping[str, str]
    org: api.Organization | None = None
    principal: api.Principal | None = None

    @property
    def domain(self):
        """Returns the domain from the inputs or the resolved organization."""
        if self.inputs.domain:
            return self.inputs.domain
        return self.org.domain if self.org else None


def _skip(check_id, category, title, needs):
    return CheckResult(
        check_id,
        category,
        title,
        Status.SKIP,
        f"Not checked; pass {needs} to enable this check.",
    )


def _listed(items):
    items = sorted(items)
    shown = ", ".join(items[:_MAX_LISTED])
    if len(items) > _MAX_LISTED:
        shown += f", and {len(items) - _MAX_LISTED} more"
    return shown


def check_tools(ctx):
    """Checks that Terraform and the Google Cloud SDK are installed."""
    results = []
    minimum = ctx.repo.min_terraform_version()
    installed = ctx.tools.terraform_version()
    if installed is None:
        status, detail = Status.FAIL, "Terraform is not installed."
    elif version.Version(installed) < version.Version(minimum):
        status = Status.FAIL
        detail = f"Terraform {installed} is older than {minimum}."
    else:
        status = Status.PASS
        detail = f"Terraform {installed} meets the {minimum} minimum."
    results.append(
        CheckResult(
            "tools.terraform",
            Category.TOOLS,
            "Terraform version",
            status,
            detail,
            remedy=f"Install Terraform {minimum} or newer.",
            doc=DOC_WORKSTATION,
        )
    )
    jq = ctx.tools.jq_version()
    results.append(
        CheckResult(
            "tools.jq",
            Category.TOOLS,
            "jq",
            Status.PASS if jq else Status.WARN,
            f"{jq} is installed."
            if jq
            else "jq is not installed. The setIAM.sh and sa_lockdown.sh "
            "scripts in the manual DDG flow need it.",
            remedy="Install jq.",
            doc=DOC_WORKSTATION,
        )
    )
    gcloud = ctx.tools.gcloud_version()
    results.append(
        CheckResult(
            "tools.gcloud",
            Category.TOOLS,
            "Google Cloud SDK",
            Status.PASS if gcloud else Status.FAIL,
            f"Google Cloud SDK {gcloud} is installed."
            if gcloud
            else "The gcloud command is not installed.",
            remedy="Install the Google Cloud SDK.",
            doc=DOC_WORKSTATION,
        )
    )
    return results


def check_identity(ctx):
    """Checks the gcloud account and Application Default Credentials."""
    results = []
    account = ctx.tools.gcloud_account()
    results.append(
        CheckResult(
            "identity.gcloud",
            Category.IDENTITY,
            "Active gcloud account",
            Status.PASS if account else Status.FAIL,
            f"gcloud is signed in as {account}."
            if account
            else "gcloud has no active account.",
            remedy="Run `gcloud auth login`.",
            doc=DOC_WORKSTATION,
        )
    )
    try:
        ctx.principal = ctx.cloud.adc_principal()
    except api.CredentialsError as error:
        results.append(
            CheckResult(
                "identity.adc",
                Category.IDENTITY,
                "Application Default Credentials",
                Status.FAIL,
                f"Application Default Credentials are not usable: {error}",
                remedy="Run `gcloud auth application-default login`.",
                doc=DOC_WORKSTATION,
            )
        )
        return results
    principal = ctx.principal
    results.append(
        CheckResult(
            "identity.adc",
            Category.IDENTITY,
            "Application Default Credentials",
            Status.PASS if principal.email else Status.WARN,
            f"Terraform will run as {principal.email}."
            if principal.email
            else "The identity behind the credentials cannot be determined.",
            doc=DOC_WORKSTATION,
        )
    )
    if account and principal.email:
        same = account.lower() == principal.email.lower()
        results.append(
            CheckResult(
                "identity.match",
                Category.IDENTITY,
                "gcloud and Terraform use the same identity",
                Status.PASS if same else Status.FAIL,
                "Both use the same account."
                if same
                else (
                    f"gcloud uses {account} but Terraform uses "
                    f"{principal.email}."
                ),
                remedy=(
                    "Run `gcloud auth application-default login` as the "
                    "account that gcloud uses."
                ),
                doc=DOC_WORKSTATION,
            )
        )
    if principal.kind == api.PrincipalKind.SERVICE_ACCOUNT:
        status = (
            Status.WARN if ctx.inputs.allow_service_account else Status.FAIL
        )
        results.append(
            CheckResult(
                "identity.user",
                Category.IDENTITY,
                "Deploying identity is a user",
                status,
                (
                    f"{principal.email} is a service account. Stage 0 grants "
                    "`bootstrap_user` as a `user:` principal, so the first "
                    "apply needs a user account."
                ),
                remedy="Sign in with a user account that has the DDG roles.",
                doc=DDG_PREREQUISITES,
            )
        )
    elif principal.kind == api.PrincipalKind.USER:
        results.append(
            CheckResult(
                "identity.user",
                Category.IDENTITY,
                "Deploying identity is a user",
                Status.PASS,
                f"{principal.email} is a user account.",
            )
        )
    project = ctx.inputs.bootstrap_project
    active_project = ctx.tools.gcloud_project()
    if project and active_project != project:
        results.append(
            CheckResult(
                "identity.project",
                Category.IDENTITY,
                "Active gcloud project",
                Status.WARN,
                f"The active gcloud project is {active_project or 'unset'}, "
                f"not the bootstrap project {project}.",
                remedy=f"Run `gcloud config set project {project}`.",
                doc=DOC_WORKSTATION,
            )
        )
    elif project:
        results.append(
            CheckResult(
                "identity.project",
                Category.IDENTITY,
                "Active gcloud project",
                Status.PASS,
                f"The active gcloud project is {project}.",
            )
        )
    impersonating = {
        name: ctx.environ[name]
        for name in IMPERSONATION_ENV_VARS
        if ctx.environ.get(name)
    }
    results.append(
        CheckResult(
            "identity.impersonation",
            Category.IDENTITY,
            "No stale service account impersonation",
            Status.WARN if impersonating else Status.PASS,
            "Impersonation is set: "
            + ", ".join(f"{k}={v}" for k, v in impersonating.items())
            if impersonating
            else "No impersonation environment variables are set.",
            remedy="Run `unset " + " ".join(IMPERSONATION_ENV_VARS) + "`.",
            doc=DOC_TROUBLESHOOTING,
        )
    )
    return results


def check_organization(ctx):
    """Resolves the organization and compares it with the inputs."""
    category = Category.ORGANIZATION
    org_id = ctx.inputs.org_id
    if org_id is None:
        try:
            orgs = ctx.cloud.search_organizations()
        except api.CloudError as error:
            orgs, detail = [], f"Cannot list organizations: {error}"
        else:
            detail = (
                "No organization is visible to this identity."
                if not orgs
                else "More than one organization is visible: "
                + _listed(org.org_id for org in orgs)
            )
        if len(orgs) != 1:
            return [
                CheckResult(
                    "org.access",
                    category,
                    "Organization access",
                    Status.FAIL,
                    detail,
                    remedy="Pass --org with the numeric organization ID.",
                    doc=DOC_ORGANIZATION,
                )
            ]
        ctx.org = orgs[0]
        found = f"Using organization {ctx.org.org_id} ({ctx.org.domain})."
    else:
        try:
            ctx.org = ctx.cloud.get_organization(org_id)
        except api.CloudError as error:
            ctx.org, found = None, f"Access denied: {error}"
        else:
            found = (
                f"Organization {org_id} is {ctx.org.domain}." if ctx.org else ""
            )
        if ctx.org is None:
            return [
                CheckResult(
                    "org.access",
                    category,
                    "Organization access",
                    Status.FAIL,
                    found or f"Organization {org_id} does not exist.",
                    remedy=(
                        "Check the organization ID with "
                        "`gcloud organizations list`."
                    ),
                    doc=DOC_ORGANIZATION,
                )
            ]
    results = [
        CheckResult(
            "org.access",
            category,
            "Organization access",
            Status.PASS,
            found,
            doc=DOC_ORGANIZATION,
        )
    ]
    for field, actual, label in (
        ("domain", ctx.org.domain, "Organization domain"),
        ("customer_id", ctx.org.customer_id, "Directory customer ID"),
    ):
        expected = getattr(ctx.inputs, field)
        if expected is None:
            continue
        same = expected.lower() == actual.lower()
        results.append(
            CheckResult(
                f"org.{field}",
                category,
                label,
                Status.PASS if same else Status.FAIL,
                f"{label} is {actual}."
                if same
                else f"{label} is {actual}, not {expected}.",
                remedy="Fix the value to match `gcloud organizations list`.",
                doc=DOC_ORGANIZATION,
            )
        )
    return results


def _role_result(role, testable, granted, scope):
    missing = sorted(testable - granted)
    if not testable:
        return CheckResult(
            f"iam.{role}",
            Category.IAM,
            role,
            Status.WARN,
            f"None of this role's permissions can be tested on the {scope}.",
            remedy="Confirm the grant in the console.",
            doc=DOC_IAM,
        )
    if missing:
        return CheckResult(
            f"iam.{role}",
            Category.IAM,
            role,
            Status.FAIL,
            f"Missing {len(missing)} of {len(testable)} permissions on the "
            f"{scope}, including {_listed(missing[:3])}.",
            remedy=(
                "Grant the role at the organization level, for example with "
                "`fast/stages-aw/0-bootstrap/setIAM.sh <email> <org_id>`."
            ),
            doc=DOC_IAM,
        )
    return CheckResult(
        f"iam.{role}",
        Category.IAM,
        role,
        Status.PASS,
        f"All {len(testable)} testable permissions are granted on the {scope}.",
        doc=DOC_IAM,
    )


def check_iam_roles(ctx):
    """Checks that the caller holds every role that `setIAM.sh` grants.

    The check tests effective permissions with testIamPermissions, so it is
    correct whether a role is granted directly, through a group, or by
    inheritance. Billing Account Administrator may be granted on the billing
    account instead of the organization, so it is tested there when a
    billing account is given.
    """
    if ctx.org is None:
        return [_skip("iam.roles", Category.IAM, "Organization roles", "--org")]
    try:
        return _role_results(ctx)
    except api.CloudError as error:
        return [
            CheckResult(
                "iam.roles",
                Category.IAM,
                "Organization roles",
                Status.FAIL,
                f"Cannot test the organization roles: {error}",
                doc=DOC_IAM,
            )
        ]


def _role_results(ctx):
    org_resource = (
        f"//cloudresourcemanager.googleapis.com/organizations/{ctx.org.org_id}"
    )
    org_testable = ctx.cloud.testable_permissions(org_resource)
    roles = ctx.repo.required_roles()
    billing_account = ctx.inputs.billing_account
    per_role = {}
    for role in roles:
        if role == BILLING_ADMIN_ROLE and billing_account:
            continue
        per_role[role] = set(ctx.cloud.role_permissions(role)) & org_testable
    wanted = sorted(set().union(*per_role.values())) if per_role else []
    granted = ctx.cloud.granted_org_permissions(ctx.org.org_id, wanted)
    results = []
    for role in roles:
        if role in per_role:
            results.append(
                _role_result(role, per_role[role], granted, "organization")
            )
            continue
        billing_resource = (
            f"//cloudbilling.googleapis.com/billingAccounts/{billing_account}"
        )
        testable = set(ctx.cloud.role_permissions(role)) & (
            ctx.cloud.testable_permissions(billing_resource)
        )
        try:
            billing_granted = ctx.cloud.granted_billing_permissions(
                billing_account, sorted(testable)
            )
        except api.CloudError as error:
            results.append(
                CheckResult(
                    f"iam.{role}",
                    Category.IAM,
                    role,
                    Status.FAIL,
                    f"Cannot test this role on the billing account: {error}",
                    doc=DOC_IAM,
                )
            )
            continue
        results.append(
            _role_result(role, testable, billing_granted, "billing account")
        )
    return results


def check_billing(ctx):
    """Checks the billing account and the bootstrap project's billing link."""
    category = Category.BILLING
    account_id = ctx.inputs.billing_account
    if account_id is None:
        return [
            _skip(
                "billing.account",
                category,
                "Billing account",
                "--billing-account",
            )
        ]
    try:
        account = ctx.cloud.get_billing_account(account_id)
    except api.CloudError as error:
        account, detail = None, f"Access denied: {error}"
    else:
        detail = f"Billing account {account_id} does not exist."
    if account is None or not account.is_open:
        if account is not None:
            detail = f"Billing account {account_id} is closed."
        results = [
            CheckResult(
                "billing.account",
                category,
                "Billing account",
                Status.FAIL,
                detail,
                remedy="Check the ID with `gcloud billing accounts list`.",
                doc=DOC_BOOTSTRAP,
            )
        ]
    else:
        results = [
            CheckResult(
                "billing.account",
                category,
                "Billing account",
                Status.PASS,
                f"Billing account {account_id} is open.",
                doc=DOC_BOOTSTRAP,
            )
        ]
    project = ctx.inputs.bootstrap_project
    if project is None:
        results.append(
            _skip(
                "billing.project",
                category,
                "Bootstrap project billing",
                "--project",
            )
        )
        return results
    try:
        link = ctx.cloud.project_billing(project)
    except api.CloudError as error:
        results.append(
            CheckResult(
                "billing.project",
                category,
                "Bootstrap project billing",
                Status.FAIL,
                f"Cannot read the billing link of {project}: {error}",
                doc=DOC_BOOTSTRAP,
            )
        )
        return results
    linked = link.enabled and link.account_id == account_id
    if linked:
        detail = f"{project} is billed to {account_id}."
    elif link.enabled:
        detail = f"{project} is billed to {link.account_id}, not {account_id}."
    else:
        detail = f"{project} has no billing account."
    results.append(
        CheckResult(
            "billing.project",
            category,
            "Bootstrap project billing",
            Status.PASS if linked else Status.FAIL,
            detail,
            remedy=(
                f"Run `gcloud billing projects link {project} "
                f"--billing-account={account_id}`."
            ),
            doc=DOC_BOOTSTRAP,
        )
    )
    return results


def check_project(ctx):
    """Checks that the bootstrap project exists and has the required APIs."""
    category = Category.PROJECT
    project = ctx.inputs.bootstrap_project
    if project is None:
        return [
            _skip("project.state", category, "Bootstrap project", "--project")
        ]
    try:
        state = ctx.cloud.project_state(project)
    except api.CloudError:
        state = None
    if state != "ACTIVE":
        return [
            CheckResult(
                "project.state",
                category,
                "Bootstrap project",
                Status.FAIL,
                f"{project} does not exist, is not active, or is not "
                "visible to this identity.",
                remedy="Create the project or fix --project.",
                doc=DOC_BOOTSTRAP,
            )
        ]
    results = [
        CheckResult(
            "project.state",
            category,
            "Bootstrap project",
            Status.PASS,
            f"{project} is active.",
            doc=DOC_BOOTSTRAP,
        )
    ]
    required = [*ctx.repo.required_apis(), *EXTRA_APIS]
    try:
        enabled = ctx.cloud.enabled_services(project)
    except api.CloudError as error:
        results.append(
            CheckResult(
                "project.apis",
                category,
                "Required APIs",
                Status.FAIL,
                f"Cannot list the enabled services: {error}",
                doc=DOC_APIS,
            )
        )
        return results
    missing = [api_name for api_name in required if api_name not in enabled]
    results.append(
        CheckResult(
            "project.apis",
            category,
            "Required APIs",
            Status.FAIL if missing else Status.PASS,
            f"Not enabled: {_listed(missing)}."
            if missing
            else f"All {len(required)} required APIs are enabled.",
            remedy=(
                f"Run `gcloud services enable {' '.join(missing)} "
                f"--project={project}`."
            ),
            doc=DOC_APIS,
        )
    )
    return results


def _group_members(ctx):
    """Resolves Stage 0 group keys to IAM members like `main.tf` does.

    A value with a `scheme:` prefix is already a principal. Any other value
    is a group name in the organization domain.
    """
    names = {**ctx.repo.default_groups(), **ctx.inputs.groups}
    return {
        key: value if _SCHEME_RE.match(value) else f"group:{value}@{ctx.domain}"
        for key, value in names.items()
    }


def _group_emails(ctx):
    members = _group_members(ctx).values()
    return sorted(
        {m.removeprefix("group:") for m in members if m.startswith("group:")}
    )


def check_groups(ctx):
    """Checks that the Stage 0 administrative groups exist."""
    category = Category.GROUPS
    if ctx.domain is None:
        return [_skip("groups", category, "Administrative groups", "--domain")]
    results = []
    for email in _group_emails(ctx):
        try:
            exists = ctx.cloud.group_exists(email)
        except api.CloudError as error:
            return [
                CheckResult(
                    "groups",
                    category,
                    "Administrative groups",
                    Status.MANUAL,
                    f"Cloud Identity cannot be queried ({error}). Confirm "
                    "that these groups exist: " + _listed(_group_emails(ctx)),
                    remedy=(
                        "Create missing groups in the Cloud Setup wizard "
                        "or the Google Admin console."
                    ),
                    doc=DOC_GROUPS,
                )
            ]
        results.append(
            CheckResult(
                f"groups.{email}",
                category,
                email,
                Status.PASS if exists else Status.FAIL,
                "The group exists." if exists else "The group does not exist.",
                remedy="Create the group in the Cloud Setup wizard.",
                doc=DOC_GROUPS,
            )
        )
    return results


def _check_region(ctx):
    region = ctx.inputs.region
    if region is None:
        return _skip("naming.region", Category.NAMING, "Region", "--region")
    regime = ctx.inputs.regime
    supported = regions.supported_regions(regime) if regime else None
    if supported is not None:
        ok = region in supported
        detail = (
            f"{regime} is available in {region}."
            if ok
            else f"{regime} is not available in {region}. Use one of "
            + _listed(supported)
            + "."
        )
    else:
        ok = bool(_REGION_RE.match(region))
        detail = (
            f"{region} is a single US region."
            if ok
            else f"{region} is not a single US region."
        )
        if regime and regime != regions.Regime.COMPLIANCE_REGIME_UNSPECIFIED:
            detail += f" No region table is recorded for {regime}."
    return CheckResult(
        "naming.region",
        Category.NAMING,
        "Region",
        Status.PASS if ok else Status.FAIL,
        detail,
        remedy=f"Pick a supported region, see {regions.LOCATIONS_DOC}.",
        doc=DDG_PREREQUISITES,
    )


def _guarded(check_id, title, run):
    """Runs one sub-check and reports a Google Cloud error as a warning."""
    try:
        return run()
    except api.CloudError as error:
        return CheckResult(
            check_id,
            Category.NAMING,
            title,
            Status.WARN,
            f"Cannot check for existing resources: {error}",
        )


def _collision(ctx, check_id, title, taken, what, unseen_note=""):
    if not taken:
        return CheckResult(
            check_id,
            Category.NAMING,
            title,
            Status.PASS,
            f"No existing {what} use this prefix.{unseen_note}",
        )
    redeploy = ctx.inputs.redeploy
    return CheckResult(
        check_id,
        Category.NAMING,
        title,
        Status.WARN if redeploy else Status.FAIL,
        f"These {what} already exist: {_listed(taken)}.",
        remedy=(
            "Pick a different prefix, or pass --redeploy if this is your own "
            "earlier deployment with the same prefix."
        ),
        doc=DDG_PREREQUISITES,
    )


def check_naming(ctx):
    """Checks the prefix format, region choice and name collisions."""
    results = [_check_region(ctx)]
    prefix = ctx.inputs.prefix
    if prefix is None:
        results.append(
            _skip("naming.prefix", Category.NAMING, "Prefix", "--prefix")
        )
        return results
    limit = ctx.repo.prefix_max_length()
    valid = bool(_PREFIX_RE.match(prefix)) and len(prefix) <= limit
    results.append(
        CheckResult(
            "naming.prefix",
            Category.NAMING,
            "Prefix format",
            Status.PASS if valid else Status.FAIL,
            f"{prefix} is a valid prefix."
            if valid
            else (
                f"{prefix} must start with a lowercase letter, use only "
                f"lowercase letters, digits and hyphens, and be at most "
                f"{limit} characters."
            ),
            doc=DDG_PREREQUISITES,
        )
    )
    if not valid:
        return results
    project_ids = [
        f"{prefix}-prod-{name}" for name in ctx.repo.stage0_project_names()
    ]
    results.append(
        _guarded(
            "naming.projects",
            "Project IDs",
            lambda: _collision(
                ctx,
                "naming.projects",
                "Project IDs",
                [
                    pid
                    for pid in project_ids
                    if ctx.cloud.visible_project_exists(pid)
                ],
                "projects",
                unseen_note=(
                    " Project IDs are global, so a project outside this "
                    "identity's view can still own one, which Stage 0 "
                    "reports as a conflict."
                ),
            ),
        )
    )
    buckets = [
        f"{prefix}-prod-iac-core-{name}-0"
        for name in ("bootstrap", "outputs", "resman")
    ]
    results.append(
        _guarded(
            "naming.buckets",
            "State buckets",
            lambda: _collision(
                ctx,
                "naming.buckets",
                "State buckets",
                [name for name in buckets if ctx.cloud.bucket_exists(name)],
                "buckets",
            ),
        )
    )
    if ctx.org is not None:
        folder = f"StellarEngine-{prefix}"
        results.append(
            _guarded(
                "naming.folder",
                "Assured Workloads folder",
                lambda: _collision(
                    ctx,
                    "naming.folder",
                    "Assured Workloads folder",
                    [folder]
                    if ctx.cloud.find_folders(ctx.org.org_id, folder)
                    else [],
                    "folders",
                ),
            )
        )
    return results


def _holder_member(ctx, holder, groups):
    """Resolves a Stage 0 role holder to the IAM member it grants."""
    prefix = ctx.inputs.prefix
    principal = ctx.principal
    match holder.kind:
        case repo_lib.HolderKind.GROUP:
            return groups.get(holder.key)
        case repo_lib.HolderKind.SERVICE_ACCOUNT if prefix:
            return (
                f"serviceAccount:{prefix}-prod-{holder.key}@"
                f"{prefix}-prod-iac-core-0.iam.gserviceaccount.com"
            )
        case repo_lib.HolderKind.BOOTSTRAP_USER if (
            principal and principal.kind == api.PrincipalKind.USER
        ):
            return f"user:{principal.email}"
        case repo_lib.HolderKind.DOMAIN if ctx.domain:
            return f"domain:{ctx.domain}"
    return None


def _removed_grants(ctx, bindings):
    """Lists existing grants that the first Stage 0 apply removes."""
    authoritative = ctx.repo.authoritative_bindings()
    groups = _group_members(ctx)
    removed = []
    for binding in bindings:
        if binding.role not in authoritative:
            continue
        kept = {
            _holder_member(ctx, holder, groups)
            for holder in authoritative[binding.role]
        }
        removed.extend(
            f"{binding.role} {member}"
            for member in binding.members
            if member not in kept and not member.startswith("deleted:")
        )
    return sorted(removed)


def check_shared_org(ctx):
    """Flags org-wide resources and IAM grants that Stage 0 would change."""
    category = Category.SHARED_ORG
    if ctx.org is None:
        return [_skip("shared", category, "Shared organization", "--org")]
    org_id = ctx.org.org_id
    results = []
    try:
        existing = [
            f"custom role {role_id}"
            for role_id in ctx.repo.custom_role_ids()
            if ctx.cloud.custom_role_exists(org_id, role_id)
        ]
        existing += [
            f"custom constraint {name}"
            for name in ctx.repo.custom_constraint_names()
            if ctx.cloud.custom_constraint_exists(org_id, name)
        ]
        existing += [
            f"log sink {name}"
            for name in ctx.repo.log_sink_names()
            if ctx.cloud.log_sink_exists(org_id, name)
        ]
    except api.CloudError as error:
        results.append(
            CheckResult(
                "shared.resources",
                category,
                "Organization-wide names",
                Status.WARN,
                f"Cannot check organization-wide resources: {error}",
            )
        )
    else:
        results.append(
            CheckResult(
                "shared.resources",
                category,
                "Organization-wide names",
                Status.WARN if existing else Status.PASS,
                (
                    "Stage 0 creates these organization-wide resources, and "
                    f"they already exist: {_listed(existing)}."
                )
                if existing
                else "No Stage 0 organization-wide resources exist yet.",
                remedy=(
                    "Another deployment or an earlier run created them. "
                    "Import them into Stage 0 state before the first apply, "
                    "or delete them if nothing uses them."
                ),
                doc=DDG_PREREQUISITES,
            )
        )
    try:
        bindings = ctx.cloud.org_iam_bindings(org_id)
    except api.CloudError as error:
        results.append(
            CheckResult(
                "shared.iam",
                category,
                "Authoritative IAM roles",
                Status.WARN,
                f"Cannot read the organization IAM policy: {error}",
            )
        )
        return results
    removed = _removed_grants(ctx, bindings)
    results.append(
        CheckResult(
            "shared.iam",
            category,
            "Authoritative IAM roles",
            Status.WARN if removed else Status.PASS,
            (
                f"The first Stage 0 apply removes {len(removed)} existing "
                f"grants from roles it manages authoritatively: "
                f"{_listed(removed)}."
            )
            if removed
            else "No existing grants would be removed by Stage 0.",
            remedy=(
                "Review these grants with the organization administrators "
                "before Stage 0, because Terraform removes them."
            ),
            doc=DOC_IAM,
        )
    )
    return results


def check_manual(ctx):
    """Lists prerequisites that only a person can confirm."""
    del ctx  # Manual confirmations do not depend on inputs.
    items = (
        (
            "manual.super_admin",
            "Super Admin",
            "Confirm that the deploying user is a Google Workspace or Cloud "
            "Identity Super Admin at https://admin.google.com/ac/roles.",
            DOC_ORGANIZATION,
        ),
        (
            "manual.access_transparency",
            "Access Transparency",
            "Confirm that Access Transparency is enabled at "
            "https://console.cloud.google.com/iam-admin/settings.",
            DOC_FEATURES,
        ),
        (
            "manual.quota",
            "Project quota",
            "Confirm that the project quota allows at least 13 new projects.",
            DOC_FEATURES,
        ),
    )
    return [
        CheckResult(
            check_id, Category.MANUAL, title, Status.MANUAL, detail, doc=doc
        )
        for check_id, title, detail, doc in items
    ]


ALL_CHECKS = (
    check_tools,
    check_identity,
    check_organization,
    check_iam_roles,
    check_billing,
    check_project,
    check_groups,
    check_naming,
    check_shared_org,
    check_manual,
)
