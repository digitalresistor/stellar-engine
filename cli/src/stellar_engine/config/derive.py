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

"""Values that follow from the answers the way the stage code derives them.

Each function mirrors a Terraform expression and names it, so a change in
the stage code has one place to follow here.
"""

import re

from stellar_engine import repo as repo_lib
from stellar_engine.config import models

# `0-bootstrap/main.tf` local.principals keeps values that already carry a
# principal type, such as `user:admin@example.com`.
_PRINCIPAL_RE = re.compile(r"^[a-zA-Z]+:")

ORGANIZATION_ADMINS = "gcp-organization-admins"
DEVOPS = "gcp-devops"


def kms_protection_level(answers: models.Answers) -> str:
    """Returns the CMEK protection level Stage 0 uses.

    Mirrors `local.kms_protection_level` in `0-bootstrap/kms.tf`: an
    explicit value wins, else SOFTWARE for FEDRAMP_MODERATE and HSM for
    every other regime.

    Args:
        answers: The environment answers.
    """
    if answers.kms_protection_level:
        return answers.kms_protection_level
    if answers.compliance.regime == "FEDRAMP_MODERATE":
        return "SOFTWARE"
    return "HSM"


def compliance_location(answers: models.Answers) -> str:
    """Returns the Assured Workloads location, defaulting to the region.

    Args:
        answers: The environment answers.
    """
    return answers.compliance.location or answers.region


def group_name(answers: models.Answers, repo: repo_lib.Repo, key: str) -> str:
    """Returns a Stage 0 group value: the renamed one or the repo default.

    Args:
        answers: The environment answers.
        repo: Repository that defines the default group names.
        key: Group key such as `gcp-devops`.

    Raises:
        KeyError: If the key is not a field of the Stage 0 `groups` type.
    """
    defaults = repo.default_groups()
    if key not in defaults:
        raise KeyError(key)
    return answers.groups.get(key) or defaults[key]


def group_principal(
    answers: models.Answers, repo: repo_lib.Repo, key: str
) -> str:
    """Returns the IAM principal of a group the way Stage 0 builds it.

    Mirrors `local.principals` in `0-bootstrap/main.tf`.

    Args:
        answers: The environment answers.
        repo: Repository that defines the default group names.
        key: Group key such as `gcp-devops`.

    Raises:
        KeyError: If the key is not a field of the Stage 0 `groups` type.
    """
    name = group_name(answers, repo, key)
    if _PRINCIPAL_RE.match(name):
        return name
    return f"group:{name}@{answers.organization.domain}"


def group_email(answers: models.Answers, repo: repo_lib.Repo, key: str) -> str:
    """Returns the email of a group, without the principal type.

    Args:
        answers: The environment answers.
        repo: Repository that defines the default group names.
        key: Group key such as `gcp-devops`.

    Raises:
        KeyError: If the key is not a field of the Stage 0 `groups` type.
    """
    return group_principal(answers, repo, key).split(":", 1)[1]


def env_admin(answers: models.Answers, repo: repo_lib.Repo, env: str) -> str:
    """Returns the admin email of a Stage 1 environment folder.

    The `1-resman` sample defaults every env to the organization admins
    group email.

    Args:
        answers: The environment answers.
        repo: Repository that defines the default group names.
        env: Env key, such as `Prod`.

    Raises:
        KeyError: If the env is not in the answers.
    """
    folder = answers.resman.envs[env]
    return folder.admin or group_email(answers, repo, ORGANIZATION_ADMINS)


def tenant_admin(
    answers: models.Answers, repo: repo_lib.Repo, tenant: str
) -> str:
    """Returns the admin principal of a Stage 1 tenant.

    The `1-resman` sample defaults it to the `gcp-devops` group principal.

    Args:
        answers: The environment answers.
        repo: Repository that defines the default group names.
        tenant: Tenant key, such as `ten1`.

    Raises:
        KeyError: If the tenant is not in the answers.
    """
    info = answers.resman.tenants[tenant]
    return info.admin_principal or group_principal(answers, repo, DEVOPS)


def tenant_locations(answers: models.Answers, tenant: str) -> dict[str, str]:
    """Returns the GCS and KMS locations of a tenant, defaulting to region.

    Args:
        answers: The environment answers.
        tenant: Tenant key, such as `ten1`.

    Raises:
        KeyError: If the tenant is not in the answers.
    """
    locations = answers.resman.tenants[tenant].locations
    if locations is None:
        return {"gcs": answers.region, "kms": answers.region}
    return {"gcs": locations.gcs, "kms": locations.kms}


def stage0_project_id(
    answers: models.Answers, project: repo_lib.Stage0Project
) -> str:
    """Returns the ID of a Stage 0 project, `<prefix>-prod-<name>`.

    Args:
        answers: The environment answers.
        project: A Stage 0 project from `Repo.stage0_projects`.
    """
    return f"{answers.prefix}-prod-{project.name}"


def stage0_projects(
    answers: models.Answers, repo: repo_lib.Repo
) -> list[repo_lib.Stage0Project]:
    """Returns the Stage 0 projects that Stage 0 creates for these answers.

    The billing export project only exists when Stage 0 manages billing IAM
    on an organization-level account; see `repo.stage0_project_created`.

    Args:
        answers: The environment answers.
        repo: The engine checkout.
    """
    return [
        project
        for project in repo.stage0_projects()
        if repo_lib.stage0_project_created(
            project,
            no_iam=answers.billing.no_iam,
            is_org_level=answers.billing.is_org_level,
        )
    ]


def stage0_project_ids(
    answers: models.Answers, repo: repo_lib.Repo
) -> list[str]:
    """Returns the IDs of the projects Stage 0 creates for these answers.

    Args:
        answers: The environment answers.
        repo: The engine checkout.
    """
    return [
        stage0_project_id(answers, project)
        for project in stage0_projects(answers, repo)
    ]


def _tenant_env_key(env, tenant):
    # `local.tenant_envs` in `1-resman/branch-tenants.tf` keys each pair as
    # "${e}-${t}", and every name built from it goes through lower().
    return f"{env}-{tenant}".lower()


def tenant_project_ids(answers: models.Answers) -> dict[str, list[str]]:
    """Returns the project IDs Stage 1 creates for each tenant.

    Mirrors `tenant-self-iac-projects` and `tenant-self-main-projects` in
    `1-resman/branch-tenants.tf`: one pair per env, named
    `<prefix>-<env>-<tenant>-iac-core-0` and `<prefix>-<env>-<tenant>-main-0`
    with the env and tenant lowercased.

    Args:
        answers: The environment answers.

    Returns:
        Tenant key to project IDs, in env order, iac-core before main.
    """
    return {
        tenant: [
            f"{answers.prefix}-{_tenant_env_key(env, tenant)}-{suffix}"
            for env in answers.resman.envs
            for suffix in ("iac-core-0", "main-0")
        ]
        for tenant in answers.resman.tenants
    }


def tenant_service_account_ids(
    answers: models.Answers,
) -> dict[str, list[str]]:
    """Returns the service account IDs Stage 1 creates for each tenant.

    Mirrors `tenant-core-sa` (`tn-<env>-<tenant>-prod-0`) and
    `tenant-self-iac-sa` (`<env>-<tenant>-iac-0`) in
    `1-resman/branch-tenants.tf`, both prefixed and lowercased. Service
    account IDs share the 30-character limit of project IDs.

    Args:
        answers: The environment answers.

    Returns:
        Tenant key to service account IDs, in env order.
    """
    return {
        tenant: [
            name
            for env in answers.resman.envs
            for name in (
                f"{answers.prefix}-tn-{_tenant_env_key(env, tenant)}-prod-0",
                f"{answers.prefix}-{_tenant_env_key(env, tenant)}-iac-0",
            )
        ]
        for tenant in answers.resman.tenants
    }
