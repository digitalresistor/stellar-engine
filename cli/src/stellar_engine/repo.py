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

"""Reads deployment facts from the Stellar Engine repository.

The CLI never duplicates lists that already live in the repository, such as
the roles granted by `setIAM.sh` or the APIs enabled by `enableServices.sh`.
This module parses those files so that the CLI and the manual flow in
`docs/ddg.md` always agree.
"""

import dataclasses
import enum
import functools
import json
import pathlib
import re

import hcl2
from packaging import version
import yaml

BOOTSTRAP_DIR = pathlib.Path("fast/stages-aw/0-bootstrap")
RESMAN_DIR = pathlib.Path("fast/stages-aw/1-resman")

_SERVICES_RE = re.compile(r'^list_of_services="([^"]+)"', re.MULTILINE)
_PREFIX_LIMIT_RE = re.compile(r"length\(var\.prefix\),\s*0\)\s*<=\s*(\d+)")
_TENANT_KEY_LIMIT_RE = re.compile(r"length\(k\)\s*(<=?)\s*(\d+)")
_GROUP_DEFAULT_RE = re.compile(
    r'([\w-]+)\s*=\s*optional\(string,\s*"([^"]+)"\)'
)
# python-hcl2 returns a conditional such as `cond ? {} : { ... }` as one
# expression string, so the map literal in its else branch is parsed again.
_CONDITIONAL_MAP_RE = re.compile(
    r"^\$\{.*?\?\s*\{\}\s*:\s*(\{.*\})\}$", re.DOTALL
)
_HOLDER_KEY_RE = re.compile(
    r"^(?:\$\{\(local\.principals\.(?P<group>[\w-]+)\)\}"
    r"|\$\{\(module\.(?P<module>[\w-]+)\.iam_email\)\}"
    r"|(?P<user>user):\$\{var\.bootstrap_user\}"
    r"|(?P<domain>domain):\$\{var\.organization\.domain\})$"
)
_VERSION_FLOOR_RE = re.compile(r">=\s*([0-9.]+)")
# `local._org_policies_raw` in `0-bootstrap/organization.tf` decodes every
# `*_policy.yaml` file of the plain directory with `yamldecode`, and renders
# the files of the templated directory with `templatefile` first.
_ORG_POLICY_DIR = "data/org-policies"
_TEMPLATED_ORG_POLICY_DIR = "data/custom-org-policies"
_ORG_POLICY_GLOB = "*_policy.yaml"
# A top-level key of a templated policy file. Template directives such as
# `%{ if ... ~}` and indented rules never match.
_TEMPLATED_KEY_RE = re.compile(r"^([A-Za-z0-9_.]+):")
# A template directive on its own line, such as `%{ if ... ~}`.
_DIRECTIVE_RE = re.compile(
    r"^\s*%\{~?\s*(?P<keyword>if|else|endif|for|endfor)\b(?P<rest>.*?)~?\}"
)
# The regime condition of the templated policy files, such as
# `!contains(["FEDRAMP_MODERATE"], regime)`.
_REGIME_CONDITION_RE = re.compile(
    r"^\s*(?P<negated>!?)\s*contains\(\s*\[(?P<regimes>[^\]]*)\]\s*,"
    r"\s*regime\s*\)\s*$"
)
# Constraints that `data/custom-constraint-policies` defines.
CUSTOM_CONSTRAINT_PREFIX = "custom."
# Stage 0 writes `local.tfvars` to `0-bootstrap.auto.tfvars.json` and
# `local.tfvars_globals` to `0-globals.auto.tfvars.json` in
# `outputs-files.tf`; `fast/stage-links.sh` links both into Stage 1. Stage 0
# reads no output files.
_AUTO_TFVARS_LOCALS = {
    "0-bootstrap": (),
    "1-resman": ("tfvars", "tfvars_globals"),
}


# `module "billing-export-project"` in `0-bootstrap/billing.tf` has
# `count = local.billing_mode == "org" ? 1 : 0`.
BILLING_EXPORT_MODULE = "billing-export-project"
_PROJECT_MODULE_SOURCE = "modules/project"


class RepoError(Exception):
    """Raised when the repository layout does not match expectations."""


@dataclasses.dataclass(frozen=True)
class Stage0Project:
    """A project that a Stage 0 `modules/project` call creates.

    Attributes:
        module: Module label, such as `automation-project`.
        name: Project name, the ID suffix after `<prefix>-prod-`.
        address: Address of the module's `google_project` resource, which
            an import block adopts.
        count: The module `count` expression, or None when it has none.
    """

    module: str
    name: str
    address: str
    count: str | None = None


def billing_export_created(*, no_iam: bool, is_org_level: bool) -> bool:
    """Returns whether Stage 0 creates the billing export project.

    Mirrors `local.billing_mode` in `0-bootstrap/billing.tf`, which is "org"
    only when Stage 0 manages billing IAM on an organization-level account.

    Args:
        no_iam: The `billing_account.no_iam` value.
        is_org_level: The `billing_account.is_org_level` value.
    """
    return not no_iam and is_org_level


def stage0_project_created(
    project: Stage0Project, *, no_iam: bool, is_org_level: bool
) -> bool:
    """Returns whether Stage 0 creates a project for these billing answers.

    Args:
        project: A Stage 0 project from `Repo.stage0_projects`.
        no_iam: The `billing_account.no_iam` value.
        is_org_level: The `billing_account.is_org_level` value.
    """
    if project.module == BILLING_EXPORT_MODULE:
        return billing_export_created(no_iam=no_iam, is_org_level=is_org_level)
    return True


@dataclasses.dataclass(frozen=True)
class OrgPolicyScan:
    """Organization policies sorted by whether Stage 0 imports them.

    Attributes:
        kept: Policies that Stage 0 declares and imports on its final
            apply.
        custom: Policies of custom constraints, which Stage 0 never
            imports.
        undeclared: Policies that Stage 0 does not manage.
    """

    kept: tuple[str, ...]
    custom: tuple[str, ...]
    undeclared: tuple[str, ...]


def _templated_keys(text, regime):
    """Returns the top-level keys of a templated policy file for a regime.

    Args:
        text: Content of a `data/custom-org-policies` file.
        regime: Regime that `templatefile` renders the file for, or None to
            keep the keys of every regime.

    Returns:
        The set of top-level keys that the rendered file contains.
    """
    keys = set()
    # One entry per open directive: True or False when the regime decides
    # the branch, None when it does not.
    stack = []
    for line in text.splitlines():
        directive = _DIRECTIVE_RE.match(line)
        if directive is None:
            key = _TEMPLATED_KEY_RE.match(line)
            if key and False not in stack:
                keys.add(key.group(1))
            continue
        keyword = directive.group("keyword")
        if keyword == "if":
            stack.append(_regime_branch(directive.group("rest"), regime))
        elif keyword == "for":
            stack.append(None)
        elif keyword == "else" and stack and stack[-1] is not None:
            stack[-1] = not stack[-1]
        elif keyword in ("endif", "endfor") and stack:
            stack.pop()
    return keys


def _regime_branch(condition, regime):
    """Returns whether a template condition holds for a regime, or None."""
    match = _REGIME_CONDITION_RE.match(condition)
    if regime is None or match is None:
        return None
    regimes = set(re.findall(r'"([^"]*)"', match.group("regimes")))
    return (regime in regimes) != bool(match.group("negated"))


def _counted(body):
    return "" if body.get("count") is None else "[0]"


class HolderKind(enum.StrEnum):
    """Kinds of principal that Stage 0 binds to organization roles."""

    GROUP = "group"
    SERVICE_ACCOUNT = "serviceAccount"
    BOOTSTRAP_USER = "bootstrapUser"
    DOMAIN = "domain"


@dataclasses.dataclass(frozen=True)
class Holder:
    """A principal that Stage 0 binds to an organization role.

    Attributes:
        kind: Kind of principal.
        key: Group key such as `gcp-devops`, or service account name such as
            `bootstrap-0`. None for the bootstrap user and the domain.
    """

    kind: HolderKind
    key: str | None = None


def _unquote(value):
    """Strips the HCL quoting that python-hcl2 keeps on strings and labels."""
    if isinstance(value, str) and value.startswith('"') and value.endswith('"'):
        return json.loads(value)
    return value


def _load_hcl(path):
    with path.open(encoding="utf-8") as handle:
        return hcl2.load(handle)


def _literal_map(value, name):
    """Returns a parsed HCL map, unwrapping a `cond ? {} : {...}` value.

    Raises:
        RepoError: If the value is neither a map nor that conditional.
    """
    if isinstance(value, dict):
        return value
    match = _CONDITIONAL_MAP_RE.match(value) if isinstance(value, str) else None
    if not match:
        raise RepoError(f"Cannot read local.{name} as a map")
    return hcl2.loads(f"value = {match.group(1)}")["value"]


def find_root(start=None):
    """Finds the Stellar Engine repository root.

    Args:
        start: Directory to start searching from. Defaults to the current
            working directory, then the location of this package.

    Returns:
        The repository root path.

    Raises:
        RepoError: If no directory containing `fast/stages-aw` is found.
    """
    candidates = [pathlib.Path(start) if start else pathlib.Path.cwd()]
    candidates.append(pathlib.Path(__file__).resolve())
    for candidate in candidates:
        for directory in [candidate, *candidate.parents]:
            if (directory / "fast" / "stages-aw").is_dir():
                return directory
    raise RepoError(
        "Cannot find the Stellar Engine repository root. Run the command "
        "from inside a checkout or pass --repo."
    )


@dataclasses.dataclass(frozen=True)
class Repo:
    """Read-only view of the deployment facts stored in the repository.

    Attributes:
        root: Path of the repository root.
    """

    root: pathlib.Path

    @property
    def bootstrap_dir(self):
        """Returns the Stage 0 bootstrap directory."""
        return self.root / BOOTSTRAP_DIR

    @functools.cached_property
    def _bootstrap_variables(self):
        parsed = _load_hcl(self.bootstrap_dir / "variables.tf")
        variables = {}
        for block in parsed.get("variable", []):
            for name, body in block.items():
                variables[_unquote(name)] = body
        return variables

    def required_roles(self):
        """Returns the organization roles that `setIAM.sh` grants.

        Returns:
            Role names in file order, for example `roles/owner`.
        """
        path = self.bootstrap_dir / "setIAM.yaml.sample"
        policy = json.loads(path.read_text(encoding="utf-8"))
        return [binding["role"] for binding in policy["bindings"]]

    def required_apis(self):
        """Returns the APIs that `enableServices.sh` enables.

        Returns:
            Fully qualified service names such as `iam.googleapis.com`.

        Raises:
            RepoError: If the service list cannot be found in the script.
        """
        script = (self.bootstrap_dir / "enableServices.sh").read_text(
            encoding="utf-8"
        )
        match = _SERVICES_RE.search(script)
        if not match:
            raise RepoError("Cannot find list_of_services in enableServices.sh")
        return [f"{name}.googleapis.com" for name in match.group(1).split()]

    def prefix_max_length(self):
        """Returns the prefix length limit from the Stage 0 validation block.

        Raises:
            RepoError: If the validation block cannot be found.
        """
        text = (self.bootstrap_dir / "variables.tf").read_text(encoding="utf-8")
        match = _PREFIX_LIMIT_RE.search(text)
        if not match:
            raise RepoError("Cannot find the prefix length validation")
        return int(match.group(1))

    def tenant_key_max_length(self):
        """Returns the tenant key length limit from the Stage 1 validation.

        The `tenants` variable in `1-resman/variables.tf` writes the limit
        as `length(k) < 7`, so the strict bound is converted to the longest
        allowed key length.

        Raises:
            RepoError: If the validation block cannot be found.
        """
        text = (self.root / RESMAN_DIR / "variables.tf").read_text(
            encoding="utf-8"
        )
        match = _TENANT_KEY_LIMIT_RE.search(text)
        if not match:
            raise RepoError("Cannot find the tenant key length validation")
        limit = int(match.group(2))
        return limit if match.group(1) == "<=" else limit - 1

    def default_groups(self):
        """Returns the default group names from the Stage 0 `groups` type.

        Returns:
            A mapping of group key to group name, for example
            `{"gcp-support": "gcp-devops"}`.
        """
        group_type = self._bootstrap_variables["groups"]["type"]
        return dict(_GROUP_DEFAULT_RE.findall(group_type))

    def regime_names(self):
        """Returns the compliance regimes in the Stage 0 `regime_mapping`."""
        default = self._bootstrap_variables["regime_mapping"].get("default", {})
        return sorted(_unquote(name) for name in default)

    def log_sink_names(self):
        """Returns the default organization log sink names."""
        default = self._bootstrap_variables["log_sinks"].get("default", {})
        return sorted(_unquote(name) for name in default)

    def custom_role_ids(self):
        """Returns the organization custom role IDs that Stage 0 creates.

        A role file without a `name` key falls back to its file name, which
        matches how the organization module names it.
        """
        role_ids = []
        for path in sorted(
            (self.bootstrap_dir / "data/custom-roles").glob("*.yaml")
        ):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            role_ids.append(data.get("name") or path.stem)
        return role_ids

    def custom_constraint_names(self):
        """Returns the organization custom constraint names Stage 0 creates."""
        names = []
        directory = self.bootstrap_dir / "data/custom-constraint-policies"
        for path in sorted(directory.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            names.extend(data)
        return names

    def declared_org_policies(self, regime=None):
        """Returns the constraints of the organization policies Stage 0 sets.

        The names are the top-level keys of the `*_policy.yaml` files in
        `data/org-policies` and `data/custom-org-policies`, the files that
        `local._org_policies_raw` in `organization.tf` loads. A templated
        file can omit a key for some regimes through a
        `contains([...], regime)` condition, so pass the regime to drop
        those keys the way `templatefile` does. A key behind any other
        condition counts for every regime.

        Args:
            regime: Assured Workloads regime, such as `FEDRAMP_MODERATE`.
                None returns the keys of every regime.

        Returns:
            Sorted unique constraint names, such as
            `iam.allowedPolicyMemberDomains`.
        """
        names = set()
        for path in sorted(
            (self.bootstrap_dir / _ORG_POLICY_DIR).glob(_ORG_POLICY_GLOB)
        ):
            names.update(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        for path in sorted(
            (self.bootstrap_dir / _TEMPLATED_ORG_POLICY_DIR).glob(
                _ORG_POLICY_GLOB
            )
        ):
            names.update(
                _templated_keys(path.read_text(encoding="utf-8"), regime)
            )
        return sorted(names)

    def scan_org_policies(self, existing, regime=None):
        """Sorts existing organization policies by whether Stage 0 imports them.

        These are the rules of `0-bootstrap/import.sh`. Stage 0 imports
        each existing policy that it declares, so its final apply adopts
        the policy instead of failing to create it. A policy of a custom
        constraint that Stage 0 declares is skipped, because Stage 0
        creates that constraint in the same apply, and preflight reports a
        custom constraint that already exists. Any other policy, custom or
        not, is undeclared.

        Args:
            existing: Constraint names of the policies set on the
                organization.
            regime: Assured Workloads regime whose templated policies
                count as declared. None counts the policies of every
                regime.

        Returns:
            An `OrgPolicyScan` with sorted unique names.
        """
        declared = set(self.declared_org_policies(regime))
        kept, custom, undeclared = set(), set(), set()
        for name in existing:
            if name not in declared:
                undeclared.add(name)
            elif name.startswith(CUSTOM_CONSTRAINT_PREFIX):
                custom.add(name)
            else:
                kept.add(name)
        return OrgPolicyScan(
            tuple(sorted(kept)),
            tuple(sorted(custom)),
            tuple(sorted(undeclared)),
        )

    def _module_names(self, filename):
        """Maps each module in a Stage 0 file to its `name` argument."""
        names = {}
        for block in _load_hcl(self.bootstrap_dir / filename).get("module", []):
            for label, body in block.items():
                if "name" in body:
                    names[_unquote(label)] = _unquote(body["name"])
        return names

    def automation_service_accounts(self):
        """Maps Stage 0 automation service account modules to their names.

        Returns:
            For example `{"automation-tf-bootstrap-sa": "bootstrap-0"}`. The
            account email is `<prefix>-prod-<name>@<prefix>-prod-iac-core-0`.
        """
        return {
            module: name
            for module, name in self._module_names("automation.tf").items()
            if module.endswith("-sa")
        }

    def stage0_project_names(self):
        """Returns the names of the projects Stage 0 can create.

        The project ID is `<prefix>-prod-<name>`. The billing export project
        is included even though Stage 0 only creates it for some billing
        answers; see `stage0_project_created`.
        """
        return [project.name for project in self.stage0_projects()]

    def stage0_projects(self):
        """Returns the projects Stage 0 can create, with their addresses.

        Each address comes from the stage code: the `modules/project` call
        in `0-bootstrap` whose `name` is a Stage 0 project name, indexed
        `[0]` when the module or the module's `google_project` resource has
        a `count`.

        Returns:
            A tuple of `Stage0Project`: the automation, log export and
            billing export projects, in that order.

        Raises:
            RepoError: If a Stage 0 project has no project module.
        """
        return self._stage0_projects

    @functools.cached_property
    def _stage0_projects(self):
        names = [
            ("automation.tf", "automation-project"),
            ("log-export.tf", "log-export-project"),
            ("billing.tf", BILLING_EXPORT_MODULE),
        ]
        resource_index = ""
        project_main = _load_hcl(self.root / "modules/project/main.tf")
        for block in project_main.get("resource", []):
            for label, bodies in block.items():
                if _unquote(label) != "google_project":
                    continue
                for name, body in bodies.items():
                    if _unquote(name) == "project":
                        resource_index = _counted(body)
        projects = []
        for filename, module in names:
            body = None
            for block in _load_hcl(self.bootstrap_dir / filename).get(
                "module", []
            ):
                for label, candidate in block.items():
                    if _unquote(label) == module:
                        body = candidate
            source = _unquote(body.get("source", "")) if body else ""
            if body is None or not str(source).endswith(_PROJECT_MODULE_SOURCE):
                raise RepoError(f"No Stage 0 project module {module}")
            count = body.get("count")
            projects.append(
                Stage0Project(
                    module=module,
                    name=_unquote(body["name"]),
                    address=(
                        f"module.{module}{_counted(body)}."
                        f"google_project.project{resource_index}"
                    ),
                    count=None if count is None else str(count),
                )
            )
        return tuple(projects)

    def authoritative_bindings(self):
        """Returns the principals Stage 0 keeps on each authoritative role.

        Stage 0 removes every other principal from these roles on its first
        apply, as defined in `organization-iam.tf`. Roles in
        `iam_delete_roles` keep no principal at all.

        Returns:
            A dict of role to a set of `Holder` values.

        Raises:
            RepoError: If a binding refers to an unknown principal or service
                account, or a binding local is not a map.
        """
        local_values = {}
        path = self.bootstrap_dir / "organization-iam.tf"
        for block in _load_hcl(path).get("locals", []):
            local_values.update(block)
        accounts = self.automation_service_accounts()
        bindings = {}
        for name, value in local_values.items():
            if not name.endswith("_bindings"):
                continue
            for key, body in _literal_map(value, name).items():
                holder = self._holder(_unquote(key), accounts)
                roles = body.get("authoritative", [])
                if not isinstance(roles, list):
                    raise RepoError(f"Cannot read the roles of {key}")
                for role in roles:
                    bindings.setdefault(_unquote(role), set()).add(holder)
        for role in local_values.get("iam_delete_roles", []):
            bindings[_unquote(role)] = set()
        return bindings

    @staticmethod
    def _holder(key, accounts):
        """Returns the Holder for an `organization-iam.tf` binding key."""
        match = _HOLDER_KEY_RE.match(key)
        if not match:
            raise RepoError(f"Unknown principal {key}")
        if match.group("group"):
            return Holder(HolderKind.GROUP, match.group("group"))
        if match.group("module"):
            module = match.group("module")
            if module not in accounts:
                raise RepoError(f"Unknown service account {module}")
            return Holder(HolderKind.SERVICE_ACCOUNT, accounts[module])
        if match.group("user"):
            return Holder(HolderKind.BOOTSTRAP_USER)
        return Holder(HolderKind.DOMAIN)

    def authoritative_org_roles(self):
        """Returns organization roles that Stage 0 manages authoritatively."""
        return sorted(self.authoritative_bindings())

    def auto_tfvars_keys(self, stage):
        """Returns the variables a stage receives from `*.auto.tfvars.json`.

        Terraform loads `*.auto.tfvars.json` files after `terraform.tfvars`,
        so these keys override anything the rendered tfvars sets. They are
        the keys of the Stage 0 locals that `outputs-files.tf` writes.

        Args:
            stage: Stage directory name, such as `1-resman`.

        Returns:
            A frozenset of variable names, empty for Stage 0.

        Raises:
            RepoError: If the stage is unknown or a local is not a map.
        """
        if stage not in _AUTO_TFVARS_LOCALS:
            raise RepoError(f"Unknown stage {stage}")
        local_values = {}
        for block in _load_hcl(self.bootstrap_dir / "outputs.tf").get(
            "locals", []
        ):
            local_values.update(block)
        keys = set()
        for name in _AUTO_TFVARS_LOCALS[stage]:
            value = local_values.get(name)
            if not isinstance(value, dict):
                raise RepoError(f"Cannot read local.{name} in outputs.tf")
            keys.update(_unquote(key) for key in value)
        return frozenset(keys)

    def min_terraform_version(self):
        """Returns the highest Terraform `required_version` floor of modules.

        Stages pull in many modules, so the effective minimum is the highest
        `>=` constraint declared under `modules/*/versions.tf`.

        Raises:
            RepoError: If no module declares a `>=` constraint.
        """
        floors = []
        for path in (self.root / "modules").glob("*/versions.tf"):
            for block in _load_hcl(path).get("terraform", []):
                constraint = _unquote(block.get("required_version", ""))
                floors.extend(
                    version.Version(found)
                    for found in _VERSION_FLOOR_RE.findall(constraint)
                )
        if not floors:
            raise RepoError("No module declares a required_version floor")
        return str(max(floors))
