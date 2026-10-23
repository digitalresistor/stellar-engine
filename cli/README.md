# Stellar Engine CLI

The `stellar` command verifies that your workstation, identity, and Google
Cloud organization meet the prerequisites in the
[Detailed Deployment Guide](../docs/ddg.md) before you deploy Stage 0. It
also records the answers of each deployment and renders ready-to-run
Terraform workspaces for the `0-bootstrap` and `1-resman` stages.

## 1 Install the CLI

The `cli/` project uses [uv](https://docs.astral.sh/uv/) to install the
Python version and the dependencies that `cli/pyproject.toml` declares, so you
do not install Python yourself.

- Install uv by following the
  [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/).
- Run the command from the repository root with
  `uv run --project cli stellar --help`.
- Install the command on your `PATH` with `uv tool install ./cli` if you
  prefer to run `stellar` directly.

## 2 Choose a home

One home folder holds every file that a deployment owns, so you move or back
up a deployment by moving one folder.

- The `--home` flag selects the home for one command.
- The `STELLAR_HOME` environment variable selects the home when you omit the
  `--home` flag, for example `STELLAR_HOME=~/deployments/lab`.
- Without either setting, the command uses the `.stellar/` folder in the
  engine checkout, which the root `.gitignore` file excludes.
- Every command resolves the home the same way, and `stellar env show`
  prints the home and the setting that selected it.
- A home can live outside the checkout, because workspaces link to the
  engine code with absolute paths.
- One checkout can serve many homes, such as one home per organization.

Each environment lives in the `envs/<prefix>/` folder of the home.

- The `answers.yaml` file records the answers and keeps your comments
  across reruns.
- Only your user can read the `answers.yaml` file, because it names
  principals and billing accounts.
- The `fast/stages-aw/<stage>/` folders hold the stage workspaces.
- The `fast-config/` folder receives the provider and tfvars files that
  Stage 0 writes for later stages.
- The `generated/` folder stores a hash of each tfvars file that
  `stellar render` wrote, so the next render detects manual edits.
- The `.gitignore` file of the home tracks only the answers files, so you
  can turn the home into a private Git repository without committing state,
  logs, or plans.

## 3 Create an environment

The `stellar init` command validates every answer against the repository
before it saves the `answers.yaml` file, so mistakes surface before
Terraform runs.

```bash
uv run --project cli stellar init
```

- The wizard offers the organizations and billing accounts that your
  credentials can see as defaults.
- The `--offline` flag skips those Google Cloud lookups.
- A rerun keeps the current answers as defaults, so you press Enter to keep
  each one.
- The `--section` flag asks only the named wizard section, such as
  `--section tenants`, and accepts repeats.
- The `--set KEY=VALUE` flag sets one answer and accepts repeats.
- Each `--set` value is YAML, so lists and maps work.
- The `--non-interactive` flag never prompts and exits with status 2 when an
  answer is missing or invalid.
- The `--from-config-env scripts/config.env` flag starts a new environment
  from an existing `scripts/deploy.sh` configuration file.
- The `overrides` answer passes raw tfvars values per stage for variables
  that the answers do not model, such as the Stage 0 `iam` map.
- The command rejects an override of a variable that the stage does not
  declare or that the Stage 0 outputs provide.
- The command also rejects an override of a value that the CLI derives,
  such as `prefix`, `outputs_location`, or `bootstrap_user`.
- A rerun never changes the prefix of an environment, so use the
  `--answers-from` flag to start a new environment from it.

```bash
uv run --project cli stellar init --non-interactive --prefix abc \
  --set organization.id=123456789012 \
  --set organization.domain=example.com \
  --set organization.customer_id=C01234567 \
  --set billing.account_id=000000-AAAAAA-BBBBBB \
  --set bootstrap_project=my-bootstrap-project \
  --set region=us-east4 \
  --set compliance.regime=IL5 \
  --set alert_email=alerts@example.com \
  --set bootstrap_user=admin@example.com \
  --set 'resman.tenants.ten1={descriptive_name: tenant-1}'
```

A new environment can start from the answers of another one, so most
prompts only need Enter.

- The `--answers-from` flag copies the organization, billing, groups, and
  tenants from another environment prefix or an `answers.yaml` path.
- The copy never includes the prefix, the engine path, the imports, or the
  existing organization policies, because those belong to the source
  environment.
- The command lists the answers to review when the regime changes, such as
  an explicit `kms_protection_level` value.
- The `--new-prefix` flag suggests a fresh prefix with a random suffix, so
  the new project IDs avoid the IDs of a recently deleted deployment.

## 4 Manage environments

Each prefix in a home is one environment, and every command that omits the
`--prefix` flag works on the current environment.

- The `stellar env list` command shows each environment with its regime,
  region, and organization, and marks the current one.
- The `stellar env use PREFIX` command makes another environment current.
- The `stellar env show` command prints the home, the answers file, the
  workspaces, and the values that the CLI derives, such as the KMS
  protection level and the project IDs.
- The `stellar env show` command also lists the organization policies that
  Stage 0 imports.
- The `STELLAR_PREFIX` environment variable selects an environment the same
  way as the `--prefix` flag.
- Every command stops when the current environment no longer exists and
  points you to the `stellar env use PREFIX` command.
- Every command stops when the `prefix` answer differs from the name of the
  environment folder.

## 5 Render the workspaces

The `stellar render` command turns the answers into one Terraform workspace
per stage, so you run Terraform with the `-chdir` option and never edit the
engine checkout. The command prints the `terraform -chdir` lines for each
stage, so you can copy them. With the default home, they look like this.

```bash
uv run --project cli stellar render
terraform -chdir=.stellar/envs/abc/fast/stages-aw/0-bootstrap init
terraform -chdir=.stellar/envs/abc/fast/stages-aw/0-bootstrap plan \
  -var bootstrap_user=admin@example.com
```

- Each workspace links the stage files of the engine and keeps the files
  that the environment owns, such as `terraform.tfvars` and the local state.
- The Stage 0 workspace receives a copy of the `providers.tf.tmp` file as
  `0-bootstrap-providers.tf`, as the DDG instructs.
- Later renders keep the `0-bootstrap-providers.tf` file, because the state
  migration step replaces it with the remote providers file.
- The `1-resman` workspace links the Stage 0 outputs from the `fast-config/`
  folder once Stage 0 writes them.
- The `--stage` flag renders one stage, such as `--stage 0`, and accepts
  repeats.
- The `--diff` flag prints the changes and writes nothing.
- A rerun replaces a tfvars file silently only when the file still matches
  the last render.
- The command asks before it replaces a tfvars file that holds manual edits,
  and exits with status 3 when it cannot ask.
- The `--force` flag replaces an edited file after it saves a
  `terraform.tfvars.backup.<timestamp>` copy.
- The tfvars file never sets the `bootstrap_user` variable, because the DDG
  passes it with the `-var` option on the first Stage 0 apply.

## 6 Adopt existing projects

Terraform import blocks adopt Stage 0 projects that an administrator creates
in advance, so Stage 0 moves them into its folders instead of creating them
and linking billing again.

```yaml
imports:
  0-bootstrap:
    module.automation-project.google_project.project[0]: abc-prod-iac-core-0
    module.log-export-project.google_project.project[0]: abc-prod-audit-logs-0
```

- The `stellar render` command writes one `import` block per entry to the
  `0-bootstrap-imports.tf` file in the workspace.
- The command removes that file when the `imports` map becomes empty.
- The bootstrap section of the wizard asks whether the Stage 0 projects
  exist already and reads their addresses from the stage code.
- Each Stage 0 import ID must equal the project ID that the prefix
  derives, because a different ID makes Terraform replace the imported
  project.
- The `module.billing-export-project[0]` address exists only when
  `billing.no_iam` is false and `billing.is_org_level` is true, so the
  command warns about an import into it otherwise.
- Preflight expects each project in the `imports` map to exist and be
  active, and reports it as a pass instead of a name collision.
- The `--set` flag accepts an address in double quotes, such as
  `--set 'imports.0-bootstrap."module.automation-project.google_project.project[0]"=abc-prod-iac-core-0'`.

## 7 Import organization policies

The `stellar imports scan` command records the organization policies that
exist before Stage 0, so the final Stage 0 apply adopts them instead of
failing to create them, and you no longer run the `import.sh` script.

```bash
uv run --project cli stellar imports scan
uv run --project cli stellar render --stage 0
```

- The command lists the policies of the organization and only reads from
  Google Cloud.
- The command keeps each constraint that a `*_policy.yaml` file declares in
  the `data/org-policies/` or `data/custom-org-policies/` folder of Stage 0.
- The command skips a constraint that the templates in the
  `data/custom-org-policies/` folder omit for the regime of the
  environment.
- The command skips the policies of the `custom.*` constraints that Stage 0
  declares, because Stage 0 creates those constraints in the same apply.
- The command also skips every other constraint, including custom
  constraints of the organization, because Stage 0 does not manage them.
- The command saves the kept constraints to the `existing_org_policies`
  answer and keeps the comments in the `answers.yaml` file.
- The `stellar render` command adds one `import` block for these policies
  to the `0-bootstrap-imports.tf` file.
- The first Stage 0 apply passes the `bootstrap_user` variable, so Stage 0
  manages no organization policies yet and imports none.
- The final Stage 0 apply omits the `bootstrap_user` variable and imports
  each listed policy that the regime templates still set.
- Terraform skips an import once the state holds the policy, so later
  applies keep working with the same file.
- Rerun the scan before the final apply when someone changes the
  organization policies in the meantime.
- Preflight warns when a policy that Stage 0 declares exists but the
  `existing_org_policies` answer does not list it.
- Preflight only counts the existing policies when it runs without an
  `answers.yaml` file or with the `--redeploy` flag.
- The CLI rejects an `import_defaults` value of true in the
  `overrides.0-bootstrap.org_policies_config` answer while the
  `existing_org_policies` answer lists policies, because that option
  imports a fixed list of policies whether or not each one exists.
- The scan also finds the policies that the `import_defaults` option
  imports, so you can drop that option.

## 8 Run preflight

Preflight only reads from Google Cloud and never changes a resource, so you
can run it as often as you like.

```bash
gcloud auth login
gcloud auth application-default login
uv run --project cli stellar preflight \
  --org 123456789012 \
  --billing-account 000000-AAAAAA-BBBBBB \
  --project my-bootstrap-project \
  --prefix abc \
  --regime IL5 \
  --region us-east4
```

- Each flag also reads an environment variable, such as `STELLAR_ORG_ID` for
  the `--org` flag.
- The `--config-env scripts/config.env` flag reads values from an existing
  `scripts/deploy.sh` configuration file, and explicit flags override it.
- Preflight reads unset values from the answers of the current environment,
  or of the environment that the `--prefix` flag selects, and explicit flags
  override them.
- The `--group gcp-devops=platform-ops` flag checks a renamed Stage 0 group
  and accepts repeats.
- A check whose inputs you omit reports `skip` and names the flag that
  enables it.
- The `--json` flag prints machine-readable results for automation.
- The command exits with status 1 when a check fails, and the `--strict` flag
  also fails the run on warnings.

## 9 Read the results

Each check reports one status, and every failure or warning includes a fix
and a link to the matching documentation.

| Status | Meaning |
| --- | --- |
| `pass` | Preflight verified the prerequisite. |
| `warn` | Review a risk that does not block Stage 0. |
| `fail` | Fix a missing prerequisite that blocks Stage 0. |
| `manual` | Confirm the prerequisite yourself. |
| `skip` | Pass the inputs that the check needs. |

## 10 Checks performed

Preflight follows the order of the DDG prerequisites section.

- Terraform meets the highest `required_version` floor that the modules under
  `modules/` declare, and the Google Cloud SDK and jq are installed.
- The active gcloud account matches the Application Default Credentials
  identity that Terraform uses.
- A user account is available for the `bootstrap_user` variable, because
  Stage 0 grants it as a `user:` principal. The signed-in user serves by
  default, and the `--bootstrap-user` flag names another user when
  Terraform runs as a service account.
- The active gcloud project is the bootstrap project.
- The organization exists, and its domain and directory customer ID match the
  values you pass.
- The deploying identity holds every role that
  `fast/stages-aw/0-bootstrap/setIAM.yaml.sample` grants. The check tests
  effective permissions with `testIamPermissions`, so it accepts direct,
  group, and inherited grants alike.
- The billing account is open, the deploying identity holds Billing Account
  Administrator on it, and the bootstrap project bills to it.
- The `--billing-no-iam` flag matches a Stage 0 `billing_account` input with
  `no_iam = true`, so Stage 0 never manages billing IAM. Preflight then skips
  the Billing Account Administrator check and tests only the
  `billing.resourceAssociations.create` permission that links new projects
  to the billing account.
- The bootstrap project is active and has every API that
  `fast/stages-aw/0-bootstrap/enableServices.sh` enables, plus the Cloud
  Monitoring API that the DDG requires.
- The Stage 0 administrative groups exist in Cloud Identity, resolved from
  the `groups` variable the same way Stage 0 resolves them.
- The region supports the compliance regime according to the
  [Assured Workloads locations](https://cloud.google.com/assured-workloads/docs/locations)
  page, and the regime appears in the Stage 0 `regime_mapping` variable.
- The prefix is valid, and no project, state bucket, or Assured Workloads
  folder that Stage 0 creates already exists with that prefix.
- No soft-deleted project still holds a project ID that Stage 0 creates,
  because a deleted project keeps its ID for 30 days.
- The naming checks skip the billing export project unless the
  `billing.no_iam` answer is false and the `billing.is_org_level` answer is
  true, because Stage 0 creates it only then.
- The Stage 1 tenant project IDs from the answers are free and no
  soft-deleted project holds them.
- Organization-wide custom roles, custom constraints, and log sinks that
  Stage 0 creates do not exist yet.
- The `existing_org_policies` answer lists every existing organization
  policy that Stage 0 declares, so the final Stage 0 apply imports it.
- The organization IAM policy lists every existing grant that the first
  Stage 0 apply removes. For each role that `organization-iam.tf` manages
  authoritatively, preflight compares the current members with the members
  that Stage 0 keeps on that role.
- Super Admin status, Access Transparency, and project quota appear as manual
  confirmations because no API exposes them to the deploying identity.

## 11 Required access

Preflight needs read access to the resources it checks, which the DDG roles
already include.

- Your Application Default Credentials need a quota project with the Cloud
  Resource Manager, IAM, Cloud Billing, Service Usage, Cloud Identity, Cloud
  Logging, and Organization Policy APIs enabled.
- A disabled API reports the exact `gcloud services enable` command to run.
- Terraform can run as a service account, because Stage 0 only needs a user
  account for the `bootstrap_user` variable. Pass that user's email with the
  `--bootstrap-user` flag, and use the same value for
  `-var bootstrap_user` on the first Stage 0 apply.
- The `--redeploy` flag downgrades existing prefix resources to warnings when
  you rerun preflight against your own earlier deployment.

## 12 Develop the CLI

The `cli/` project follows the
[Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
with the ruff settings in `cli/pyproject.toml`.

- Install the development environment with `uv sync` in the `cli/`
  directory.
- Run the tests with `uv run pytest`.
- Format and lint the code with `uv run ruff format` and `uv run ruff check`.
- Check types with `uv run pyright`.
- Unit tests replace Google Cloud with in-memory fakes, so they never touch
  the network.
- Tests marked `terraform` run the real Terraform binary and skip when it
  is missing.
- Sync tests in `cli/tests/test_repo.py` read the repository and the DDG, so
  they fail when the documentation and the code drift apart.
