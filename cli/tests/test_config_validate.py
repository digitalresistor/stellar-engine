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

"""Tests for the repository-backed answer rules."""

import pytest

import answer_fixtures
import render_fixtures
from stellar_engine import repo as repo_lib
from stellar_engine.config import models
from stellar_engine.config import validate


def _answers(**overrides):
    return models.Answers.model_validate(
        answer_fixtures.answer_data(**overrides)
    )


def test_valid_answers_have_no_problems(repo):
    answers = _answers(
        groups={"gcp-devops": "platform"},
        resman={"tenants": {"ten1": {"descriptive_name": "Tenant"}}},
        imports={
            "0-bootstrap": {
                "module.automation-project.google_project.project[0]": (
                    "tst-prod-iac-core-0"
                )
            }
        },
    )
    assert validate.problems(answers, repo) == []


def test_prefix_longer_than_repo_limit(repo, monkeypatch):
    monkeypatch.setattr(repo_lib.Repo, "prefix_max_length", lambda self: 2)
    problems = validate.problems(_answers(), repo)
    assert problems == [
        "prefix tst is longer than the 2 characters Stage 0 allows."
    ]


def test_unknown_regime(repo):
    problems = validate.problems(_answers(compliance={"regime": "IL9"}), repo)
    assert len(problems) == 1
    assert problems[0].startswith("compliance.regime IL9 is not one of")


def test_unknown_group_key(repo):
    problems = validate.problems(_answers(groups={"gcp-nope": "x"}), repo)
    assert len(problems) == 1
    assert problems[0].startswith("groups keys gcp-nope are not Stage 0")


def test_region_must_suit_the_regime(repo):
    answers = _answers(region="us-east5")
    problems = validate.problems(answers, repo)
    assert len(problems) == 1
    assert problems[0].startswith(
        "region us-east5 is not an Assured Workloads region for IL5"
    )


def test_unlisted_region_can_be_allowed(repo):
    answers = _answers(
        region="us-east5",
        compliance={"regime": "IL5", "allow_unlisted_region": True},
    )
    assert validate.problems(answers, repo) == []


def test_regime_without_region_table_accepts_any_region(repo):
    answers = _answers(region="europe-west1", compliance={"regime": "IL2"})
    assert validate.problems(answers, repo) == []


def test_tenant_key_limit_comes_from_resman(repo):
    answers = _answers(
        resman={"tenants": {"abcdefg": {"descriptive_name": "Tenant"}}}
    )
    problems = validate.problems(answers, repo)
    assert (
        "resman.tenants key abcdefg is longer than the 6 characters Stage 1 "
        "allows."
    ) in problems


def test_tenant_ids_over_30_characters(repo):
    answers = _answers(
        prefix="abcdefg",
        resman={
            "envs": {"Production": {}},
            "tenants": {"tenant": {"descriptive_name": "Tenant"}},
        },
    )
    problems = validate.problems(answers, repo)
    # abcdefg-production-tenant-iac-core-0 is 36 characters.
    assert any(
        "project ID abcdefg-production-tenant-iac-core-0 is 36" in problem
        for problem in problems
    )
    assert any("service account ID" in problem for problem in problems)
    assert all(
        problem.startswith("resman.tenants.tenant: ") for problem in problems
    )


@pytest.mark.parametrize(
    "address",
    [
        "google_project.project",
        "google_project.project[0]",
        "module.automation-project.google_project.project[0]",
        "module.billing-export-project[0].google_project.project[0]",
        'module.a["key"].module.b[1].google_x.y["a.b[0]"]',
        'module.a["with \\"quote\\""].google_x.y',
    ],
)
def test_valid_import_addresses(address):
    assert validate.import_address_problems(address) == []


@pytest.mark.parametrize(
    ("address", "message"),
    [
        ("", "empty or has spaces"),
        (" google_x.y", "empty or has spaces"),
        ("google_project", "not a resource address"),
        ("module.automation-project", "names a module"),
        ("module.a.module.b", "names a module"),
        ("data.google_project.x", "data source"),
        ("module.a.data.google_project.x", "data source"),
        ("google_project.project[x]", "not a resource address"),
        ("google_project.project[0", "not a resource address"),
        ("google_project.project.extra", "not a resource address"),
        ("module..google_x.y", "not a resource address"),
        ("1bad.name", "not a resource address"),
        ("google_x.y[0][1]", "not a resource address"),
    ],
)
def test_invalid_import_addresses(address, message):
    problems = validate.import_address_problems(address)
    assert len(problems) == 1
    assert message in problems[0]


def test_problems_include_import_addresses(repo):
    answers = _answers(imports={"0-bootstrap": {"bad address": "x"}})
    problems = validate.problems(answers, repo)
    assert len(problems) == 1
    assert problems[0].startswith("imports.0-bootstrap: Import address")


def test_home_references(tmp_path):
    home = tmp_path / "home"
    answers = _answers(
        overrides={
            "0-bootstrap": {"outputs_location": str(home / "envs/tst")},
            "1-resman": {"other": str(tmp_path / "elsewhere")},
        },
        engine={"path": str(tmp_path / "engine")},
    )
    problems = validate.home_references(answers, home)
    assert len(problems) == 1
    assert problems[0].startswith("overrides.0-bootstrap.outputs_location")


def test_home_references_skip_the_recorded_engine(tmp_path):
    home = tmp_path / "home"
    answers = _answers(
        engine={"path": str(home / "engine")},
        overrides={"1-resman": {"other": str(home / "data")}},
    )
    problems = validate.home_references(answers, home)
    assert len(problems) == 1
    assert problems[0].startswith("overrides.1-resman.other")


def test_home_references_expand_tilde(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    answers = _answers(overrides={"1-resman": {"other": "~/home/engine"}})
    assert validate.home_references(answers, tmp_path / "home")
    assert validate.home_references(_answers(), tmp_path / "home") == []


_AUTOMATION = "module.automation-project.google_project.project[0]"


def test_import_id_must_match_the_prefix(repo):
    # The prefix changes while the imports keep the old project IDs.
    data = render_fixtures.answer_data("lab")
    data["prefix"] = "new1"
    problems = validate.problems(models.Answers.model_validate(data), repo)
    assert len(problems) == 2
    assert problems[0].startswith(
        f"imports.0-bootstrap: {_AUTOMATION} imports lab1-prod-iac-core-0, "
        "but Stage 0 names that project new1-prod-iac-core-0"
    )
    assert "new1-prod-audit-logs-0" in problems[1]


def test_swapped_import_id_is_a_problem(repo):
    answers = _answers(
        imports={"0-bootstrap": {_AUTOMATION: "tst-prod-audit-logs-0"}}
    )
    problems = validate.problems(answers, repo)
    assert len(problems) == 1
    assert "set the import ID to tst-prod-iac-core-0" in problems[0]


def test_unknown_import_addresses_keep_any_id(repo):
    answers = _answers(
        imports={
            "0-bootstrap": {"google_storage_bucket.extra": "any-bucket"},
            "1-resman": {
                'module.x["a"].google_project.project[0]': "any-project"
            },
        }
    )
    assert validate.problems(answers, repo) == []


def test_problems_include_override_problems(repo):
    answers = _answers(
        overrides={
            "0-bootstrap": {"prefix": "other", "not_a_var": 1},
            "1-resman": {"prefix": "zzz"},
        }
    )
    problems = validate.problems(answers, repo)
    assert len(problems) == 3
    assert all(problem.startswith("overrides.") for problem in problems)
