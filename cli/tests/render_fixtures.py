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

"""Answer fixtures and helpers shared by the render tests."""

import pathlib
import subprocess

import yaml

from stellar_engine import paths
from stellar_engine.config import models

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
ANSWERS_DIR = FIXTURES / "answers"
STAGE_OUTPUTS_DIR = FIXTURES / "stage-outputs"
# One fixture per regime plus the lab-shaped case with imports.
REGIME_FIXTURES = (
    "fedramp_high",
    "fedramp_moderate",
    "il4",
    "il5",
    "unspecified",
)
ALL_FIXTURES = (*REGIME_FIXTURES, "lab")
# A fixed home keeps `outputs_location` stable across snapshot runs.
SNAPSHOT_HOME = pathlib.Path("/home/operator/.stellar")


def answer_data(name):
    """Returns the raw answer data of a fixture."""
    path = ANSWERS_DIR / f"{name}.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_answers(name, **updates):
    """Returns the validated answers of a fixture with top-level updates."""
    data = answer_data(name)
    data.update(updates)
    return models.Answers.model_validate(data)


def env_paths(answers, home=SNAPSHOT_HOME):
    """Returns the EnvPaths of the answers' prefix under a home."""
    return paths.EnvPaths(home / "envs" / answers.prefix, answers.prefix)


def terraform(directory, *args):
    """Runs terraform in a directory and returns the completed process."""
    return subprocess.run(
        ["terraform", f"-chdir={directory}", *args, "-no-color"],
        capture_output=True,
        check=False,
        text=True,
        timeout=600,
    )
