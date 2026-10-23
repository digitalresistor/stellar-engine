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

"""Minimal answer data shared by the config and wizard tests."""

import conftest


def answer_data(**overrides):
    """Returns minimal valid answer data with placeholder values."""
    data = {
        "prefix": "tst",
        "organization": {
            "id": conftest.ORG_ID,
            "domain": conftest.DOMAIN,
            "customer_id": conftest.CUSTOMER_ID,
        },
        "billing": {"account_id": conftest.BILLING},
        "bootstrap_project": conftest.PROJECT,
        "region": "us-east4",
        "compliance": {"regime": "IL5"},
        "alert_email": f"alerts@{conftest.DOMAIN}",
    }
    data.update(overrides)
    return data
