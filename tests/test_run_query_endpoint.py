# Copyright (c) 2026 Splunk Inc.
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
import pytest

from src.actions.run_query import _validate_query_endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "/devices/queries/devices/v1",
        "/real-time-response/queries/sessions/v1",
        "/ioarules/queries/rule-groups-full/v1",
    ],
)
def test_validate_query_endpoint_accepts_structural_query_paths(endpoint):
    assert _validate_query_endpoint(endpoint) == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "/installation-tokens/entities/tokens/v1?next=/devices/queries/devices/v1",
        "/real-time-response/entities/sessions/v1#/devices/queries/devices/v1",
        "https://example.invalid/devices/queries/devices/v1",
        "/devices/queries/../v1",
        "/devices/queries/devices%2fother/v1",
        "/devices/queries/devices/v1/extra",
        "devices/queries/devices/v1",
    ],
)
def test_validate_query_endpoint_rejects_non_query_or_ambiguous_paths(endpoint):
    with pytest.raises(ValueError, match="query endpoint"):
        _validate_query_endpoint(endpoint)
