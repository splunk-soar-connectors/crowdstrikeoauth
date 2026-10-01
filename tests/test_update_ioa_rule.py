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

from unittest.mock import Mock, patch

import pytest

from src.actions.update_ioa_rule import UpdateIoaRuleParams, update_ioa_rule
from src.consts import CROWDSTRIKE_IOA_UPDATE_RULE_ENDPOINT


@pytest.mark.parametrize("enabled", [None, False, True])
def test_update_ioa_rule_preserves_or_sets_enabled_state(enabled: bool | None) -> None:
    params = UpdateIoaRuleParams(
        rule_group_id="group",
        rule_group_version=2,
        rule_id="rule",
        rule_version=3,
        name="test",
        description="test rule",
        severity="high",
        disposition_id=10,
        field_values="[]",
        enabled=enabled,
    )
    client = Mock()
    client.make_rest_call.return_value = {
        "resources": [
            {
                "id": "group",
                "rules": [
                    {"instance_id": "rule", "magic_cookie": 2, "instance_version": 4}
                ],
            }
        ]
    }

    with patch("src.actions.update_ioa_rule.get_client", return_value=client):
        update_ioa_rule.__wrapped__(params, Mock(), Mock())

    args, kwargs = client.make_rest_call.call_args
    assert args == (CROWDSTRIKE_IOA_UPDATE_RULE_ENDPOINT,)
    assert kwargs["method"] == "patch"
    rule_update = kwargs["json_data"]["rule_updates"][0]
    if enabled is None:
        assert "enabled" not in rule_update
    else:
        assert rule_update["enabled"] is enabled
