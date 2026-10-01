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
from src.consts import CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT


def make_params(enabled: str | None = None) -> UpdateIoaRuleParams:
    values = dict(
        rule_group_id="group",
        rule_group_version=2,
        rule_id="rule",
        rule_version=3,
        name="test",
        description="test rule",
        severity="high",
        disposition_id=10,
        field_values="[]",
    )
    if enabled is not None:
        values["enabled"] = enabled
    return UpdateIoaRuleParams(**values)


@pytest.mark.parametrize(
    ("enabled", "current_state", "expected"),
    [
        (None, True, True),
        (None, False, False),
        ("preserve", True, True),
        ("preserve", False, False),
        ("enable", None, True),
        ("disable", None, False),
    ],
)
def test_update_ioa_rule_preserves_or_sets_enabled_state(
    enabled: str | None, current_state: bool | None, expected: bool
) -> None:
    params = make_params(enabled)
    client = Mock()
    update_response = {
        "resources": [
            {
                "id": "group",
                "rules": [
                    {"instance_id": "rule", "magic_cookie": 2, "instance_version": 4}
                ],
            }
        ]
    }
    if enabled is None or enabled == "preserve":
        client.make_rest_call.side_effect = [
            {
                "resources": [
                    {
                        "instance_id": "rule",
                        "rulegroup_id": "group",
                        "enabled": current_state,
                    }
                ]
            },
            update_response,
        ]
    else:
        client.make_rest_call.return_value = update_response

    with patch("src.actions.update_ioa_rule.get_client", return_value=client):
        update_ioa_rule.__wrapped__(params, Mock(), Mock())

    args, kwargs = client.make_rest_call.call_args
    assert args == (CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT,)
    assert kwargs["method"] == "patch"
    rule_update = kwargs["json_data"]["rule_updates"][0]
    assert rule_update["enabled"] is expected
    if enabled is None or enabled == "preserve":
        assert client.make_rest_call.call_count == 2
        get_args, get_kwargs = client.make_rest_call.call_args_list[0]
        assert get_args == (CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT,)
        assert get_kwargs == {"params": {"ids": "rule"}, "method": "get"}
    else:
        client.make_rest_call.assert_called_once()


@pytest.mark.parametrize(
    "current_rules",
    [
        {"resources": []},
        {
            "resources": [
                {"instance_id": "other", "rulegroup_id": "group", "enabled": True}
            ]
        },
        {
            "resources": [
                {"instance_id": "rule", "rulegroup_id": "other", "enabled": True}
            ]
        },
        {"resources": [{"instance_id": "rule", "rulegroup_id": "group"}]},
    ],
)
def test_update_ioa_rule_rejects_missing_enabled_state(current_rules: dict) -> None:
    client = Mock()
    client.make_rest_call.return_value = current_rules

    with (
        patch("src.actions.update_ioa_rule.get_client", return_value=client),
        pytest.raises(ValueError, match="current rule enabled state"),
    ):
        update_ioa_rule.__wrapped__(make_params(), Mock(), Mock())

    client.make_rest_call.assert_called_once()


def test_update_ioa_rule_exposes_choice_control() -> None:
    schema = UpdateIoaRuleParams._to_json_schema()["enabled"]
    assert schema["data_type"] == "string"
    assert schema["default"] == "preserve"
    assert schema["value_list"] == ["preserve", "enable", "disable"]


def test_update_ioa_rule_rejects_invalid_choice() -> None:
    client = Mock()
    with (
        patch("src.actions.update_ioa_rule.get_client", return_value=client),
        pytest.raises(ValueError, match="enabled must be"),
    ):
        update_ioa_rule.__wrapped__(make_params("unexpected"), Mock(), Mock())
    client.make_rest_call.assert_not_called()
