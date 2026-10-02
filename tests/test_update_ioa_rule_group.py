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

from src.actions.update_ioa_rule_group import (
    UpdateIoaRuleGroupParams,
    update_ioa_rule_group,
)
from src.consts import CROWDSTRIKE_IOA_CREATE_RULE_GROUP_ENDPOINT


def make_params(enabled: str | bool | None = None) -> UpdateIoaRuleGroupParams:
    values = dict(
        id="group",
        version=2,
        name="test",
        description="test group",
        comment="update",
    )
    if enabled is not None:
        values["enabled"] = enabled
    return UpdateIoaRuleGroupParams(**values)


@pytest.mark.parametrize(
    ("enabled", "expected"),
    [
        (None, None),
        ("preserve", None),
        ("enable", True),
        ("disable", False),
        (True, True),
        (False, False),
        ("True", True),
        ("False", False),
    ],
)
def test_update_ioa_rule_group_preserves_or_sets_enabled_state(
    enabled: str | bool | None, expected: bool | None
) -> None:
    client = Mock()
    client.make_rest_call.return_value = {"resources": [{"id": "group"}]}

    with patch("src.actions.update_ioa_rule_group.get_client", return_value=client):
        update_ioa_rule_group.__wrapped__(make_params(enabled), Mock(), Mock())

    client.make_rest_call.assert_called_once()
    args, kwargs = client.make_rest_call.call_args
    assert args == (CROWDSTRIKE_IOA_CREATE_RULE_GROUP_ENDPOINT,)
    assert kwargs["method"] == "patch"
    body = kwargs["json_data"]
    if expected is None:
        assert "enabled" not in body
    else:
        assert body["enabled"] is expected


def test_update_ioa_rule_group_exposes_choice_control() -> None:
    schema = UpdateIoaRuleGroupParams._to_json_schema()["enabled"]
    assert schema["data_type"] == "string"
    assert schema["default"] == "preserve"
    assert schema["value_list"] == ["preserve", "enable", "disable"]


def test_update_ioa_rule_group_rejects_invalid_choice() -> None:
    client = Mock()
    with (
        patch("src.actions.update_ioa_rule_group.get_client", return_value=client),
        pytest.raises(ValueError, match="enabled must be"),
    ):
        update_ioa_rule_group.__wrapped__(make_params("unexpected"), Mock(), Mock())
    client.make_rest_call.assert_not_called()
