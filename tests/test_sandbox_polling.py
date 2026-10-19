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

from importlib import import_module
from unittest.mock import Mock, call

import pytest
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from src.actions import _sandbox_common as sandbox
from src.consts import CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT


@pytest.fixture
def progress(mocker):
    return mocker.patch.object(getLogger(), "progress")


def test_long_running_analysis_emits_progress_before_every_poll(mocker, progress):
    client = Mock()
    client.make_rest_call.side_effect = [{"resources": [{"state": "running"}]}] * 6 + [
        {"resources": [{"state": "success"}]}
    ]
    sleep = mocker.patch.object(sandbox.time, "sleep")
    events = Mock()
    events.attach_mock(progress, "progress")
    events.attach_mock(client.make_rest_call, "poll")
    events.attach_mock(sleep, "sleep")

    assert sandbox.poll_for_detonation(client, "submission", 10) == ([], "success")

    expected = []
    for poll in range(1, 8):
        expected.extend(
            [
                call.progress(f"Waiting for Falcon Sandbox report, poll {poll}/10..."),
                call.poll(
                    CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT,
                    params={"ids": "submission"},
                ),
            ]
        )
        if poll < 7:
            expected.append(call.sleep(60))
    assert events.mock_calls == expected


@pytest.mark.parametrize("response", [{}, {"resources": []}, {"resources": None}])
def test_empty_responses_emit_progress_until_timeout(mocker, progress, response):
    client = Mock()
    client.make_rest_call.return_value = response
    sleep = mocker.patch.object(sandbox.time, "sleep")

    assert sandbox.poll_for_detonation(client, "submission", 3) == ([], "timeout")

    assert progress.call_args_list == [
        call(f"Waiting for Falcon Sandbox report, poll {poll}/3...")
        for poll in range(1, 4)
    ]
    assert client.make_rest_call.call_count == 3
    assert sleep.call_args_list == [call(60)] * 3


@pytest.mark.parametrize("state", ["success", "failed"])
def test_terminal_analysis_does_not_sleep(mocker, progress, state):
    client = Mock()
    client.make_rest_call.return_value = {"resources": [{"state": state}]}
    sleep = mocker.patch.object(sandbox.time, "sleep")

    if state == "success":
        assert sandbox.poll_for_detonation(client, "submission", 3) == ([], "success")
    else:
        with pytest.raises(ValueError, match="Analysis of the report failed"):
            sandbox.poll_for_detonation(client, "submission", 3)

    progress.assert_called_once_with("Waiting for Falcon Sandbox report, poll 1/3...")
    client.make_rest_call.assert_called_once()
    sleep.assert_not_called()


@pytest.mark.parametrize("kind", ["url", "file"])
@pytest.mark.parametrize("completes", [True, False])
def test_detonation_actions_poll_with_progress(mocker, progress, kind, completes):
    module = import_module(f"src.actions.detonate_{kind}")
    action = getattr(module, f"detonate_{kind}")
    params_cls = getattr(module, f"Detonate{kind.title()}Params")
    target = {"url": "https://example.com"} if kind == "url" else {"vault_id": "vault"}
    params = params_cls(environment="Windows 10, 64-bit", **target)
    soar = Mock()
    soar.vault.get_attachment.return_value = [
        Mock(metadata={"sha256": "sample-hash"}, path="unused", name="sample")
    ]
    asset = Mock(detonate_timeout=8 if completes else 3)
    client = Mock(_required_detonation=True)
    client.paginator.return_value = []
    client.make_rest_call.side_effect = (
        [{"resources": [{"state": "running"}]}] * 6
        + [{"resources": [{"state": "success"}]}]
        if completes
        else [{}] * 3
    )
    mocker.patch.object(module, "get_client", return_value=client)
    mocker.patch.object(module, "submit_for_detonation", return_value="submission")
    if kind == "file":
        mocker.patch.object(module, "upload_sample", return_value="sample-hash")
    reports = [{"id": "submission", "verdict": "No specific threat"}]
    fetch = mocker.patch.object(module, "fetch_reports", return_value=reports)
    sleep = mocker.patch.object(sandbox.time, "sleep")

    if completes:
        outputs = action.__wrapped__(params, soar, asset)
        assert outputs[0].id == "submission"
        assert outputs[0].verdict == "No specific threat"
        fetch.assert_called_once_with(client, ["submission"], False, None)
        soar.set_summary.assert_called_once_with(sandbox.report_summary(reports))
    else:
        with pytest.raises(
            ActionFailure, match="Timed out while waiting for the result"
        ):
            action.__wrapped__(params, soar, asset)
        fetch.assert_not_called()
        soar.set_summary.assert_not_called()

    assert progress.call_args_list == [
        call(
            f"Waiting for Falcon Sandbox report, poll {poll}/{asset.detonate_timeout}..."
        )
        for poll in range(1, (8 if completes else 4))
    ]
    assert sleep.call_args_list == [call(60)] * (6 if completes else 3)
