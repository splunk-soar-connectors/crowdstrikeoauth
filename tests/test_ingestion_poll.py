# Authored by OpenAI Codex for PAPP-37903 and SOARHELP-7363.
import copy
import importlib
import json
from unittest.mock import Mock

import pytest
from soar_sdk.params import OnPollParams

from src import parse_cs_events as parser

connector = importlib.import_module("src.app")


@pytest.fixture
def poll(asset, client, monkeypatch, detection_event):
    response = Mock(status_code=200)
    response.iter_lines.side_effect = lambda **kwargs: iter(
        [json.dumps(detection_event()).encode()]
    )
    client.get_datafeed = Mock(
        return_value={
            "data_feed_url": "https://feed.example.test/events?secret=never-log",
            "token": "never-log-token",
            "refresh_url": "https://feed.example.test/refresh",
            "refresh_interval": 1800,
        }
    )
    client.stream_datafeed = Mock(return_value=response)
    client.refresh_datafeed_session = Mock()
    monkeypatch.setattr(connector, "get_client", lambda asset: client)
    monkeypatch.setattr(connector.app, "_asset", asset, raising=False)
    monkeypatch.setattr(
        connector.app, "_adapt_action_result", lambda result, manager: result.status
    )
    manager = connector.app.actions_manager
    save_container = Mock(return_value=(True, "Created", 101))
    save_artifacts = Mock(return_value=(True, "Saved", [1]))
    monkeypatch.setattr(manager, "save_container", save_container)
    monkeypatch.setattr(manager, "save_artifacts", save_artifacts)
    monkeypatch.setattr(manager, "add_exception", Mock())
    asset.ingest_state["last_offset_id"] = 40
    return response, save_container, save_artifacts


def run_poll(manual=False):
    return connector.on_poll(
        OnPollParams(start_time=0, end_time=1, container_count=1 if manual else None)
    )


def test_checkpoint_commits_after_final_artifact_flush(poll, asset, state_backend):
    response, _, save = poll
    before = copy.deepcopy(state_backend.stored)

    def save_artifacts(artifacts):
        assert state_backend.stored == before
        assert asset.ingest_state["last_offset_id"] == 43
        return True, "Saved", [1]

    save.side_effect = save_artifacts
    assert run_poll() is True
    assert asset.ingest_state["last_offset_id"] == 43
    assert state_backend.stored != before
    response.close.assert_called_once()


@pytest.mark.parametrize(
    "failure",
    [
        "discovery",
        "opening",
        "http",
        "read",
        "parse",
        "no_results",
        "incomplete_result",
        "model",
        "container",
        "artifact",
        "checkpoint",
    ],
)
def test_failures_preserve_durable_checkpoint(
    poll, client, asset, state_backend, monkeypatch, failure, detection_event
):
    response, save_container, save_artifacts = poll
    before = copy.deepcopy(state_backend.stored)
    if failure == "discovery":
        client.get_datafeed.side_effect = ValueError("no resources")
    elif failure == "opening":
        client.stream_datafeed.side_effect = ConnectionError("connect")
    elif failure == "http":
        response.status_code = 403
    elif failure == "read":

        def lines(**kwargs):
            yield json.dumps(detection_event()).encode()
            raise ConnectionError("read failed")

        response.iter_lines.side_effect = lines
    elif failure == "parse":
        monkeypatch.setattr(
            parser, "parse_events", Mock(side_effect=ValueError("parse failed"))
        )
    elif failure in {"no_results", "incomplete_result", "model"}:
        results = (
            []
            if failure == "no_results"
            else [
                {
                    "container": {"name": "test"},
                    "artifacts": []
                    if failure == "incomplete_result"
                    else [{"cef": "not a dictionary"}],
                }
            ]
        )
        monkeypatch.setattr(parser, "parse_events", Mock(return_value=results))
    elif failure == "container":
        save_container.return_value = False, "Rejected", None
    elif failure == "artifact":
        save_artifacts.return_value = False, "Rejected", None
    else:
        state_backend.backend.save_state.side_effect = OSError("disk")
    assert run_poll() is False
    assert state_backend.stored == before
    assert asset.ingest_state["last_offset_id"] == 40
    if failure not in {"discovery", "opening"}:
        response.close.assert_called_once()
    else:
        response.close.assert_not_called()


@pytest.mark.parametrize("manual,lines", [(False, []), (True, None)])
def test_empty_and_manual_polls_preserve_checkpoint(
    poll, asset, state_backend, manual, lines
):
    response, _, _ = poll
    before = copy.deepcopy(state_backend.stored)
    if lines is not None:
        response.iter_lines.side_effect = lambda **kwargs: iter(lines)
    assert run_poll(manual) is True
    assert state_backend.stored == before
    response.close.assert_called_once()


@pytest.mark.parametrize(
    "record",
    [
        b"not json",
        b"null",
        b"[]",
        b'{"metadata":null}',
        b'{"metadata":{"eventType":"DetectionSummaryEvent"},"event":{}}',
    ],
)
def test_malformed_records_allow_valid_events_to_commit(
    poll, asset, detection_event, record
):
    response, _, save = poll
    response.iter_lines.side_effect = lambda **kwargs: iter(
        [
            json.dumps(detection_event(41)).encode(),
            record,
            json.dumps(detection_event(43)).encode(),
        ]
    )
    assert run_poll() is True
    assert asset.ingest_state["last_offset_id"] == 44
    assert sum(len(call.args[0]) for call in save.call_args_list) == 4


@pytest.mark.parametrize(
    "field,value",
    [("offset", True), ("offset", -1), ("offset", "42"), ("event", []), ("name", " ")],
)
def test_invalid_detection_structure_is_skipped(
    poll, asset, detection_event, field, value
):
    event = detection_event()
    if field == "offset":
        event["metadata"][field] = value
    elif field == "name":
        event["event"]["DetectName"] = value
    else:
        event[field] = value
    poll[0].iter_lines.side_effect = lambda **kwargs: iter([json.dumps(event).encode()])
    assert run_poll() is True
    assert asset.ingest_state["last_offset_id"] == 40
    poll[2].assert_not_called()


@pytest.mark.parametrize("has_events", [False, True])
def test_refresh_failure_only_saves_already_received_events(
    poll, client, asset, monkeypatch, detection_event, has_events
):
    response, _, save = poll
    response.iter_lines.side_effect = lambda **kwargs: iter(
        [
            json.dumps(detection_event(41)).encode(),
            json.dumps(detection_event(42)).encode(),
        ]
    )
    clock = iter([0, 0, 2000] if has_events else [0, 2000])
    monkeypatch.setattr(connector.time, "time", lambda: next(clock, 2000))
    client.refresh_datafeed_session.side_effect = ConnectionError("refresh failed")
    assert run_poll() is has_events
    assert asset.ingest_state["last_offset_id"] == (42 if has_events else 40)
    assert save.call_count == int(has_events)
    response.close.assert_called_once()


@pytest.mark.parametrize("stop", ["event", "blank", "none", "unsupported"])
def test_normal_stream_stop_reasons(poll, asset, detection_event, stop):
    response, _, _ = poll
    event = json.dumps(detection_event()).encode()
    lines = [event, event]
    if stop == "event":
        asset.max_events = 1
    elif stop == "blank":
        asset.max_crlf = 1
        lines = [event, b"", b"", event]
    elif stop == "none":
        lines = [event, None, event]
    else:
        other = detection_event(99)
        other["metadata"]["eventType"] = "OtherEvent"
        lines = [event, json.dumps(other).encode()]
    response.iter_lines.side_effect = lambda **kwargs: iter(lines)
    assert run_poll() is True
    assert asset.ingest_state["last_offset_id"] == 43
    response.close.assert_called_once()


def test_checkpoint_does_not_regress(poll, asset, detection_event):
    asset.ingest_state["last_offset_id"] = 100
    assert run_poll() is True
    assert asset.ingest_state["last_offset_id"] == 100


def test_later_tenant_failure_rolls_back_all_checkpoints(
    poll, client, asset, state_backend
):
    asset.subtenants = "child"
    before = copy.deepcopy(state_backend.stored)
    client.get_datafeed.side_effect = [
        client.get_datafeed.return_value,
        ValueError("child failed"),
    ]
    assert run_poll() is False
    assert state_backend.stored == before
    assert "last_offset_id_child" not in asset.ingest_state


def test_duplicate_container_reuses_artifacts_and_commits(poll, asset):
    _, container, artifacts = poll
    container.return_value = False, "Duplicate container found", 101
    assert run_poll() is True
    assert artifacts.call_args.args[0][0]["container_id"] == 101
    assert asset.ingest_state["last_offset_id"] == 43


@pytest.mark.parametrize("collate", [False, True])
@pytest.mark.parametrize(
    "event_type", ["DetectionSummaryEvent", "EppDetectionSummaryEvent"]
)
@pytest.mark.parametrize("sub_events", [False, True])
def test_automation_templates_and_identifiers(
    detection_event, monkeypatch, collate, event_type, sub_events
):
    events = [detection_event(offset, event_type, sub_events) for offset in (41, 42)]
    results = parser.parse_events(events, collate)
    assert results
    assert all(result["container"]["run_automation"] is False for result in results)
    assert all(
        artifact["run_automation"] is True
        for result in results
        for artifact in result["artifacts"]
    )
    expected_ids = [
        [artifact["source_data_identifier"] for artifact in result["artifacts"]]
        for result in results
    ]
    monkeypatch.setitem(parser._artifact_common, "run_automation", False)
    monkeypatch.setitem(parser._sub_artifact_common, "run_automation", False)
    legacy = parser.parse_events(events, collate)
    assert expected_ids == [
        [artifact["source_data_identifier"] for artifact in result["artifacts"]]
        for result in legacy
    ]
    assert [r["container"]["source_data_identifier"] for r in results] == [
        r["container"]["source_data_identifier"] for r in legacy
    ]
    assert all(
        item.run_automation is False for item in connector._yield_results(legacy)
    )


def test_new_artifact_preceding_duplicate_still_requests_automation(
    poll, detection_event
):
    poll[0].iter_lines.side_effect = lambda **kwargs: iter(
        [
            json.dumps(detection_event(41, sub_events=False)).encode(),
            json.dumps(detection_event(42, sub_events=False)).encode(),
        ]
    )

    def save(artifacts):
        assert artifacts[-1]["source_data_identifier"] == "42"
        newly_created = [a for a in artifacts if a["source_data_identifier"] != "42"]
        assert newly_created
        assert all(a["run_automation"] for a in newly_created)
        return True, "Saved", [1]

    poll[2].side_effect = save
    assert run_poll() is True


def test_stage_logs_omit_sensitive_data_and_label_staging(poll, monkeypatch):
    logger = Mock()
    monkeypatch.setattr(connector, "logger", logger)
    assert run_poll() is True
    messages = " ".join(str(call.args[0]) for call in logger.method_calls)
    assert "Checkpoint staged" in messages
    assert "commit pending SDK artifact saves" in messages
    for secret in ["never-log", "never-log-token", "evidence.txt", "test-secret"]:
        assert secret not in messages


def test_subartifact_identifier_matches_captured_legacy_value(detection_event):
    artifact = parser.parse_events([detection_event()], False)[0]["artifacts"][1]
    assert (
        artifact["source_data_identifier"]
        == "3e3dddd87739c948aee259845f7e50ed6c843c2ae637bed274d2322496ec0a3c"
    )


def test_default_app_id_uses_sdk_metadata(poll, asset, client):
    asset.app_id = None
    assert run_poll() is True
    client.get_datafeed.assert_called_once_with(
        str(connector.app.app_meta_info["appid"]), subtenant=None
    )


@pytest.mark.parametrize("failure", [None, "container", "artifact", "checkpoint"])
def test_sdk_already_protects_checkpoints(poll, asset, state_backend, failure):
    """This contract must also hold with connector source preceding the fix."""
    before = copy.deepcopy(state_backend.stored)
    if failure == "container":
        poll[1].return_value = False, "Rejected", None
    elif failure == "artifact":
        poll[2].return_value = False, "Rejected", None
    elif failure == "checkpoint":
        state_backend.backend.save_state.side_effect = OSError("disk")
    else:

        def save(artifacts):
            assert state_backend.stored == before
            return True, "Saved", [1]

        poll[2].side_effect = save
    assert run_poll() is (failure is None)
    assert asset.ingest_state["last_offset_id"] == (43 if failure is None else 40)
    if failure:
        assert state_backend.stored == before


def test_legacy_checkpoint_migration_is_not_repeated(poll, asset, state_backend):
    del asset.ingest_state["last_offset_id"]
    state_backend.stored["last_offset_id"] = 41
    assert run_poll() is True
    assert asset.ingest_state["last_offset_id"] == 43
    state_backend.stored["last_offset_id"] = 1
    assert run_poll() is True
    assert asset.ingest_state["last_offset_id"] == 43


def test_subtenant_success_keeps_separate_checkpoint(
    poll, asset, client, detection_event
):
    asset.subtenants = "child"
    asset.ingest_state["last_offset_id_child"] = 5
    responses = [Mock(status_code=200), Mock(status_code=200)]
    for response, offset in zip(responses, [42, 7], strict=True):
        response.iter_lines.return_value = iter(
            [json.dumps(detection_event(offset)).encode()]
        )
    client.stream_datafeed.side_effect = responses
    assert run_poll() is True
    assert asset.ingest_state["last_offset_id"] == 43
    assert asset.ingest_state["last_offset_id_child"] == 8


@pytest.mark.parametrize("stage", ["feed discovery", "stream reading", "event parsing"])
def test_failure_logs_identify_stage(poll, client, monkeypatch, stage):
    logger = Mock()
    monkeypatch.setattr(connector, "logger", logger)
    error = ValueError("do-not-log-sensitive-error")
    if stage == "feed discovery":
        client.get_datafeed.side_effect = error
    elif stage == "stream reading":
        poll[0].iter_lines.side_effect = error
    else:
        monkeypatch.setattr(parser, "parse_events", Mock(side_effect=error))
    assert run_poll() is False
    message = logger.error.call_args.args[0]
    assert f"stage={stage}" in message
    assert "do-not-log-sensitive-error" not in message


def test_successful_session_refresh_continues_poll(
    poll, asset, client, monkeypatch, detection_event
):
    clock = iter([0, 0, 2000, 2000])
    monkeypatch.setattr(connector.time, "time", lambda: next(clock, 2000))
    poll[0].iter_lines.side_effect = lambda **kwargs: iter(
        [
            json.dumps(detection_event(41)).encode(),
            json.dumps(detection_event(42)).encode(),
        ]
    )
    assert run_poll() is True
    client.refresh_datafeed_session.assert_called_once()
    assert asset.ingest_state["last_offset_id"] == 43


@pytest.mark.parametrize("checkpoint", [None, "invalid", -1])
def test_invalid_legacy_checkpoint_starts_at_zero(poll, asset, client, checkpoint):
    asset.ingest_state["last_offset_id"] = checkpoint
    assert run_poll() is True
    assert client.stream_datafeed.call_args.args[-1] == 0
