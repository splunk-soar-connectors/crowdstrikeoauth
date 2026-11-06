# Authored by OpenAI Codex for PAPP-37903.
import base64
import copy
import json
from unittest.mock import Mock

import pytest

from src.helper import CrowdStrikeClient


@pytest.mark.parametrize(
    "state",
    [
        None,
        "old",
        [],
        {"access_token": None},
        {"access_token": []},
        {"access_token": {"oauth2_token": None}},
        {"access_token": {"oauth2_token": {"access_token": 1}}},
    ],
)
def test_malformed_token_cache_is_replaced(asset, monkeypatch, state):
    asset.auth_state.put_all({"unrelated": "preserved", "oauth2_token": state})
    client = CrowdStrikeClient(asset)
    request = Mock(return_value={"access_token": "replacement"})
    monkeypatch.setattr(client, "_make_rest_call", request)
    assert client.access_token() == "replacement"
    assert asset.auth_state["unrelated"] == "preserved"
    assert CrowdStrikeClient(asset).access_token() == "replacement"
    request.assert_called_once()


@pytest.mark.parametrize(
    "response",
    [
        None,
        [],
        "token",
        {},
        {"access_token": None},
        {"access_token": 123},
        {"access_token": " "},
    ],
)
def test_invalid_token_response_fails_before_api_call(client, monkeypatch, response):
    request = Mock(return_value=response)
    monkeypatch.setattr(client, "_make_rest_call", request)
    with pytest.raises(ValueError, match="valid access_token"):
        client.make_rest_call("/test")
    assert "oauth2_token" not in client._tokens
    assert request.call_count == 1


def test_acquisition_error_survives_cleanup_error(client, monkeypatch):
    error = ConnectionError("token acquisition failed")
    monkeypatch.setattr(client, "_make_rest_call", Mock(side_effect=error))
    monkeypatch.setattr(
        client, "_save_tokens", Mock(side_effect=OSError("cache write failed"))
    )
    with pytest.raises(ConnectionError) as result:
        client.access_token()
    assert result.value is error


def test_new_token_persistence_failure_is_reported(client, monkeypatch):
    monkeypatch.setattr(
        client, "_make_rest_call", Mock(return_value={"access_token": "new"})
    )
    monkeypatch.setattr(client, "_save_tokens", Mock(side_effect=OSError("disk")))
    with pytest.raises(RuntimeError, match="persist CrowdStrike OAuth token"):
        client.access_token()
    assert client._tokens == {}


def test_sdk_serializes_token_partition_before_encryption(
    client, asset, state_backend, monkeypatch
):
    monkeypatch.setattr(
        client,
        "_make_rest_call",
        Mock(return_value={"access_token": "secret-token", "expires_in": 1800}),
    )
    assert client.access_token() == "secret-token"
    assert isinstance(state_backend.stored["auth"], str)
    assert "secret-token" not in state_backend.stored["auth"]
    assert CrowdStrikeClient(asset).access_token() == "secret-token"


def test_failed_subtenant_fetch_preserves_other_tokens(client, monkeypatch):
    client._tokens = {
        "oauth2_token": {"access_token": "main"},
        "oauth2_tokenchild": {"access_token": "old"},
    }
    monkeypatch.setattr(
        client, "_make_rest_call", Mock(side_effect=ConnectionError("fetch failed"))
    )
    with pytest.raises(ConnectionError):
        client._get_token("child")
    assert client._tokens == {"oauth2_token": {"access_token": "main"}}


def test_invalid_token_is_refreshed_only_once(client, monkeypatch):
    client._tokens = {"oauth2_token": {"access_token": "old"}}
    headers = []

    def request(url, *args, **kwargs):
        if url.endswith("/oauth2/token"):
            return {"access_token": "replacement"}
        headers.append(dict(args[0]))
        raise RuntimeError("token is invalid")

    mocked = Mock(side_effect=request)
    monkeypatch.setattr(client, "_make_rest_call", mocked)
    with pytest.raises(RuntimeError, match="token is invalid"):
        client.make_rest_call("/test")
    assert mocked.call_count == 3
    assert [h["Authorization"] for h in headers] == ["Bearer old", "Bearer replacement"]


def test_session_refresh_uses_selected_tenant(client, monkeypatch):
    client._tokens = {
        "oauth2_token": {"access_token": "main"},
        "oauth2_tokenchild": {"access_token": "child"},
    }
    request = Mock(return_value={})
    monkeypatch.setattr(client, "_make_rest_call", request)
    client.refresh_datafeed_session("https://feed.example.test/refresh", "child")
    assert request.call_args.args[1]["Authorization"] == "Bearer child"


@pytest.fixture
def feed_response():
    return {
        "meta": {"trace_id": "test"},
        "resources": [
            {
                "dataFeedURL": "https://feed.example.test/events?a=1",
                "sessionToken": {"token": "session-secret"},
                "refreshActiveSessionURL": "https://feed.example.test/refresh",
            }
        ],
    }


@pytest.mark.parametrize(
    "response",
    [
        None,
        [],
        {},
        {"meta": "bad"},
        {"meta": {"x": 1}},
        {"meta": {"x": 1}, "resources": []},
        {"meta": {"x": 1}, "resources": {}},
        {"meta": {"x": 1}, "resources": [None]},
    ],
)
def test_malformed_feed_response_has_connector_error(client, monkeypatch, response):
    monkeypatch.setattr(client, "make_rest_call", Mock(return_value=response))
    with pytest.raises(ValueError, match=r"CrowdStrike|Meta|Datafeed|Session"):
        client.get_datafeed("app-id")


@pytest.mark.parametrize(
    "field,value",
    [
        ("dataFeedURL", " "),
        ("dataFeedURL", 1),
        ("sessionToken", "bad"),
        ("sessionToken", {}),
        ("sessionToken", {"token": 1}),
        ("sessionToken", {"token": " "}),
        ("refreshActiveSessionURL", None),
        ("refreshActiveSessionInterval", None),
        ("refreshActiveSessionInterval", True),
        ("refreshActiveSessionInterval", 0),
        ("refreshActiveSessionInterval", -1),
        ("refreshActiveSessionInterval", "1800"),
    ],
)
def test_invalid_feed_fields_have_connector_error(
    client, monkeypatch, feed_response, field, value
):
    response = copy.deepcopy(feed_response)
    response["resources"][0][field] = value
    monkeypatch.setattr(client, "make_rest_call", Mock(return_value=response))
    with pytest.raises(ValueError, match=r"CrowdStrike|Meta|Datafeed|Session"):
        client.get_datafeed("app-id")


def test_feed_default_interval_and_tenant(client, monkeypatch, feed_response):
    request = Mock(return_value=feed_response)
    monkeypatch.setattr(client, "make_rest_call", request)
    feed = client.get_datafeed("app-id", "child")
    assert feed["refresh_interval"] == 1800
    assert feed["token"] == "session-secret"
    assert request.call_args.kwargs == {
        "params": {"appId": "appid"},
        "subtenant": "child",
    }


@pytest.mark.parametrize("state", [None, [], "invalid"])
def test_malformed_auth_partition_is_replaced(asset, state_backend, monkeypatch, state):
    state_backend.stored["auth"] = base64.b64encode(json.dumps(state).encode()).decode()
    client = CrowdStrikeClient(asset)
    monkeypatch.setattr(
        client, "_make_rest_call", Mock(return_value={"access_token": "replacement"})
    )
    assert client.access_token() == "replacement"
    assert CrowdStrikeClient(asset).access_token() == "replacement"


@pytest.mark.parametrize("upload", [False, True])
def test_rest_call_refresh_success_and_upload_token(client, monkeypatch, upload):
    client._tokens = {"oauth2_token": {"access_token": "old"}}
    responses = (
        [{"access_token": "new"}, {"resources": ["ok"]}]
        if upload
        else [
            RuntimeError("token has expired"),
            {"access_token": "new"},
            {"resources": ["ok"]},
        ]
    )
    request = Mock(side_effect=responses)
    monkeypatch.setattr(client, "_make_rest_call", request)
    assert client.make_rest_call("/test", upload_file=upload) == {"resources": ["ok"]}
    assert request.call_args.args[1]["Authorization"] == "Bearer new"


def test_non_auth_api_failure_does_not_refresh(client, monkeypatch):
    client._tokens = {"oauth2_token": {"access_token": "old"}}
    request = Mock(side_effect=ConnectionError("service unavailable"))
    monkeypatch.setattr(client, "_make_rest_call", request)
    with pytest.raises(ConnectionError, match="service unavailable"):
        client.make_rest_call("/test")
    request.assert_called_once()


def test_token_persistence_false_result_is_reported(
    client, asset, state_backend, monkeypatch
):
    asset.auth_state.put_all({"unrelated": "preserved"})
    request = Mock(return_value={"access_token": "new"})
    monkeypatch.setattr(client, "_make_rest_call", request)
    state_backend.backend.save_state.side_effect = None
    state_backend.backend.save_state.return_value = False
    with pytest.raises(RuntimeError, match="persist CrowdStrike OAuth token"):
        client.make_rest_call("/test")
    request.assert_called_once()
    assert asset.auth_state.get_all() == {"unrelated": "preserved"}
