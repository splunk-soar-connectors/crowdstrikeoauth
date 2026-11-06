# Authored by OpenAI Codex for PAPP-37903.
import base64
import copy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from soar_sdk.asset_state import AssetState

from src.app import Asset
from src.helper import CrowdStrikeClient


@pytest.fixture
def state_backend(monkeypatch):
    """Use real SDK partitions with isolated, copy-on-write persistence."""
    stored = {}
    backend = Mock()
    backend.load_state.side_effect = lambda: copy.deepcopy(stored)

    def save(state):
        stored.clear()
        stored.update(copy.deepcopy(state))

    backend.save_state.side_effect = save
    monkeypatch.setattr(
        "soar_sdk.asset_state.is_onprem_broker_rpc_install", lambda: False
    )

    def encrypt(value, salt):
        assert isinstance(value, str)
        return base64.b64encode(value.encode()).decode()

    monkeypatch.setattr("soar_sdk.asset_state.encryption_helper.encrypt", encrypt)
    monkeypatch.setattr(
        "soar_sdk.asset_state.encryption_helper.decrypt",
        lambda value, salt: base64.b64decode(value).decode(),
    )
    return SimpleNamespace(backend=backend, stored=stored)


@pytest.fixture
def asset(state_backend):
    value = Asset(
        url="https://api.example.test",
        client_id="test-id",
        client_secret="test-secret",
        subtenants=None,
        app_id="app-id",
        collate=True,
    )
    value._auth_state = AssetState(state_backend.backend, "auth", "1")
    value._ingest_state = AssetState(state_backend.backend, "ingest", "1")
    return value


@pytest.fixture
def client(asset):
    return CrowdStrikeClient(asset)


@pytest.fixture
def detection_event():
    def make(offset=42, event_type="DetectionSummaryEvent", sub_events=True):
        details = (
            {
                "DetectName": "Test detection",
                "DetectDescription": "Suspicious process",
                "ComputerName": "test-host",
                "Severity": 3,
            }
            if event_type == "DetectionSummaryEvent"
            else {
                "Name": "Test detection",
                "Description": "Suspicious process",
                "Hostname": "test-host",
                "SeverityName": "medium",
            }
        )
        if sub_events:
            details["FilesAccessed"] = [{"FileName": "evidence.txt"}]
        return {
            "metadata": {
                "eventType": event_type,
                "offset": offset,
                "eventCreationTime": 1609459200000 + offset * 1000,
            },
            "event": details,
        }

    return make
