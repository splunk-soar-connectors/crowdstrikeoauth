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

from io import BytesIO
from unittest.mock import Mock

import pytest
from requests import Response

from src.helper import CrowdStrikeClient


def _response(body: bytes) -> Response:
    response = Response()
    response.status_code = 200
    response.headers["Content-Type"] = "application/json"
    response.raw = BytesIO(body)
    return response


def test_rest_call_rejects_oversized_body_before_json_parse(monkeypatch) -> None:
    body = b'{"resources":[{"stdout":"' + b"x" * 100 + b'"}]}'
    response = _response(body)
    request = Mock(return_value=response)
    monkeypatch.setattr("src.helper.requests.request", request)
    client = object.__new__(CrowdStrikeClient)
    client._stream_file_data = False
    client._process_json_response = Mock()

    with pytest.raises(ValueError, match="Response exceeded the maximum size"):
        client._make_rest_call("https://example.test/results", max_response_bytes=40)

    assert request.call_args.kwargs["stream"] is True
    client._process_json_response.assert_not_called()
    assert response.raw.closed


def test_rest_call_accepts_body_within_limit(monkeypatch) -> None:
    body = b'{"resources":["ok"]}'
    request = Mock(return_value=_response(body))
    monkeypatch.setattr("src.helper.requests.request", request)
    client = object.__new__(CrowdStrikeClient)
    client._stream_file_data = False

    assert client._make_rest_call(
        "https://example.test/results", max_response_bytes=len(body)
    ) == {"resources": ["ok"]}


def test_paginator_limits_accumulated_bytes(monkeypatch) -> None:
    monkeypatch.setattr("src.helper.MAX_PAGINATION_BYTES", 12)
    client = object.__new__(CrowdStrikeClient)
    client.make_rest_call = Mock(
        side_effect=[
            {"meta": {"pagination": {"offset": 1, "total": 2}}, "resources": ["abcd"]},
            {"meta": {"pagination": {"offset": 2, "total": 2}}, "resources": ["efgh"]},
        ]
    )

    with pytest.raises(Exception, match="Pagination exceeded the maximum result size"):
        client.paginator("/queries/example/v1")


def test_hunt_paginator_limits_accumulated_bytes(monkeypatch) -> None:
    monkeypatch.setattr("src.helper.MAX_PAGINATION_BYTES", 12)
    client = object.__new__(CrowdStrikeClient)
    client._last_hunt_total = 0
    client._last_hunt_total_known = True
    client._last_hunt_truncated = False
    client.make_rest_call = Mock(
        side_effect=[
            {
                "meta": {"pagination": {"offset": "next", "next_page": True}},
                "resources": ["abcd"],
            },
            {"meta": {"pagination": {"offset": None}}, "resources": ["efgh"]},
        ]
    )

    with pytest.raises(Exception, match="Pagination exceeded the maximum result size"):
        client.hunt_paginator("/queries/example/v1", {})
