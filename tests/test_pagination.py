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

from unittest.mock import Mock

import pytest

from src.helper import CrowdStrikeClient


def _client(*responses: dict) -> CrowdStrikeClient:
    client = object.__new__(CrowdStrikeClient)
    client._required_detonation = False
    client._last_hunt_total = 0
    client.make_rest_call = Mock(side_effect=responses)
    return client


def test_paginator_rejects_empty_nonterminal_page() -> None:
    client = _client(
        {"meta": {"pagination": {"offset": 0, "total": 2}}, "resources": []}
    )

    with pytest.raises(Exception, match="made no progress"):
        client.paginator("/queries/example/v1")


def test_hunt_paginator_rejects_repeated_cursor() -> None:
    client = _client(
        {
            "meta": {"pagination": {"offset": "same", "next_page": "next"}},
            "resources": ["first"],
        },
        {
            "meta": {"pagination": {"offset": "same", "next_page": "next"}},
            "resources": ["second"],
        },
    )

    with pytest.raises(Exception, match="made no progress"):
        client.hunt_paginator("/queries/example/v1", {})


def test_hunt_paginator_records_authoritative_total() -> None:
    client = _client(
        {
            "meta": {"pagination": {"offset": None, "total": 250}},
            "resources": ["first", "second"],
        }
    )

    assert client.hunt_paginator("/queries/example/v1", {"limit": 2}) == [
        "first",
        "second",
    ]
    assert client._last_hunt_total == 250
