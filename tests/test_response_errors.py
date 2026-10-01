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


def test_non_success_json_error_keeps_status_and_server_message() -> None:
    response = Mock(status_code=409)
    response.json.return_value = {
        "errors": [{"code": 409, "message": "file with given name already exists"}]
    }

    with pytest.raises(
        Exception,
        match="Error from server. Status Code: 409 Data from server:  file with given name already exists",
    ):
        CrowdStrikeClient._process_json_response(None, response)


def test_success_status_with_error_payload_still_fails() -> None:
    response = Mock(status_code=200)
    response.json.return_value = {"resources": [], "errors": [{"code": 42, "message": "bad data"}]}

    with pytest.raises(Exception, match="Error from server. Error details: 42 - bad data"):
        CrowdStrikeClient._process_json_response(None, response)
