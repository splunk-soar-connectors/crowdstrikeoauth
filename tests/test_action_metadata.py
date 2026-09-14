# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from src.actions.detonate_file import DetonateFileParams
from src.actions.detonate_url import DetonateUrlParams
from src.app import app


def test_run_query_requires_approval() -> None:
    action = app.actions_manager._actions["run_query"]

    assert action.meta.read_only is False


def test_document_passwords_generate_password_parameters() -> None:
    assert (
        DetonateFileParams._to_json_schema()["document_password"]["data_type"]
        == "password"
    )
    assert (
        DetonateUrlParams._to_json_schema()["document_password"]["data_type"]
        == "password"
    )
