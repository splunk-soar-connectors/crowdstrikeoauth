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

from src.app import Asset, _load_preprocess_container


def test_preprocess_script_requires_edit_code():
    schema = Asset.to_json_schema()

    assert schema["preprocess_script"]["data_type"] == "python_script"


def test_load_preprocess_container():
    preprocess_container = _load_preprocess_container(
        "def preprocess_container(container):\n"
        "    container['name'] = 'processed'\n"
        "    return container\n"
    )

    assert preprocess_container is not None
    assert preprocess_container({"name": "original"})["name"] == "processed"
