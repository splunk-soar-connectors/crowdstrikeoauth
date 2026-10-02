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


def normalize_ioa_enabled(value: object) -> object:
    """Accept old Boolean action inputs alongside the new SOAR choice values."""
    if value is None:
        return "preserve"
    if isinstance(value, bool):
        return "enable" if value else "disable"
    if isinstance(value, str):
        choice = value.strip().lower()
        return {"": "preserve", "true": "enable", "false": "disable"}.get(
            choice, choice
        )
    return value
