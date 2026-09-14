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

import re
from pathlib import Path


UNESCAPED_JS_TEMPLATE_VALUE = re.compile(r"'\{\{(?![^}]*\|escapejs)[^}]+\}\}'")


def test_widget_javascript_string_values_are_escaped() -> None:
    templates = Path("templates").glob("*.html")
    failures = []
    for template in templates:
        for line_number, line in enumerate(template.read_text().splitlines(), 1):
            if "onclick=" in line and UNESCAPED_JS_TEMPLATE_VALUE.search(line):
                failures.append(f"{template}:{line_number}")

    assert failures == []
