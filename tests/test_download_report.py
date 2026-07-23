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

import pytest
from soar_sdk.exceptions import ActionFailure

from src.actions.download_report import _validate_filename_stem, download_report


@pytest.mark.parametrize(
    "filename",
    [
        "../report",
        "reports/report",
        "/tmp/report",
        "..\\report",
        "reports\\report",
        ".",
        "..",
        "report\0name",
    ],
)
def test_validate_filename_stem_rejects_path_components(filename: str) -> None:
    with pytest.raises(ActionFailure, match="must not contain path components"):
        _validate_filename_stem(filename)


def test_validate_filename_stem_accepts_plain_filename() -> None:
    assert _validate_filename_stem("report-123") == "report-123"


def test_download_report_is_not_read_only() -> None:
    assert download_report.meta.type == "generic"
    assert download_report.meta.read_only is False
