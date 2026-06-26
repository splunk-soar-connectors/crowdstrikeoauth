# Copyright (c) 2019-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_DOWNLOAD_REPORT_ENDPOINT


class DownloadReportParams(Params):
    artifact_id: str = Param(
        description="Artifact ID to download",
        required=True,
        primary=True,
        cef_types=["crowdstrike artifact id"],
        column_name="Artifact ID",
    )
    file_name: str = Param(
        description="Filename to use for the downloaded artifact",
        required=False,
        primary=True,
        cef_types=["filename"],
        column_name="Filename",
    )


class DownloadReportOutput(ActionOutput):
    status: str | None = OutputField(column_name="Status")


@app.action(
    name="download report",
    description="Download the report of a detonated file or URL",
    action_type="investigate",
    read_only=True,
    render_as="table",
)
def download_report(
    params: DownloadReportParams, soar: SOARClient, asset: Asset
) -> list[DownloadReportOutput]:
    client = get_client(asset)

    client.make_rest_call(
        CROWDSTRIKE_DOWNLOAD_REPORT_ENDPOINT,
        params={"id": params.artifact_id},
        headers={"Accept-Encoding": "application/gzip"},
    )

    soar.set_message("Report downloaded successfully")
    return [DownloadReportOutput(status="success")]
