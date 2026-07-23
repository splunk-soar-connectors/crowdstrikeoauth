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
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    CROWDSTRIKE_QUERY_FILE_ENDPOINT,
    CROWDSTRIKE_QUERY_REPORT_ENDPOINT,
)
from ._sandbox_common import (
    SandboxReportOutput,
    SandboxReportSummary,
    build_param_dict,
    build_report_view,
    fetch_reports,
    report_summary,
)


REPUTATION_SORT_LIST = [
    "verdict.asc",
    "verdict.desc",
    "created_timestamp.asc",
    "created_timestamp.desc",
    "environment_description.asc",
    "environment_description.desc",
    "threat_score.asc",
    "threat_score.desc",
]
API_SORT_LIST = [
    "created_timestamp.asc",
    "created_timestamp.desc",
]

PARAM_KEYS = ["vault_id", "sha256", "sort", "offset", "limit", "detail_report"]


class FileReputationParams(Params):
    vault_id: str = Param(
        description="Vault ID of file to get the reputation of",
        required=False,
        primary=True,
        cef_types=["vault id"],
    )
    sha256: str = Param(
        description="SHA256 of file to get the reputation of",
        required=False,
        primary=True,
        cef_types=["sha256"],
    )
    limit: int = Param(
        description="Maximum reports to be fetched",
        required=False,
        default=50,
    )
    sort: str = Param(
        description="Property to sort by",
        required=False,
        value_list=REPUTATION_SORT_LIST,
    )
    offset: int = Param(
        description="Starting index of overall result set",
        required=False,
        default=0,
    )
    detail_report: bool = Param(
        description="Provide a detailed report of the file",
        required=False,
        default=False,
    )


@app.view_handler(template="crowdstrike_file_reputation.html")
def file_reputation_view(outputs: list[SandboxReportOutput]) -> dict:
    return build_report_view(outputs, "file reputation", PARAM_KEYS)


@app.action(
    name="file reputation",
    description="Queries CrowdStrike for the file reputation info",
    action_type="investigate",
    read_only=True,
    view_handler=file_reputation_view,
    summary_type=SandboxReportSummary,
)
def file_reputation(
    params: FileReputationParams, soar: SOARClient, asset: Asset
) -> list[SandboxReportOutput]:
    client = get_client(asset)

    if params.vault_id:
        endpoint = CROWDSTRIKE_QUERY_FILE_ENDPOINT
        attachments = soar.vault.get_attachment(vault_id=params.vault_id)
        if not attachments:
            raise ValueError("Vault file could not be found with supplied Vault ID")
        try:
            file_hash = attachments[0].metadata["sha256"]
        except Exception as e:
            raise ValueError(f"Vault ID not valid: {e}") from e
    elif params.sha256:
        endpoint = CROWDSTRIKE_QUERY_REPORT_ENDPOINT
        file_hash = params.sha256
    else:
        raise ValueError("No Vault ID or SHA256 was provided")

    filter_query = f"sandbox.sha256:'{file_hash}'"

    param_dict = build_param_dict(
        filter_query,
        params.limit,
        params.offset,
        params.sort,
        API_SORT_LIST,
        REPUTATION_SORT_LIST,
    )

    resource_id_list = client.paginator(endpoint, param_dict)

    if not resource_id_list:
        soar.set_message("No data found")
        return []

    reports = fetch_reports(client, resource_id_list, params.detail_report, params.sort)

    if not reports:
        soar.set_message("No data found")
        return []

    summary = report_summary(reports)
    soar.set_summary(summary)

    return [
        SandboxReportOutput(
            **report,
            _param_vault_id=params.vault_id,
            _param_sha256=params.sha256,
            _param_sort=params.sort,
            _param_offset=params.offset,
            _param_limit=params.limit,
            _param_detail_report=params.detail_report,
        )
        for report in reports
    ]
