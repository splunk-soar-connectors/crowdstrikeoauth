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
from ..consts import CROWDSTRIKE_QUERY_REPORT_ENDPOINT
from ..helper import validate_integer
from ._sandbox_common import (
    ACTION_SCRIPT_LIST,
    SandboxReportOutput,
    SandboxReportSummary,
    build_param_dict,
    build_report_view,
    fetch_reports,
    poll_for_detonation,
    report_summary,
    submit_for_detonation,
    validate_environment,
)


DETONATE_SORT_LIST = [
    "verdict.asc",
    "verdict.desc",
    "created_timestamp.asc",
    "created_timestamp.desc",
    "threat_score.asc",
    "threat_score.desc",
]
API_SORT_LIST = [
    "verdict.desc",
    "verdict.asc",
    "created_timestamp.asc",
    "created_timestamp.desc",
]

ENVIRONMENT_LIST = [
    "Linux Ubuntu 16.04, 64-bit",
    "Android (static analysis)",
    "Windows 10, 64-bit",
    "Windows 7, 64-bit",
    "Windows 7, 32-bit",
]

PARAM_KEYS = ["url", "environment", "sort", "offset", "limit", "detail_report"]


def _defang_url(url: str) -> str:
    if "https://" in url:
        return url.replace("https://", "hxxps://")
    if "http://" in url:
        return url.replace("http://", "hxxp://")
    if "ftp://" in url:
        return url.replace("ftp://", "fxp://")
    return url


class DetonateUrlParams(Params):
    url: str = Param(
        description="URL to detonate",
        required=True,
        primary=True,
        cef_types=["url"],
    )
    environment: str = Param(
        description="Sandbox environment to use for analysis",
        required=True,
        primary=True,
        value_list=ENVIRONMENT_LIST,
        cef_types=["crowdstrike environment"],
    )
    limit: int = Param(
        description="Maximum reports to be fetched",
        required=False,
        default=50,
    )
    offset: int = Param(
        description="Starting index of overall result set",
        required=False,
        default=0,
    )
    document_password: str = Param(
        description="Auto-filled password for Adobe or Office files",
        required=False,
        sensitive=True,
    )
    command_line: str = Param(
        description="Command line script passed to the submitted file at runtime",
        required=False,
    )
    user_tags: str = Param(
        description="Comma-separated list of tags to categorize the submission",
        required=False,
    )
    sort: str = Param(
        description="Property to sort by",
        required=False,
        value_list=DETONATE_SORT_LIST,
    )
    action_script: str = Param(
        description="Runtime script for sandbox analysis",
        required=False,
        value_list=ACTION_SCRIPT_LIST,
    )
    detail_report: bool = Param(
        description="Provide a detailed report of the URL",
        required=False,
        default=False,
    )
    enable_tor: bool = Param(
        description="Route the analysis through the TOR network",
        required=False,
        default=False,
    )


@app.view_handler(template="crowdstrike_detonate_url.html")
def detonate_url_view(outputs: list[SandboxReportOutput]) -> dict:
    return build_report_view(outputs, "detonate url", PARAM_KEYS)


def _make_outputs(
    reports: list, params: DetonateUrlParams
) -> list[SandboxReportOutput]:
    return [
        SandboxReportOutput(
            **report,
            _param_url=params.url,
            _param_environment=params.environment,
            _param_sort=params.sort,
            _param_offset=params.offset,
            _param_limit=params.limit,
            _param_detail_report=params.detail_report,
        )
        for report in reports
    ]


@app.action(
    name="detonate url",
    description="Detonate a URL in the CrowdStrike sandbox",
    action_type="generic",
    read_only=False,
    view_handler=detonate_url_view,
    summary_type=SandboxReportSummary,
)
def detonate_url(
    params: DetonateUrlParams, soar: SOARClient, asset: Asset
) -> list[SandboxReportOutput]:
    client = get_client(asset)

    environment_id = validate_environment(params.environment)

    url = _defang_url(params.url)
    filter_query = (
        f"sandbox.submit_url.raw:'{url}'+sandbox.environment_id:'{environment_id}'"
    )

    param_dict = build_param_dict(
        filter_query,
        params.limit,
        params.offset,
        params.sort,
        API_SORT_LIST,
        DETONATE_SORT_LIST,
    )

    resource_id_list = client.paginator(CROWDSTRIKE_QUERY_REPORT_ENDPOINT, param_dict)

    if not resource_id_list and client._required_detonation:
        resource_id = submit_for_detonation(
            client,
            params.environment,
            params.enable_tor,
            url=params.url,
            action_script=params.action_script,
            command_line=params.command_line,
            document_password=params.document_password,
            user_tags=params.user_tags,
        )

        poll_interval = validate_integer(asset.detonate_timeout, "detonate_timeout")
        prev_resources, status = poll_for_detonation(client, resource_id, poll_interval)

        if status == "success":
            reports = fetch_reports(client, [resource_id], params.detail_report, None)
            if reports:
                soar.set_summary(report_summary(reports))
            return _make_outputs(reports, params)

        soar.set_message(
            f"Timed out while waiting for the result. To know the status of submitted "
            f"sample please run the check status action with {resource_id} resource id."
        )
        return _make_outputs(prev_resources, params)

    if not resource_id_list:
        soar.set_message("No data found")
        return []

    reports = fetch_reports(client, resource_id_list, params.detail_report, params.sort)

    if not reports:
        soar.set_message("No data found")
        return []

    soar.set_summary(report_summary(reports))
    return _make_outputs(reports, params)
