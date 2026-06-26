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

import time

from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput

from ..consts import (
    CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT,
    CROWDSTRIKE_ENVIRONMENT_ID_DICT,
    CROWDSTRIKE_FALCONX_API_LIMIT,
    CROWDSTRIKE_GET_FULL_REPORT_ENDPOINT,
    CROWDSTRIKE_GET_REPORT_SUMMARY_ENDPOINT,
    CROWDSTRIKE_UPLOAD_FILE_ENDPOINT,
)
from ..helper import CrowdStrikeClient, validate_integer


ACTION_SCRIPT_LIST = [
    "default",
    "default_maxantievasion",
    "default_randomfiles",
    "default_randomtheme",
    "default_openie",
]


class SandboxReportOutput(PermissiveActionOutput):
    cid: str | None = None
    created_timestamp: str | None = OutputField(cef_types=["date"])
    id: str | None = OutputField(cef_types=["crowdstrike resource id"])
    ioc_report_broad_csv_artifact_id: str | None = OutputField(
        cef_types=["crowdstrike artifact id"]
    )
    ioc_report_broad_json_artifact_id: str | None = OutputField(
        cef_types=["crowdstrike artifact id"]
    )
    ioc_report_broad_maec_artifact_id: str | None = OutputField(
        cef_types=["crowdstrike artifact id"]
    )
    ioc_report_broad_stix_artifact_id: str | None = OutputField(
        cef_types=["crowdstrike artifact id"]
    )
    ioc_report_strict_csv_artifact_id: str | None = OutputField(
        cef_types=["crowdstrike artifact id"]
    )
    ioc_report_strict_json_artifact_id: str | None = OutputField(
        cef_types=["crowdstrike artifact id"]
    )
    ioc_report_strict_maec_artifact_id: str | None = OutputField(
        cef_types=["crowdstrike artifact id"]
    )
    ioc_report_strict_stix_artifact_id: str | None = OutputField(
        cef_types=["crowdstrike artifact id"]
    )
    origin: str | None = None
    user_id: str | None = None
    user_name: str | None = None
    user_uuid: str | None = None
    user_tags: str | None = None
    verdict: str | None = None


class SandboxReportSummary(ActionOutput):
    verdict: str | None = None
    total_reports: int | None = None


def validate_sort(sort: str | None) -> str | None:
    if sort is None:
        return None
    if sort == "--":
        raise ValueError("Please provide a valid value in the 'sort' parameter")
    return sort.lower()


def build_param_dict(
    filter_query: str,
    limit,
    offset,
    sort: str | None,
    api_sort_list: list[str],
    valid_sort_list: list[str] | None = None,
) -> dict:
    sort = validate_sort(sort)

    if sort and valid_sort_list is not None and sort not in valid_sort_list:
        raise ValueError("Please provide a valid value in the 'sort' parameter")

    param_dict: dict = {"filter": filter_query}
    if offset is not None:
        param_dict["offset"] = offset
    if limit is not None:
        clamped = validate_integer(limit, "limit")
        if clamped > CROWDSTRIKE_FALCONX_API_LIMIT:
            clamped = CROWDSTRIKE_FALCONX_API_LIMIT
        param_dict["limit"] = clamped
    if sort is not None and sort in api_sort_list:
        param_dict["sort"] = sort
    return param_dict


def validate_environment(environment: str) -> int:
    environment_id = environment.lower()
    if environment_id not in CROWDSTRIKE_ENVIRONMENT_ID_DICT:
        raise ValueError("Please provide a valid environment")
    return CROWDSTRIKE_ENVIRONMENT_ID_DICT[environment_id]


def _sort_key_verdict(report: dict):
    return report.get("verdict", "")


def _sort_key_created(report: dict):
    return report.get("created_timestamp", "")


def _sort_key_environment(report: dict):
    return report["sandbox"][0]["environment_description"]


def _sort_key_threat(report: dict):
    return report["sandbox"][0].get("threat_score", 0)


_SORT_KEYS = {
    "verdict": _sort_key_verdict,
    "created_timestamp": _sort_key_created,
    "environment_description": _sort_key_environment,
    "threat_score": _sort_key_threat,
}


def _sort_reports(reports: list, sort: str | None) -> list:
    sort = validate_sort(sort)
    if not sort or "." not in sort:
        return reports
    criteria, ordering = sort.split(".")
    key_fn = _SORT_KEYS.get(criteria)
    if key_fn is None:
        return reports
    try:
        return sorted(reports, key=key_fn, reverse=(ordering == "desc"))
    except Exception as e:
        raise ValueError(f"Error occurred while sorting the response : {e}") from e


def fetch_reports(
    client: CrowdStrikeClient,
    resource_id_list: list,
    detail_report: bool,
    sort: str | None,
) -> list:
    endpoint = (
        CROWDSTRIKE_GET_FULL_REPORT_ENDPOINT
        if detail_report
        else CROWDSTRIKE_GET_REPORT_SUMMARY_ENDPOINT
    )

    id_list = list(resource_id_list)
    reports: list = []
    while id_list:
        ids = id_list[: min(100, len(id_list))]
        response = client.make_rest_call(endpoint, params={"ids": ids})
        if response.get("resources"):
            reports.extend(response["resources"])
        del id_list[: min(100, len(id_list))]

    return _sort_reports(reports, sort)


def report_summary(reports: list) -> SandboxReportSummary:
    if len(reports) == 1 and "verdict" in reports[0]:
        return SandboxReportSummary(
            verdict=reports[0]["verdict"], total_reports=len(reports)
        )
    return SandboxReportSummary(total_reports=len(reports))


def _build_detonation_payload(
    environment_id: int,
    enable_tor: bool,
    sha256: str | None,
    url: str | None,
    action_script: str | None,
    command_line: str | None,
    document_password: str | None,
    submit_name: str | None,
    user_tags: str | None,
) -> dict:
    sandbox: dict = {"environment_id": environment_id, "enable_tor": enable_tor}
    if sha256 is not None:
        sandbox["sha256"] = sha256
    if url is not None:
        sandbox["url"] = url
    if action_script is not None:
        sandbox["action_script"] = action_script
    if command_line is not None:
        sandbox["command_line"] = command_line
    if document_password is not None:
        sandbox["document_password"] = document_password
    if submit_name is not None:
        sandbox["submit_name"] = submit_name

    payload: dict = {"sandbox": [sandbox]}

    if user_tags is not None:
        tag_list = [x.strip() for x in user_tags.split(",")]
        tag_list = list(filter(None, tag_list))
        if tag_list:
            payload["user_tags"] = tag_list

    return payload


def submit_for_detonation(
    client: CrowdStrikeClient,
    environment: str,
    enable_tor: bool,
    sha256: str | None = None,
    url: str | None = None,
    action_script: str | None = None,
    command_line: str | None = None,
    document_password: str | None = None,
    submit_name: str | None = None,
    user_tags: str | None = None,
) -> str:
    environment_id = validate_environment(environment)

    if action_script is not None:
        action_script = action_script.lower()
        if action_script not in ACTION_SCRIPT_LIST:
            raise ValueError("Please provide a valid action script")

    payload = _build_detonation_payload(
        environment_id,
        enable_tor,
        sha256,
        url,
        action_script,
        command_line,
        document_password,
        submit_name,
        user_tags,
    )

    response = client.make_rest_call(
        CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT, json_data=payload, method="post"
    )

    try:
        return response["resources"][0]["id"]
    except Exception as e:
        raise ValueError(f"Error occurred while fetching the resource id : {e}") from e


def upload_sample(
    client: CrowdStrikeClient,
    file_path: str,
    file_name: str,
    is_confidential: bool,
    comment: str | None,
) -> str:
    with open(file_path, "rb") as f:
        data = f.read()

    query_param = {
        "file_name": file_name,
        "is_confidential": is_confidential,
        "comment": comment,
    }
    headers = {"Content-Type": "application/octet-stream"}

    response = client.make_rest_call(
        CROWDSTRIKE_UPLOAD_FILE_ENDPOINT,
        params=query_param,
        headers=headers,
        data=data,
        method="post",
    )

    try:
        return response["resources"][0]["sha256"]
    except Exception as e:
        raise ValueError("Error occurred while fetching sha256 for the file") from e


def poll_for_detonation(
    client: CrowdStrikeClient, resource_id: str, poll_interval: int
) -> tuple[list, str | None]:
    counter = 0
    prev_resources: list = []
    while counter < poll_interval:
        response = client.make_rest_call(
            CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT, params={"ids": resource_id}
        )
        resources = response.get("resources") or []
        prev_resources = resources

        if resources and resources[0].get("state") == "success":
            return [], "success"

        if resources and resources[0].get("state") not in ("success", "running"):
            raise ValueError(
                f"Analysis of the report failed for resource id : {resource_id}"
            )

        counter += 1
        time.sleep(60)

    return prev_resources, "timeout"


def build_report_view(outputs: list, action_name: str, param_keys: list[str]) -> dict:
    results = []
    for output in outputs:
        dumped = output.model_dump(exclude_none=True)
        param = {key: dumped.pop(f"_param_{key}", None) for key in param_keys}
        param = {k: v for k, v in param.items() if v is not None}
        ctx: dict = {
            "check_param": len(param) > 0,
            "param": param,
            "action_name": action_name,
            "data": [dumped] if dumped else [],
        }
        results.append(ctx)
    return {"results": results}
