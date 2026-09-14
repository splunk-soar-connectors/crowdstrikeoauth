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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_GET_PROCESSES_RAN_ON_APIPATH
from ..helper import get_ioc_type, validate_integer


class ListProcessesParams(Params):
    ioc: str = Param(
        description="IOC to get the processes of",
        required=True,
        primary=True,
        cef_types=["hash", "sha256", "sha1", "md5", "domain"],
    )
    id: str = Param(
        description="Device ID to get the processes ran on",
        required=True,
        primary=True,
        cef_types=["crowdstrike device id"],
    )
    limit: int = Param(
        description="Maximum processes to be fetched",
        required=False,
        default=100,
    )


class ListProcessesOutput(PermissiveActionOutput):
    falcon_process_id: str | None = OutputField(
        cef_types=["falcon process id"], column_name="Falcon Process ID"
    )
    device_id: str | None = None
    ioc: str | None = None
    ioc_type: str | None = None
    limit: int | None = None
    summary_process_count: int | None = None
    summary_total_process_count: int | None = None
    summary_truncated: bool | None = None


class ListProcessesSummary(ActionOutput):
    process_count: int
    total_process_count: int | None = None
    truncated: bool


def _build_process_summary(client, process_count: int) -> ListProcessesSummary:
    total = (
        client._last_hunt_total
        if getattr(client, "_last_hunt_total_known", False)
        else None
    )
    truncated = bool(getattr(client, "_last_hunt_truncated", False)) or (
        total is not None and process_count < total
    )
    return ListProcessesSummary(
        process_count=process_count,
        total_process_count=total,
        truncated=truncated,
    )


@app.view_handler(template="crowdstrike_process_list_view.html")
def list_processes_view(outputs: list[ListProcessesOutput]) -> dict:
    data = [o.model_dump() for o in outputs]
    param = {}
    summary = {"process_count": len(data)}
    if outputs:
        first = outputs[0]
        param = {
            "id": first.device_id,
            "ioc": first.ioc,
            "ioc_type": first.ioc_type,
            "limit": first.limit,
        }
        summary = {
            "process_count": first.summary_process_count,
            "total_process_count": first.summary_total_process_count,
            "truncated": first.summary_truncated,
        }
        for row in data:
            row.pop("summary_process_count", None)
            row.pop("summary_total_process_count", None)
            row.pop("summary_truncated", None)
    return {
        "results": [
            {
                "data": data,
                "param": param,
                "summary": summary,
            }
        ]
    }


@app.action(
    description="Lists the processes a specified IOC ran on for a specific device",
    action_type="investigate",
    read_only=True,
    view_handler=list_processes_view,
    summary_type=ListProcessesSummary,
)
def list_processes(
    params: ListProcessesParams, soar: SOARClient, asset: Asset
) -> list[ListProcessesOutput]:
    client = get_client(asset)

    ioc_type = get_ioc_type(params.ioc)

    limit = validate_integer(params.limit, "limit")

    api_data = {
        "type": ioc_type,
        "value": params.ioc,
        "device_id": params.id,
        "limit": limit,
    }

    response = client.hunt_paginator(CROWDSTRIKE_GET_PROCESSES_RAN_ON_APIPATH, api_data)

    if not response:
        soar.set_summary(_build_process_summary(client, 0))
        soar.set_message(
            "No resources found from the response for the list processes action"
        )
        return []

    summary = _build_process_summary(client, len(response))
    outputs = [
        ListProcessesOutput(
            falcon_process_id=process_id,
            device_id=params.id,
            ioc=params.ioc,
            ioc_type=ioc_type,
            limit=limit,
            summary_process_count=summary.process_count,
            summary_total_process_count=summary.total_process_count,
            summary_truncated=summary.truncated,
        )
        for process_id in response
    ]

    soar.set_summary(summary)
    if summary.total_process_count is None:
        soar.set_message(
            f"Process count: {len(response)}; provider total unavailable; "
            f"truncated: {summary.truncated}"
        )
    else:
        soar.set_message(
            f"Process count: {len(response)} of {summary.total_process_count}; "
            f"truncated: {summary.truncated}"
        )
    return outputs
