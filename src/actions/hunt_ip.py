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
from ..consts import CROWDSTRIKE_GET_DEVICES_RAN_ON_APIPATH
from ..helper import get_ioc_type, validate_integer


class HuntIpParams(Params):
    ip: str = Param(
        description="IP to hunt",
        required=True,
        primary=True,
        cef_types=["ip", "ipv6"],
    )
    count_only: bool = Param(
        description="Returns count of the devices the IOC ran on",
        required=False,
        default=False,
    )
    limit: int = Param(
        description="Maximum devices to be fetched",
        required=False,
        default=100,
    )


class HuntIpOutput(PermissiveActionOutput):
    device_id: str | None = OutputField(
        cef_types=["crowdstrike device id"], column_name="Crowdstrike Device ID"
    )


class HuntIpSummary(ActionOutput):
    device_count: int


@app.view_handler(template="crowdstrike_hunt_view.html")
def hunt_ip_view(outputs: list[HuntIpOutput]) -> dict:
    data = [o.model_dump() for o in outputs]
    param = {}
    if data:
        param = {
            "ioc": data[0].pop("ioc", None),
            "ioc_type": data[0].pop("ioc_type", None),
        }
        for item in data[1:]:
            item.pop("ioc", None)
            item.pop("ioc_type", None)
    return {
        "results": [
            {"data": data, "param": param, "summary": {"device_count": len(data)}}
        ]
    }


@app.action(
    description="Hunt for an IP across all hosts in the environment",
    action_type="investigate",
    read_only=True,
    view_handler=hunt_ip_view,
    summary_type=HuntIpSummary,
)
def hunt_ip(params: HuntIpParams, soar: SOARClient, asset: Asset) -> list[HuntIpOutput]:
    client = get_client(asset)

    ioc_type = get_ioc_type(params.ip)

    limit = validate_integer(params.limit, "limit")

    api_data = {"type": ioc_type, "value": params.ip, "limit": limit}

    response = client.hunt_paginator(
        CROWDSTRIKE_GET_DEVICES_RAN_ON_APIPATH,
        params=api_data,
        search_subtenants=True,
    )

    device_count = len(response)
    soar.set_summary(HuntIpSummary(device_count=device_count))

    if params.count_only:
        soar.set_message(f"Device count: {device_count}")
        return []

    soar.set_message(f"Device count: {device_count}")
    return [
        HuntIpOutput(device_id=device_id, ioc=params.ip, ioc_type=ioc_type)
        for device_id in response
    ]
