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
from ..helper import validate_integer


class HuntDomainParams(Params):
    domain: str = Param(
        description="Domain to hunt",
        required=True,
        primary=True,
        cef_types=["domain"],
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


class HuntDomainOutput(PermissiveActionOutput):
    device_id: str | None = OutputField(
        cef_types=["crowdstrike device id"], column_name="Crowdstrike Device ID"
    )


class HuntDomainSummary(ActionOutput):
    device_count: int


@app.view_handler(template="crowdstrike_hunt_view.html")
def hunt_domain_view(outputs: list[HuntDomainOutput]) -> dict:
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
    description="Hunt for a domain across all hosts in the environment",
    action_type="investigate",
    read_only=True,
    view_handler=hunt_domain_view,
    summary_type=HuntDomainSummary,
)
def hunt_domain(
    params: HuntDomainParams, soar: SOARClient, asset: Asset
) -> list[HuntDomainOutput]:
    client = get_client(asset)

    limit = validate_integer(params.limit, "limit")

    api_data = {"type": "domain", "value": params.domain, "limit": limit}

    response = client.hunt_paginator(
        CROWDSTRIKE_GET_DEVICES_RAN_ON_APIPATH,
        params=api_data,
        search_subtenants=True,
    )

    device_count = len(response)
    soar.set_summary(HuntDomainSummary(device_count=device_count))

    if params.count_only:
        soar.set_message(f"Device count: {device_count}")
        return []

    soar.set_message(f"Device count: {device_count}")
    return [
        HuntDomainOutput(device_id=device_id, ioc=params.domain, ioc_type="domain")
        for device_id in response
    ]
