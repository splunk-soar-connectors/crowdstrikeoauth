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


class UnquarantineDeviceParams(Params):
    device_id: str = Param(
        description="Comma-separated list of device IDs",
        required=False,
        primary=True,
        cef_types=["crowdstrike device id"],
    )
    hostname: str = Param(
        description="Comma-separated list of hostnames",
        required=False,
        primary=True,
        cef_types=["host name"],
    )
    cid: str = Param(
        description=(
            "A single, specific tenant id to search. By default, will search asset main "
            "tenant and all listed subtenants; to search only main tenant (even if you have "
            "subtenants) use 'main'"
        ),
        required=False,
    )


class UnquarantineDeviceOutput(ActionOutput):
    id: str = OutputField(cef_types=["crowdstrike device id"])
    path: str = OutputField()


class UnquarantineDeviceSummary(ActionOutput):
    total_unquarantined_device: int


@app.action(
    description=(
        "This action lifts containment on the host, which returns its network "
        "communications to normal."
    ),
    action_type="correct",
    read_only=False,
)
def unquarantine_device(
    params: UnquarantineDeviceParams, soar: SOARClient, asset: Asset
) -> list[UnquarantineDeviceOutput]:
    client = get_client(asset)

    device_params = {
        k: v
        for k, v in {
            "device_id": params.device_id,
            "hostname": params.hostname,
            "cid": params.cid,
        }.items()
        if v
    }
    device_params["action_name"] = "lift_containment"

    results = client.perform_device_action(device_params)
    outputs = [
        UnquarantineDeviceOutput(id=d.get("id"), path=d.get("path")) for d in results
    ]

    soar.set_summary(UnquarantineDeviceSummary(total_unquarantined_device=len(outputs)))
    soar.set_message("Device unquarantined successfully")
    return outputs
