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
from soar_sdk.action_results import PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    CROWDSTRIKE_DELETE_RESOURCE_NOT_FOUND,
    CROWDSTRIKE_FILTER_GET_IOC,
    CROWDSTRIKE_GET_CUSTOM_INDICATORS_ENDPOINT,
    CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
    CROWDSTRIKE_MISSING_PARAMETER_MESSAGE_DELETE_IOC_ERROR,
    CROWDSTRIKE_SUCC_DELETE_ALERT,
)
from ..helper import get_ioc_type


class DeleteIocsParams(Params):
    ioc: str = Param(
        description="The IOC to delete",
        required=False,
        primary=True,
        cef_types=["ip", "ipv6", "md5", "sha256", "domain"],
    )
    resource_id: str = Param(
        description="The resource ID of the IOC to delete",
        required=False,
        cef_types=["crowdstrike indicator id"],
    )


class DeleteIocsOutput(PermissiveActionOutput):
    ioc: str | None = None
    resource_id: str | None = None


@app.view_handler(template="crowdstrike_delete_indicator.html")
def delete_iocs_view(outputs: list[DeleteIocsOutput]) -> dict:
    results = []
    for output in outputs:
        results.append({"param": output.model_dump()})
    return {"results": results}


@app.action(
    name="delete indicator",
    description="Delete an IOC",
    action_type="correct",
    read_only=False,
    view_handler=delete_iocs_view,
)
def delete_iocs(
    params: DeleteIocsParams, soar: SOARClient, asset: Asset
) -> list[DeleteIocsOutput]:
    client = get_client(asset)

    ioc = params.ioc
    resource_id = params.resource_id

    if not ioc and not resource_id:
        raise ValueError(CROWDSTRIKE_MISSING_PARAMETER_MESSAGE_DELETE_IOC_ERROR)

    output = DeleteIocsOutput(ioc=ioc, resource_id=resource_id)

    if resource_id:
        client.make_rest_call(
            CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
            params={"ids": resource_id},
            method="delete",
        )
        soar.set_message(CROWDSTRIKE_SUCC_DELETE_ALERT)
        return [output]

    ioc_type = get_ioc_type(ioc)
    response = client.make_rest_call(
        CROWDSTRIKE_GET_CUSTOM_INDICATORS_ENDPOINT,
        params={"filter": CROWDSTRIKE_FILTER_GET_IOC.format(ioc_type, ioc)},
    )

    resources = response.get("resources")
    if not resources:
        raise ValueError(CROWDSTRIKE_DELETE_RESOURCE_NOT_FOUND)

    client.make_rest_call(
        CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
        params={"ids": resources[0]},
        method="delete",
    )

    soar.set_message(CROWDSTRIKE_SUCC_DELETE_ALERT)
    return [output]
