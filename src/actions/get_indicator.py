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
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    CROWDSTRIKE_FILTER_GET_CUSTOM_IOC,
    CROWDSTRIKE_GET_COMBINED_CUSTOM_INDICATORS_ENDPOINT,
    CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
    CROWDSTRIKE_GET_RESOURCE_NOT_FOUND,
    CROWDSTRIKE_MISSING_INDICATOR_TYPE_MESSAGE_ERROR,
    CROWDSTRIKE_MISSING_INDICATOR_VALUE_MESSAGE_ERROR,
    CROWDSTRIKE_SUCC_GET_ALERT,
    CROWDSTRIKE_VALUE_LIST_MESSAGE_ERROR,
)


class GetIndicatorParams(Params):
    indicator_value: str = Param(
        description="The IOC value to fetch",
        required=False,
        primary=True,
        cef_types=["domain", "md5", "sha256", "ip", "ipv6"],
    )
    indicator_type: str = Param(
        description="The IOC type of the indicator value",
        required=False,
        value_list=["sha256", "md5", "domain", "ipv4", "ipv6"],
        cef_types=["crowdstrike indicator type"],
    )
    resource_id: str = Param(
        description="The resource ID of the IOC",
        required=False,
        cef_types=["crowdstrike indicator id"],
    )


class GetIndicatorMetadata(PermissiveActionOutput):
    av_hits: int | None = None
    company_name: str | None = None
    file_description: str | None = None
    file_version: str | None = None
    filename: str | None = None
    original_filename: str | None = None
    product_name: str | None = None
    product_version: str | None = None
    signed: bool | None = None


class GetIndicatorOutput(PermissiveActionOutput):
    action: str | None = OutputField(cef_types=["crowdstrike indicator action"])
    applied_globally: bool | None = None
    created_by: str | None = None
    created_on: str | None = OutputField(cef_types=["date"])
    created_timestamp: str | None = OutputField(cef_types=["date"])
    deleted: bool | None = None
    description: str | None = None
    expiration: str | None = OutputField(cef_types=["date"])
    expiration_timestamp: str | None = OutputField(cef_types=["date"])
    expired: bool | None = None
    from_parent: bool | None = None
    host_groups: list[str] | None = OutputField(cef_types=["crowdstrike host group id"])
    id: str | None = OutputField(cef_types=["crowdstrike indicator id"])
    metadata: GetIndicatorMetadata | None = None
    mobile_action: str | None = None
    modified_by: str | None = None
    modified_on: str | None = None
    modified_timestamp: str | None = OutputField(cef_types=["date"])
    platforms: list[str] | None = OutputField(
        cef_types=["crowdstrike indicator platforms"]
    )
    severity: str | None = OutputField(cef_types=["severity"])
    source: str | None = None
    tags: list[str] | None = None
    type: str | None = OutputField(cef_types=["crowdstrike indicator type"])
    value: str | None = OutputField(cef_types=["ip", "ipv6", "md5", "sha256", "domain"])


@app.view_handler(template="crowdstrike_get_indicator.html")
def get_indicator_view(outputs: list[GetIndicatorOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    name="get indicator",
    description="Get the details for an indicator",
    action_type="investigate",
    read_only=True,
    view_handler=get_indicator_view,
)
def get_indicator(
    params: GetIndicatorParams, soar: SOARClient, asset: Asset
) -> list[GetIndicatorOutput]:
    client = get_client(asset)

    ioc_type = params.indicator_type
    if ioc_type:
        ioc_type = ioc_type.lower()
        if ioc_type not in ["sha256", "md5", "domain", "ipv4", "ipv6"]:
            raise ValueError(
                CROWDSTRIKE_VALUE_LIST_MESSAGE_ERROR.format("indicator_type")
            )

    ioc = params.indicator_value
    resource_id = params.resource_id

    if not ioc_type and not ioc and not resource_id:
        raise ValueError("Please provide at least one of the parameter")

    if ioc_type and not ioc and not resource_id:
        raise ValueError(CROWDSTRIKE_MISSING_INDICATOR_VALUE_MESSAGE_ERROR)

    if ioc and not ioc_type and not resource_id:
        raise ValueError(CROWDSTRIKE_MISSING_INDICATOR_TYPE_MESSAGE_ERROR)

    not_found = False
    resources: list = []
    try:
        if resource_id:
            resp_json = client.make_rest_call(
                CROWDSTRIKE_GET_INDICATOR_ENDPOINT, params={"ids": resource_id}
            )
        else:
            resp_json = client.make_rest_call(
                CROWDSTRIKE_GET_COMBINED_CUSTOM_INDICATORS_ENDPOINT,
                params={
                    "filter": CROWDSTRIKE_FILTER_GET_CUSTOM_IOC.format(ioc_type, ioc)
                },
            )
        resources = resp_json.get("resources", [])
    except Exception as e:
        if "404" not in str(e):
            raise
        not_found = True

    outputs = [GetIndicatorOutput(**resource) for resource in resources]

    if not_found or not resources:
        soar.set_message(CROWDSTRIKE_GET_RESOURCE_NOT_FOUND)
    else:
        soar.set_message(CROWDSTRIKE_SUCC_GET_ALERT)

    return outputs
