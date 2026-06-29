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
from ..consts import CROWDSTRIKE_GET_DEVICE_SCROLL_ENDPOINT


class GetDeviceScrollParams(Params):
    offset: str = Param(
        description="The offset to page from, for the next result set",
        required=False,
    )
    limit: int = Param(
        description="The maximum records to return. [1-5000]",
        required=False,
    )
    sort: str = Param(
        description="The property to sort by (e.g. status.desc or hostname.asc)",
        required=False,
    )
    filter: str = Param(
        description="The filter expression that should be used to limit the results (FQL syntax)",
        required=False,
    )


class GetDeviceScrollPagination(PermissiveActionOutput):
    expires_at: int | None = None
    limit: str | None = None
    offset: str | None = None
    total: int | None = None


class GetDeviceScrollMeta(PermissiveActionOutput):
    pagination: GetDeviceScrollPagination | None = None
    powered_by: str | None = None
    query_time: float | None = None
    trace_id: str | None = None


class GetDeviceScrollOutput(PermissiveActionOutput):
    resources: list[str] | None = OutputField(cef_types=["crowdstrike device id"])
    meta: GetDeviceScrollMeta | None = None
    param_offset: str | None = None
    param_limit: int | None = None
    param_sort: str | None = None
    param_filter: str | None = None


@app.view_handler(template="crowdstrike_get_device_scroll.html")
def get_device_scroll_view(outputs: list[GetDeviceScrollOutput]) -> dict:
    data = [o.model_dump() for o in outputs]
    param = {}
    if outputs:
        first = outputs[0]
        param = {
            "offset": first.param_offset,
            "limit": first.param_limit,
            "sort": first.param_sort,
            "filter": first.param_filter,
        }
    check_param = any(param.values())
    return {"results": [{"data": data, "param": param, "check_param": check_param}]}


@app.action(
    description="Get a list of device IDs using pagination",
    action_type="investigate",
    read_only=True,
    view_handler=get_device_scroll_view,
)
def get_device_scroll(
    params: GetDeviceScrollParams, soar: SOARClient, asset: Asset
) -> list[GetDeviceScrollOutput]:
    client = get_client(asset)

    query_params: dict = {
        k: v
        for k, v in {
            "offset": params.offset,
            "limit": params.limit,
            "sort": params.sort,
            "filter": params.filter,
        }.items()
        if v is not None
    }

    response = client.make_rest_call(
        CROWDSTRIKE_GET_DEVICE_SCROLL_ENDPOINT, params=query_params
    )

    soar.set_message("Device scroll fetched successfully")
    return [
        GetDeviceScrollOutput(
            **response,
            param_offset=params.offset,
            param_limit=params.limit,
            param_sort=params.sort,
            param_filter=params.filter,
        )
    ]
