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
    CROWDSTRIKE_GET_ZERO_TRUST_ASSESSMENT_ENDPOINT,
    CROWDSTRIKE_STATUS_CODE_CHECK_MESSAGE,
)


class GetZtaDataParams(Params):
    agent_id: str = Param(
        description="List of agent IDs. Comma separated list allowed",
        required=True,
        primary=True,
        cef_types=["crowdstrike device id"],
    )


class GetZtaDataOutput(PermissiveActionOutput):
    aid: str | None = OutputField(cef_types=["crowdstrike device id"])
    cid: str | None = OutputField(cef_types=["crowdstrike customer id"])
    event_platform: str | None = None
    sensor_file_status: str | None = None


@app.view_handler(template="crowdstrike_get_zta_data.html")
def get_zta_data_view(outputs: list[GetZtaDataOutput]) -> dict:
    return {"results": [{"data": [o.model_dump() for o in outputs]}]}


@app.action(
    description="Get Zero Trust Assessment data for one or more hosts by providing agent IDs (AID)",
    action_type="investigate",
    read_only=True,
    view_handler=get_zta_data_view,
)
def get_zta_data(
    params: GetZtaDataParams, soar: SOARClient, asset: Asset
) -> list[GetZtaDataOutput]:
    client = get_client(asset)

    agent_ids = [x.strip() for x in params.agent_id.split(",")]
    agent_ids = list(filter(None, agent_ids))

    resources = client.paginate_get_endpoint(
        agent_ids,
        CROWDSTRIKE_GET_ZERO_TRUST_ASSESSMENT_ENDPOINT,
        check_message=CROWDSTRIKE_STATUS_CODE_CHECK_MESSAGE,
    )

    if not resources:
        soar.set_message("No data found")
        return []

    outputs = [GetZtaDataOutput(**item) for item in resources]

    soar.set_message("Zero Trust Assessment data fetched successfully")
    return outputs
