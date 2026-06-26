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
from ..consts import CROWDSTRIKE_GET_INCIDENT_DETAILS_ID_ENDPOINT


class GetIncidentDetailsParams(Params):
    ids: str = Param(
        description="List of incident IDs. Comma separated list allowed",
        required=True,
        primary=True,
        cef_types=["crowdstrike incident id"],
    )


class GetIncidentDetailsHost(PermissiveActionOutput):
    hostname: str | None = OutputField(column_name="Host Name")
    device_id: str | None = OutputField(
        cef_types=["crowdstrike device id"], column_name="Host ID"
    )


class GetIncidentDetailsOutput(PermissiveActionOutput):
    incident_id: str | None = OutputField(
        cef_types=["crowdstrike incident id"], column_name="Incident ID"
    )
    name: str | None = OutputField(column_name="Name")
    description: str | None = OutputField(column_name="Description")
    start: str | None = OutputField(column_name="Start")
    state: str | None = OutputField(column_name="State")
    hosts: list[GetIncidentDetailsHost] | None = None


class GetIncidentDetailsSummary(ActionOutput):
    total_incidents: int


@app.action(
    description="Queries CrowdStrike for the details of incidents",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=GetIncidentDetailsSummary,
)
def get_incident_details(
    params: GetIncidentDetailsParams, soar: SOARClient, asset: Asset
) -> list[GetIncidentDetailsOutput]:
    client = get_client(asset)

    ids = [x.strip() for x in params.ids.split(",")]
    ids = list(filter(None, ids))

    details_list = client.get_details(ids, CROWDSTRIKE_GET_INCIDENT_DETAILS_ID_ENDPOINT)

    outputs = [GetIncidentDetailsOutput(**incident) for incident in details_list]

    soar.set_summary(GetIncidentDetailsSummary(total_incidents=len(outputs)))
    soar.set_message(f"Incidents fetched: {len(details_list)}")
    return outputs
