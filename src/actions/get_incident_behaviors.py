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
from ..consts import CROWDSTRIKE_GET_INCIDENT_BEHAVIORS_ID_ENDPOINT


class GetIncidentBehaviorsParams(Params):
    ids: str = Param(
        description="List of behavior IDs. Comma separated list allowed",
        required=True,
        primary=True,
        cef_types=["crowdstrike incidentbehavior id"],
    )


class GetIncidentBehaviorsOutput(PermissiveActionOutput):
    behavior_id: str | None = OutputField(
        cef_types=["crowdstrike incidentbehavior id"], column_name="ID"
    )
    tactic: str | None = OutputField(column_name="Tactic")
    technique: str | None = OutputField(column_name="Technique")
    objective: str | None = OutputField(column_name="Objective")
    timestamp: str | None = OutputField(column_name="Timestamp")
    cmdline: str | None = OutputField(column_name="Command Line")
    filepath: str | None = OutputField(column_name="File Path")


@app.action(
    description="Queries CrowdStrike for the details of behaviors of an incident",
    action_type="investigate",
    read_only=True,
    render_as="table",
)
def get_incident_behaviors(
    params: GetIncidentBehaviorsParams, soar: SOARClient, asset: Asset
) -> list[GetIncidentBehaviorsOutput]:
    client = get_client(asset)

    ids = [x.strip() for x in params.ids.split(",")]
    ids = list(filter(None, ids))

    details_list = client.get_details(
        ids, CROWDSTRIKE_GET_INCIDENT_BEHAVIORS_ID_ENDPOINT
    )

    outputs = [GetIncidentBehaviorsOutput(**behavior) for behavior in details_list]

    soar.set_message("Incident behavior fetched successfully")
    return outputs
