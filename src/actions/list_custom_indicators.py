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
from ..consts import (
    CROWDSTRIKE_GET_COMBINED_CUSTOM_INDICATORS_ENDPOINT,
    CROWDSTRIKE_IOCS_ACTION,
    CROWDSTRIKE_SEARCH_IOCS_TYPE,
    CROWDSTRIKE_SORT_CRITERIA_LIST,
    CROWDSTRIKE_SORT_FOR_CRITERIA_IOC_DICT,
    CROWDSTRIKE_VALUE_LIST_MESSAGE_ERROR,
)
from ..helper import validate_integer


class ListCustomIndicatorsParams(Params):
    indicator_value: str = Param(
        description="The IOC value to filter on",
        required=False,
        cef_types=["ip", "ipv6", "md5", "sha256", "domain"],
    )
    indicator_type: str = Param(
        description="The IOC type to filter on",
        required=False,
        value_list=["all", "hash", "ipv4", "ipv6", "md5", "sha256", "domain"],
        cef_types=["crowdstrike indicator type"],
    )
    action: str = Param(
        description="The action to filter on",
        required=False,
        value_list=["no_action", "allow", "prevent_no_ui", "prevent", "detect"],
        cef_types=["crowdstrike indicator action"],
    )
    source: str = Param(description="The source to filter on", required=False)
    from_expiration: str = Param(
        description="Filter by expiration date greater than or equal to this value",
        required=False,
        cef_types=["date"],
    )
    to_expiration: str = Param(
        description="Filter by expiration date less than or equal to this value",
        required=False,
        cef_types=["date"],
    )
    limit: int = Param(
        description="Maximum indicators to be fetched",
        required=False,
        default=100,
    )
    sort: str = Param(
        description="Property to sort by",
        required=False,
        value_list=CROWDSTRIKE_SORT_CRITERIA_LIST,
    )


class ListCustomIndicatorsMetadata(PermissiveActionOutput):
    av_hits: int | None = None
    company_name: str | None = None
    file_description: str | None = None
    file_version: str | None = None
    filename: str | None = None
    original_filename: str | None = None
    product_name: str | None = None
    product_version: str | None = None
    signed: bool | None = None


class ListCustomIndicatorsEntry(PermissiveActionOutput):
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
    metadata: ListCustomIndicatorsMetadata | None = None
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
    value: str | None = None


class ListCustomIndicatorsOutput(PermissiveActionOutput):
    domain: list[ListCustomIndicatorsEntry] | None = None
    ipv4: list[ListCustomIndicatorsEntry] | None = None
    ipv6: list[ListCustomIndicatorsEntry] | None = None
    md5: list[ListCustomIndicatorsEntry] | None = None
    sha256: list[ListCustomIndicatorsEntry] | None = None


class ListCustomIndicatorsSummary(ActionOutput):
    alerts_found: int | None = None
    total_domain: int | None = None
    total_ipv4: int | None = None
    total_ipv6: int | None = None
    total_md5: int | None = None
    total_sha256: int | None = None


@app.view_handler(template="crowdstrike_list_custom_indicators.html")
def list_custom_indicators_view(outputs: list[ListCustomIndicatorsOutput]) -> dict:
    results = []
    for output in outputs:
        data = output.model_dump(exclude_none=True)
        summary = {
            "alerts_found": sum(len(v) for v in data.values()),
            "total_domain": len(data.get("domain", [])),
            "total_ipv4": len(data.get("ipv4", [])),
            "total_ipv6": len(data.get("ipv6", [])),
            "total_md5": len(data.get("md5", [])),
            "total_sha256": len(data.get("sha256", [])),
        }
        results.append({"data": [data], "summary": summary})
    return {"results": results}


def _create_query(params: ListCustomIndicatorsParams) -> str:
    filter_query = ""
    if params.indicator_value:
        filter_query = f"value:'{params.indicator_value}'"
    if params.action:
        ioc_action = params.action.lower()
        filter_query = (
            f"{filter_query}+action:'{ioc_action}'"
            if filter_query
            else f"action:'{ioc_action}'"
        )
    if params.from_expiration:
        clause = f"expiration:>='{params.from_expiration}'"
        filter_query = f"{filter_query}+{clause}" if filter_query else clause
    if params.to_expiration:
        clause = f"expiration:<='{params.to_expiration}'"
        filter_query = f"{filter_query}+{clause}" if filter_query else clause
    if params.source:
        clause = f"source:'{params.source}'"
        filter_query = f"{filter_query}+{clause}" if filter_query else clause
    if params.indicator_type and params.indicator_type.lower() != "all":
        search_ioc_type = params.indicator_type.lower()
        if search_ioc_type == "hash":
            clause = "type:{}".format(["md5", "sha256"])
        else:
            clause = f"type:'{search_ioc_type}'"
        filter_query = f"{filter_query}+{clause}" if filter_query else clause
    return filter_query


def _sort_entries(sort_criteria: str, value: list) -> list:
    criteria, ordering = sort_criteria.split(".")
    key = CROWDSTRIKE_SORT_FOR_CRITERIA_IOC_DICT[criteria]
    return sorted(value, key=lambda x: x[key], reverse=(ordering == "desc"))


@app.action(
    name="list custom indicators",
    description="List the custom indicators",
    action_type="investigate",
    read_only=True,
    view_handler=list_custom_indicators_view,
    summary_type=ListCustomIndicatorsSummary,
)
def list_custom_indicators(
    params: ListCustomIndicatorsParams, soar: SOARClient, asset: Asset
) -> list[ListCustomIndicatorsOutput]:
    client = get_client(asset)

    indicator_limit = validate_integer(params.limit, "limit")

    sort_criteria = params.sort
    if sort_criteria:
        sort_criteria = sort_criteria.lower()
        if sort_criteria not in CROWDSTRIKE_SORT_CRITERIA_LIST:
            raise ValueError(CROWDSTRIKE_VALUE_LIST_MESSAGE_ERROR.format("sort"))

    if params.action and params.action.lower() not in [
        "no_action",
        "allow",
        "prevent_no_ui",
        "prevent",
        "detect",
    ]:
        raise ValueError(
            CROWDSTRIKE_VALUE_LIST_MESSAGE_ERROR.format(CROWDSTRIKE_IOCS_ACTION)
        )

    if params.indicator_type and params.indicator_type.lower() not in [
        "all",
        "hash",
        "ipv4",
        "ipv6",
        "md5",
        "sha256",
        "domain",
    ]:
        raise ValueError(
            CROWDSTRIKE_VALUE_LIST_MESSAGE_ERROR.format(CROWDSTRIKE_SEARCH_IOCS_TYPE)
        )

    api_data: dict = {"limit": 2000}
    filter_query = _create_query(params)
    if filter_query:
        api_data["filter"] = filter_query

    ioc_infos: list = []
    while True:
        response = client.make_rest_call(
            CROWDSTRIKE_GET_COMBINED_CUSTOM_INDICATORS_ENDPOINT, params=api_data
        )

        if response.get("errors"):
            error = response["errors"][0]
            raise Exception(
                "Error occurred in results:\r\nCode: {}\r\nMessage: {}".format(
                    error.get("code"), error.get("message")
                )
            )

        if response.get("resources"):
            ioc_infos.extend(response["resources"])

        after = response.get("meta", {}).get("pagination", {}).get("after")
        if after is None:
            break

        if len(ioc_infos) >= indicator_limit:
            ioc_infos = ioc_infos[:indicator_limit]
            break
        api_data["after"] = after

    grouped: dict = {}
    for ioc_info in ioc_infos:
        grouped.setdefault(ioc_info["type"], []).append(ioc_info)

    if sort_criteria:
        for key, value in grouped.items():
            grouped[key] = _sort_entries(sort_criteria, value)

    output = ListCustomIndicatorsOutput(**grouped)

    soar.set_summary(
        ListCustomIndicatorsSummary(
            alerts_found=len(ioc_infos),
            total_domain=len(grouped.get("domain", [])),
            total_ipv4=len(grouped.get("ipv4", [])),
            total_ipv6=len(grouped.get("ipv6", [])),
            total_md5=len(grouped.get("md5", [])),
            total_sha256=len(grouped.get("sha256", [])),
        )
    )
    soar.set_message(f"Indicators found: {len(ioc_infos)}")

    return [output]
