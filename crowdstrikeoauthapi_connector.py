# File: crowdstrikeoauthapi_connector.py
#
# Copyright (c) 2019-2025 Splunk Inc.
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
#
#
import ipaddress
import json
import os
import time
import traceback
import uuid
from _collections import defaultdict
from datetime import datetime, timedelta

import encryption_helper
import phantom.app as phantom
import phantom.rules as phantom_rules
import phantom.utils as util
import pytz
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault
from phantom_common import paths
from requests_toolbelt.multipart.encoder import MultipartEncoder

import parse_cs_events as events_parser
import parse_cs_incidents as incidents_parser

# THIS Connector imports
from crowdstrikeoauthapi_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class CrowdstrikeConnector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

        self._state = {}
        self._events = []
        self._base_url_oauth = None
        self._client_id = None
        self._client_secret = None
        self._oauth_access_token = None
        self._poll_interval = None
        self._required_detonation = False
        self._stream_file_data = False

    def initialize(self):
        """Automatically called by the BaseConnector before the calls to the handle_action function"""

        config = self.get_config()

        # The headers, initialize them here once and use them for all other REST calls
        self._headers = {"Content-Type": "application/json"}

        self.set_validator("ipv6", self._is_ip)
        # Base URL
        self._client_id = config[CROWDSTRIKE_CLIENT_ID]
        self._client_secret = config[CROWDSTRIKE_CLIENT_SECRET]
        self._base_url_oauth = config[CROWDSTRIKE_JSON_URL_OAuth].rstrip("/")
        self._required_detonation = False
        self._poll_interval = self._validate_integers(self, config.get(CROWDSTRIKE_POLL_INTERVAL, 15), CROWDSTRIKE_POLL_INTERVAL)
        if self._poll_interval is None:
            return self.get_status()

        self._base_url_oauth = self._base_url_oauth.replace("\\", "/")
        self._asset_id = self.get_asset_id()

        app_id = config.get("app_id", self.get_app_id())
        self._parameters = {"appId": app_id.replace("-", "")}

        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}

        self._oauth_access_token = self.decrypt_state()

        ret = self._handle_preprocess_scripts()
        if phantom.is_fail(ret):
            return ret

        return phantom.APP_SUCCESS

    def finalize(self):
        if isinstance(self._oauth_access_token, dict):  # Exists and is a dict (updated format)
            # Initialize dict if not present
            if CROWDSTRIKE_OAUTH_TOKEN_STRING not in self._state:
                self._state[CROWDSTRIKE_OAUTH_TOKEN_STRING] = {}

            # Need to encrypt each tenant's token (multiple tenants supported) [PAPP-11254]
            encrypted_tokens = {}
            for tenant, token in self._oauth_access_token.items():
                try:
                    encrypted_tokens[tenant] = encryption_helper.encrypt(token, self._asset_id)
                except Exception as ex:
                    self.debug_print(f"Error encrypting token for tenant {tenant}: {ex!s}")
                    continue

            self._state[CROWDSTRIKE_OAUTH_TOKEN_STRING][CROWDSTRIKE_OAUTH_ACCESS_TOKEN_STRING] = encrypted_tokens
            self._state[CROWDSTRIKE_OAUTH_ACCESS_TOKEN_IS_ENCRYPTED] = True

        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def decrypt_state(self):
        if self._state.get(CROWDSTRIKE_OAUTH_TOKEN_STRING, {}).get(CROWDSTRIKE_OAUTH_ACCESS_TOKEN_STRING):
            if self._state.get(CROWDSTRIKE_OAUTH_ACCESS_TOKEN_IS_ENCRYPTED, False):
                try:
                    # Decrypt each tenant's token (multiple tenants supported) [PAPP-11254]
                    encrypted_tokens = self._state[CROWDSTRIKE_OAUTH_TOKEN_STRING][CROWDSTRIKE_OAUTH_ACCESS_TOKEN_STRING]
                    decrypted_tokens = {}
                    for tenant, token in encrypted_tokens.items():
                        decrypted_tokens[tenant] = encryption_helper.decrypt(token, self._asset_id)
                    return decrypted_tokens
                except Exception as ex:
                    self.debug_print(f"{CROWDSTRIKE_DECRYPTION_ERROR}: {self._get_error_message_from_exception(ex)}")
        return None

    def _is_ip(self, input_ip_address):
        """
        Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        try:
            ipaddress.ip_address(input_ip_address)
        except Exception:
            return False
        return True

    def _handle_preprocess_scripts(self):
        config = self.get_config()
        script = config.get("preprocess_script")

        self._preprocess_container = lambda x: x

        if script:
            try:  # Try to laod in script to preprocess artifacts
                import importlib.util

                preprocess_methods = importlib.util.spec_from_loader("preprocess_methods", loader=None)
                self._script_module = importlib.util.module_from_spec(preprocess_methods)
                exec(script, self._script_module.__dict__)
            except Exception as e:
                self.save_progress(f"Error loading custom script. Error: {self._get_error_message_from_exception(e)}")
                return phantom.APP_ERROR

            try:
                self._preprocess_container = self._script_module.preprocess_container
            except Exception as ex:
                self.save_progress(
                    "Error loading custom script. Does not contain preprocess_container function, "
                    f"Error:{self._get_error_message_from_exception(ex)}"
                )
                return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_message = CROWDSTRIKE_UNAVAILABLE_MESSAGE_ERROR

        self.error_print("Error occurred.", e)

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception as e:
            self.error_print(f"Error occurred while fetching exception information. Details: {e!s}")

        if not error_code:
            error_text = f"Error Message: {error_message}"
        else:
            error_text = f"Error Code: {error_code}. Error Message: {error_message}"

        return error_text

    def _check_for_existing_container(self, container, time_interval, collate):
        # Even if the collate parameter is selected, the time mentioned in the merge_time_interval
        # config parameter will be considered for the creation of the new container for a given category of DetectionSummaryEvent
        gt_date = datetime.utcnow() - timedelta(seconds=int(time_interval))
        # Cutoff Timestamp From String
        common_str = " ".join(container["name"].split()[:-1])
        request_str = CROWDSTRIKE_FILTER_REQUEST_STR.format(
            self.get_phantom_base_url(),
            self.get_asset_id(),
            common_str,
            gt_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

        try:
            r = requests.get(request_str, verify=False)  # nosemgrep
        except Exception as e:
            self.debug_print(f"Error making local rest call: {self._get_error_message_from_exception(e)}")
            self.debug_print(f"DB QUERY: {request_str}")
            return phantom.APP_ERROR, None

        try:
            resp_json = r.json()
        except Exception as e:
            self.debug_print(f"Exception caught: {self._get_error_message_from_exception(e)}")
            return phantom.APP_ERROR, None

        count = resp_json.get("count", 0)
        if count:
            try:
                most_recent = gt_date
                most_recent_id = None
                for container in resp_json["data"]:
                    if container.get("parent_container"):
                        # container created through aggregation, skip this
                        continue
                    cur_start_time = datetime.strptime(container["start_time"], "%Y-%m-%dT%H:%M:%S.%fZ")
                    if most_recent <= cur_start_time:
                        most_recent_id = container["id"]
                        most_recent = cur_start_time
                if most_recent_id is not None:
                    return phantom.APP_SUCCESS, most_recent_id
            except Exception as e:
                self.debug_print(f"Caught Exception in parsing containers: {self._get_error_message_from_exception(e)}")
                return phantom.APP_ERROR, None
        return phantom.APP_ERROR, None

    def _get_hash_type(self, hash_value, action_result):
        if util.is_md5(hash_value):
            return (phantom.APP_SUCCESS, "md5")

        if util.is_sha1(hash_value):
            return (phantom.APP_SUCCESS, "sha1")

        if util.is_sha256(hash_value):
            return (phantom.APP_SUCCESS, "sha256")

        return (
            action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_UNSUPPORTED_HASH_TYPE_ERROR),
            None,
        )

    def _get_ioc_type(self, ioc, action_result):
        if util.is_ip(ioc):
            return phantom.APP_SUCCESS, "ipv4"

        ip = UnicodeDammit(ioc).unicode_markup.encode("UTF-8").decode("UTF-8")
        try:
            ipv6_type = ipaddress.IPv6Address(ip)
            if ipv6_type:
                return phantom.APP_SUCCESS, "ipv6"
        except Exception:
            pass

        if util.is_hash(ioc):
            return self._get_hash_type(ioc, action_result)

        if util.is_domain(ioc):
            return phantom.APP_SUCCESS, "domain"

        return action_result.set_status(phantom.APP_ERROR, "Failed to detect the IOC type")

    def _check_data(self, action_result, param, max_limit=None, sort_data=None):
        limit = self._validate_integers(action_result, param.get("limit", 50), "limit")
        if limit is None:
            return action_result.get_status()

        if max_limit is not None:
            if limit > max_limit:
                limit = max_limit

        param["limit"] = limit

        if param.get("sort") == "--":
            param["sort"] = None
        if sort_data is not None:
            if param.get("sort") and param.get("sort") != "--":
                if param.get("sort") not in sort_data:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        "Please provide a valid value in the 'sort' parameter",
                    )

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_subtenants(self, action_result, cid=None):
        """Get subtenants list from asset configuration"""
        try:
            # Get subtenants from asset config (optionally set)
            subtenants_config = self.get_config().get("subtenants", "")

            # Comma separated list of subtenants
            subtenants = [x.strip() for x in subtenants_config.split(",") if x.strip()]

            if cid:
                if cid not in subtenants:
                    return action_result.set_status(phantom.APP_ERROR, f"No subtenant found with CID {cid}")
                subtenants = [cid]

            return subtenants

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Error processing subtenants configuration: {e!s}")

    def _save_results(self, results, param, is_incident=False):
        reused_containers = 0
        containers_processed = 0
        artifact_type = "incident" if is_incident else "event"

        for i, result in enumerate(results):
            self.send_progress(f"Adding {artifact_type} artifact # {i}")
            # result is a dictionary of a single container and artifacts
            if "container" not in result:
                self.debug_print(f"Skipping empty container # {i}")
                continue

            if "artifacts" not in result:
                # ignore containers without artifacts
                self.debug_print(f"Skipping container # {i} without artifacts")
                continue

            if len(result["artifacts"]) == 0:
                # ignore containers without artifacts
                self.debug_print(f"Skipping container # {i} with 0 artifacts")
                continue

            config = self.get_config()
            time_interval = config.get("merge_time_interval", 0)

            if "artifacts" not in result:
                continue

            artifacts = result["artifacts"]

            container = result["container"]
            container["artifacts"] = artifacts

            if hasattr(self, "_preprocess_container"):
                try:
                    container = self._preprocess_container(container)
                except Exception as e:
                    self.debug_print(f"Preprocess error: {self._get_error_message_from_exception(e)}")

            artifacts = container.pop("artifacts", [])

            ret_val, container_id = self._check_for_existing_container(container, time_interval, config.get("collate"))

            if not container_id:
                ret_val, response, container_id = self.save_container(container)
                self.debug_print(f"save_container returns, value: {ret_val}, reason: {response}, id: {container_id}")

                if phantom.is_fail(ret_val):
                    self.debug_print("Error occurred while creating a new container")
                    continue
            else:
                reused_containers += 1

            # get the length of the artifact, we might have trimmed it or not
            len_artifacts = len(artifacts)
            # Always set the very first artifact to run_automation = True to never have duplicate conflicts
            if len_artifacts >= 1:
                artifacts[0]["run_automation"] = True

            # Useful for spawn.log file analysis
            for artifact in artifacts:
                artifact["container_id"] = container_id

            ret_val, status_string, artifact_ids = self.save_artifacts(artifacts)
            self.debug_print(f"save_artifacts returns, value: {ret_val}, reason: {status_string}")
            self.debug_print(f"Container with id: {container_id}")

            if phantom.is_fail(ret_val):
                self.debug_print(f"Error occurred while adding {len_artifacts} artifacts to container: {container_id}")

            containers_processed += 1

        if reused_containers and config.get("collate"):
            self.save_progress("Some containers were re-used due to collate set to True")

        return containers_processed

    @staticmethod
    def validate_comma_seperated_values(values):
        return list(set(val.strip() for val in values.split(",") if val.strip()))

    def _paginator(self, action_result, endpoint, param=None):
        """
        This action is used to create an iterator that will paginate through responses from called methods.

        :param method_name: Name of method whose response is to be paginated
        :param action_result: Object of ActionResult class
        :param **kwargs: Dictionary of Input parameters
        """
        if param is None:
            param = dict()
        list_ids = list()

        limit = None
        if param.get("limit"):
            limit = int(param.pop("limit"))

        offset = param.get("offset", 0)

        while True:
            param.update({"offset": offset})
            ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, params=param)

            if phantom.is_fail(ret_val):
                return None

            prev_offset = offset
            offset = response.get("meta", {}).get("pagination", {}).get("offset")
            if offset == prev_offset:
                offset += len(response.get("resources", []))

            # Fetching total from the response
            total = response.get("meta", {}).get("pagination", {}).get("total")

            if len(response.get("errors", [])):
                error = response.get("errors")[0]
                action_result.set_status(
                    phantom.APP_ERROR, "Error occurred in results:\r\nCode: {}\r\nMessage: {}".format(error.get("code"), error.get("message"))
                )
                return None

            if offset is None or total is None:
                action_result.set_status(
                    phantom.APP_ERROR, "Error occurred in fetching 'offset' and 'total' key-values while fetching paginated results"
                )
                return None

            if response.get("resources"):
                list_ids.extend(response.get("resources"))

            if limit and len(list_ids) >= int(limit):
                return list_ids[: int(limit)]

            if self.get_action_identifier() in ["detonate_file", "detonate_url"]:
                if total == 0:
                    self._required_detonation = True
            if offset >= total:
                return list_ids

        return list_ids

    def _hunt_paginator(self, action_result, endpoint, params, search_subtenants=False, subtenant=None):
        list_ids = list()

        offset = ""
        limit = None
        if params.get("limit"):
            limit = params.pop("limit")

        subtenants = [None]

        if subtenant:
            if subtenant == "main":
                subtenants = [None]
            else:
                subtenants = [subtenant]

            # Subtenant is specified, don't need to search across all subtenants
            search_subtenants = False

        if search_subtenants:
            configured_subtenants = self._get_subtenants(action_result, subtenant)
            if configured_subtenants:
                subtenants.extend(configured_subtenants)

        for subtenant in subtenants:
            while True:
                params.update({"offset": offset})
                params.update({"limit": 100})

                ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, params=params, subtenant=subtenant)

                if phantom.is_fail(ret_val):
                    if CROWDSTRIKE_STATUS_CODE_CHECK_MESSAGE in action_result.get_message():
                        # Continue (next subtenant if there is one)
                        break
                    return None

                offset = response.get("meta", {}).get("pagination", {}).get("offset")

                if len(response.get("errors", [])):
                    error = response.get("errors")[0]
                    action_result.set_status(
                        phantom.APP_ERROR,
                        "Error occurred in results:\r\nCode: {}\r\nMessage: {}".format(error.get("code"), error.get("message")),
                    )
                    return None

                if response.get("resources"):
                    list_ids.extend(response.get("resources"))

                if limit and len(list_ids) >= limit:
                    return list_ids[:limit]

                if (not offset) and (not response.get("meta", {}).get("pagination", {}).get("next_page")):
                    # Continue (next subtenant if there is one)
                    break

        return list_ids

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not param:
            param = {}

        ret_val = self._get_token(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        param.update({"limit": 1})
        self.save_progress("Fetching devices")
        ret_val, resp_json = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT, params=param)

        if phantom.is_fail(ret_val):
            self.save_progress(CROWDSTRIKE_CONNECTIVITY_TEST_ERROR)
            return phantom.APP_ERROR

        self.save_progress("Test connectivity passed")

        return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_SUCC_CONNECTIVITY_TEST)

    def _handle_run_query(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = param.get("endpoint")
        if not endpoint:
            return action_result.set_status(phantom.APP_ERROR, "Please provide endpoint path")

        # Ensure using query endpoint
        if "/queries/" not in endpoint.lower():
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_QUERY_ENDPOINT_MESSAGE_ERROR)

        params = {"limit": param.get("limit", 50), "offset": param.get("offset", 0)}
        params.update({k: param[k] for k in ["filter", "sort"] if param.get(k)})

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add data items
        resources = response.get("resources", [])
        for resource in resources:
            action_result.add_data({"resource_id": resource})

        summary = action_result.update_summary({})
        meta = response.get("meta", {})
        pagination = meta.get("pagination", {})

        summary.update(
            {
                "total_objects": len(resources),
                "total_count": pagination.get("total", 0),
                "query_time": meta.get("query_time", 0),
                "powered_by": meta.get("powered_by", ""),
                "trace_id": meta.get("trace_id", ""),
            }
        )

        return action_result.set_status(phantom.APP_SUCCESS, "Query completed successfully")

    def _get_ids(self, action_result, endpoint, param, is_str=True):
        id_list = self._paginator(action_result, endpoint, param)

        if id_list is None:
            return id_list

        if is_str:
            id_list = list(map(str, id_list))

        return id_list

    def _get_ids_with_subtenants(self, action_result, endpoint, param=None, subtenant=None):
        subtenants = [None]
        search_subtenants = True

        if subtenant:
            if subtenant == "main":
                subtenants = [None]
            else:
                subtenants = [subtenant]

            # Subtenant is specified, don't need to search across all subtenants
            search_subtenants = False

        if search_subtenants:
            # Get all subtenants if searching across them
            configured_subtenants = self._get_subtenants(action_result)
            if configured_subtenants:
                subtenants.extend(configured_subtenants)

        # Dictionary to store IDs with their corresponding tenants
        id_tenant_map = {}

        for tenant in subtenants:
            ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, params=param, subtenant=tenant)
            if phantom.is_fail(ret_val):
                return None

            ids = response.get("resources", [])
            if not ids:
                continue

            # Store each ID with its tenant
            for device_id in ids:
                id_tenant_map[device_id] = tenant

        # Dictionary of IDs and their corresponding tenants (when searching across subtenants)
        if search_subtenants:
            return id_tenant_map

        # Just list if not searching across
        return list(id_tenant_map.keys())

    def _get_details(self, action_result, endpoint, param, method="get", subtenant=None):
        list_ids = param.get("ids")

        list_ids_details = list()

        self.save_progress("_get_details: tenant {}".format(subtenant if subtenant else "current"))

        while list_ids:
            if endpoint == CROWDSTRIKE_LIST_ALERT_DETAILS_ENDPOINT:
                param = {"composite_ids": list_ids[: min(100, len(list_ids))]}
            else:
                param = {"ids": list_ids[: min(100, len(list_ids))]}

            ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, json_data=param, method=method, subtenant=subtenant)
            if phantom.is_fail(ret_val):
                return None

            if response.get("resources"):
                list_ids_details.extend(response.get("resources"))

            del list_ids[: min(100, len(list_ids))]

        return list_ids_details

    def _get_devices_ran_on(self, ioc, ioc_type, param, action_result):
        api_data = {"type": ioc_type, "value": ioc}
        limit = self._validate_integers(action_result, param.get("limit", 100), "limit")
        if limit is None:
            return action_result.get_status()
        api_data["limit"] = limit
        count_only = param.get(CROWDSTRIKE_JSON_COUNT_ONLY, False)
        subtenant = param.get(CROWDSTRIKE_CID)

        response = self._hunt_paginator(
            action_result, CROWDSTRIKE_GET_DEVICES_RAN_ON_APIPATH, params=api_data, search_subtenants=True, subtenant=subtenant
        )

        if response is None:
            return action_result.get_status()

        if count_only:
            action_result.update_summary({"device_count": len(response)})
            return action_result.set_status(phantom.APP_SUCCESS)

        # successful request / "none found"
        for device_id in response:
            action_result.add_data({"device_id": device_id})
        action_result.set_summary({"device_count": len(response)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_resolve_detection(self, param):
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        detection_id = param[CROWDSTRIKE_JSON_ID]
        to_state = param[CROWDSTRIKE_RESOLVE_DETECTION_TO_STATE]

        detection_id = [x.strip() for x in detection_id.split(",")]
        detection_id = list(filter(None, detection_id))

        api_data = {"ids": detection_id, "status": to_state}

        ret_val, response = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_RESOLVE_DETECTION_APIPATH,
            json_data=api_data,
            method="patch",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Status set successfully")

    def _handle_resolve_epp_alerts(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        composite_ids = self.validate_comma_seperated_values(param.get(CROWDSTRIKE_ALERT_IDS))
        if not composite_ids:
            return action_result.set_status(
                phantom.APP_ERROR,
                CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key=CROWDSTRIKE_ALERT_IDS),
            )

        to_state = param[CROWDSTRIKE_STATUS]
        if to_state not in CROWDSTRIKE_EPP_ALERT_STATUSES:
            return action_result.set_status(
                phantom.APP_ERROR,
                CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key=CROWDSTRIKE_STATUS),
            )

        api_data = {
            "composite_ids": composite_ids,
            "action_parameters": [{"name": "update_status", "value": to_state}],
        }

        ret_val, response = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_UPDATE_ALERT_ENDPOINT,
            json_data=api_data,
            method="patch",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        resources_affected = response.get("meta", {}).get("writes", {}).get("resources_affected", 0)
        if resources_affected != len(composite_ids):
            errors = [error.get("message") for error in response.get("errors", [])]
            return action_result.set_status(
                phantom.APP_ERROR,
                "Errors occurred while updating alerts: {}".format("\r\n".join(errors)),
            )

        summary = action_result.update_summary({})
        summary["alerts_affected"] = resources_affected

        return action_result.set_status(phantom.APP_SUCCESS)

    def _paginate_get_endpoint(
        self,
        action_result,
        resource_id_list,
        endpoint,
        check_message=None,
        resource_data=None,
    ):
        id_list = list()
        id_list.extend(resource_id_list)
        resource_details_list = list()
        while id_list:
            # Endpoint creation
            ids = id_list[: min(100, len(id_list))]
            endpoint_param = ""
            for resource in ids:
                endpoint_param += f"ids={resource}&"

            endpoint_param = endpoint_param.strip("&")

            endpoint = f"{endpoint}?{endpoint_param}"

            # Make REST call
            ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint)

            if phantom.is_fail(ret_val) and check_message not in action_result.get_message():
                self.debug_print(f"Error response returned from the API : {endpoint}")
                return action_result.get_status()

            if ret_val and response.get("resources"):
                resource_details_list.extend(response.get("resources"))

            del id_list[: min(100, len(id_list))]

        if not resource_details_list:
            return action_result.set_status(phantom.APP_SUCCESS, "No data found")

        resource_details_list = [i for n, i in enumerate(resource_details_list) if i not in resource_details_list[n + 1 :]]

        for item in resource_details_list:
            action_result.add_data(item)

        return action_result.set_status(phantom.APP_SUCCESS, f"{resource_data} fetched successfully")

    def _handle_get_zta_data(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        agent_ids = param["agent_id"]
        agent_ids = [x.strip() for x in agent_ids.split(",")]
        agent_ids = list(filter(None, agent_ids))
        return self._paginate_get_endpoint(
            action_result,
            agent_ids,
            CROWDSTRIKE_GET_ZERO_TRUST_ASSESSMENT_ENDPOINT,
            CROWDSTRIKE_STATUS_CODE_CHECK_MESSAGE,
            "Zero Trust Assessment data",
        )

    def _handle_hunt_file(self, param):
        file_hash = param[phantom.APP_JSON_HASH]

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, ioc_type = self._get_hash_type(file_hash, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return self._get_devices_ran_on(file_hash, ioc_type, param, action_result)

    def _handle_hunt_domain(self, param):
        domain = param[phantom.APP_JSON_DOMAIN]

        action_result = self.add_action_result(ActionResult(dict(param)))

        return self._get_devices_ran_on(domain, "domain", param, action_result)

    def _handle_hunt_ip(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        ioc = param[phantom.APP_JSON_IP]

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, ioc_type = self._get_ioc_type(ioc, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return self._get_devices_ran_on(ioc, ioc_type, param, action_result)

    def _handle_get_device_detail(self, param):
        # Add an action result to the App Run
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        fdid = param[CROWDSTRIKE_GET_DEVICE_DETAIL_DEVICE_ID]

        api_data = {"ids": fdid}

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_GET_DEVICE_DETAILS_ENDPOINT, params=api_data)

        if phantom.is_fail(ret_val) and CROWDSTRIKE_STATUS_CODE_CHECK_MESSAGE in action_result.get_message():
            return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_NO_DATA_MESSAGE)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # successful request
        try:
            data = dict(response["resources"][0])
        except Exception as ex:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Error occurred while parsing response of 'get_system_info' action."
                f" Unknown response retrieved Error:{self._get_error_message_from_exception(ex)}",
            )

        action_result.add_data(data)

        summary = action_result.update_summary({})
        try:
            summary["hostname"] = response["resources"][0]["hostname"]
        except Exception as ex:
            self.debug_print(f"Error occured while getting hostname, Error:{self._get_error_message_from_exception(ex)}")

        return action_result.set_status(phantom.APP_SUCCESS, "Device details fetched successfully")

    def _handle_get_device_scroll(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        data = {
            "offset": param.get("offset", None),
            "limit": param.get("limit", None),
            "sort": param.get("sort", None),
            "filter": param.get("filter", None),
        }

        # More info on the endpoint at https://assets.falcon.crowdstrike.com/support/api/swagger.html#/hosts/QueryDevicesByFilterScroll
        ret_val, response = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_GET_DEVICE_SCROLL_ENDPOINT, params=data)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Failed to fetch device scroll", response)

        action_result.add_data(response)

        self.debug_print(f"Successfully fetched device scroll with response {response}")
        return action_result.set_status(phantom.APP_SUCCESS, "Device scroll fetched successfully")

    def _handle_get_process_detail(self, param):
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        fpid = param.get(CROWDSTRIKE_GET_PROCESS_DETAIL_FALCON_PROCESS_ID, "")

        api_data = {"ids": fpid}

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_GET_PROCESS_DETAIL_APIPATH, params=api_data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            data = dict(response["resources"][0])
        except Exception as ex:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Error occurred while parsing response of 'get_process_detail' action. Unknown response retrieved "
                f"{self._get_error_message_from_exception(ex)}",
            )

        action_result.add_data(data)

        return action_result.set_status(phantom.APP_SUCCESS, "Process details fetched successfully")

    def _handle_list_incidents(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        max_limit = None
        sort_data = [
            "assigned_to.asc",
            "assigned_to.desc",
            "assigned_to_name.asc",
            "assigned_to_name.desc",
            "end.asc",
            "end.desc",
            "modified_timestamp.asc",
            "modified_timestamp.desc",
            "name.asc",
            "name.desc",
            "sort_score.asc",
            "sort_score.desc",
            "start.asc",
            "start.desc",
            "state.asc",
            "state.desc",
            "status.asc",
            "status.desc",
        ]

        params = {
            k: param[k]
            for k in param.keys()
            if k
            in [
                CROWDSTRIKE_FILTER,
                CROWDSTRIKE_LIMIT,
                CROWDSTRIKE_OFFSET,
                CROWDSTRIKE_SORT,
            ]
        }

        resp = self._check_data(action_result, params, max_limit, sort_data)
        if phantom.is_fail(resp):
            return action_result.get_status()

        endpoint = CROWDSTRIKE_LIST_INCIDENTS_ENDPOINT

        id_list = self._get_ids(action_result, endpoint, params)

        if id_list is None:
            return action_result.get_status()

        # Add the response into the data section
        for id in id_list:
            action_result.add_data(id)

        summary = action_result.update_summary({})
        summary["total_incidents"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_incident_behaviors(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        max_limit = None
        sort_data = ["--", "timestamp.asc", "timestamp.desc"]

        params = {
            k: param[k]
            for k in param.keys()
            if k
            in [
                CROWDSTRIKE_FILTER,
                CROWDSTRIKE_LIMIT,
                CROWDSTRIKE_OFFSET,
                CROWDSTRIKE_SORT,
            ]
        }

        resp = self._check_data(action_result, params, max_limit, sort_data)
        if phantom.is_fail(resp):
            return action_result.get_status()

        endpoint = CROWDSTRIKE_LIST_BEHAVIORS_ENDPOINT

        id_list = self._get_ids(action_result, endpoint, params)

        if id_list is None:
            return action_result.get_status()

        # Add the response into the data section
        for id in id_list:
            action_result.add_data(id)

        summary = action_result.update_summary({})
        summary["total_incident_behaviors"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident_details(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ids = param.get("ids")
        ids = [x.strip() for x in ids.split(",")]
        ids = list(filter(None, ids))

        data = {"ids": ids}

        endpoint = CROWDSTRIKE_GET_INCIDENT_DETAILS_ID_ENDPOINT

        details_list = self._get_details(action_result, endpoint, data, method="post")

        if details_list is None:
            return action_result.get_status()

        for incident in details_list:
            action_result.add_data(incident)

        summary = action_result.update_summary({})
        summary["total_incidents"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS, f"Incidents fetched: {len(details_list)}")

    def _handle_get_incident_behaviors(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ids = param.get("ids")
        ids = [x.strip() for x in ids.split(",")]
        ids = list(filter(None, ids))

        data = {"ids": ids}

        endpoint = CROWDSTRIKE_GET_INCIDENT_BEHAVIORS_ID_ENDPOINT

        details_list = self._get_details(action_result, endpoint, data, "post")

        if details_list is None:
            return action_result.get_status()

        # Add the response into the data section
        for incident_behavior in details_list:
            action_result.add_data(incident_behavior)

        return action_result.set_status(phantom.APP_SUCCESS, "Incident behavior fetched successfully")

    def _handle_list_crowdscores(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {
            k: param[k]
            for k in param.keys()
            if k
            in [
                CROWDSTRIKE_FILTER,
                CROWDSTRIKE_LIMIT,
                CROWDSTRIKE_OFFSET,
                CROWDSTRIKE_SORT,
            ]
        }

        max_limit = None
        sort_data = ["--", "score.asc", "score.desc", "timestamp.asc", "timestamp.desc"]

        resp = self._check_data(action_result, params, max_limit, sort_data)

        if phantom.is_fail(resp):
            return action_result.get_status()

        endpoint = CROWDSTRIKE_LIST_CROWDSCORES_ENDPOINT

        id_list = self._get_ids(action_result, endpoint, params, is_str=False)

        if id_list is None:
            return action_result.get_status()

        # Add the response into the data section
        for crowdscore in id_list:
            action_result.add_data(crowdscore)

        summary = action_result.update_summary({})
        summary["total_crowdscores"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_incident(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Hold the values for the status
        statuses = {"new": 20, "reopened": 25, "in progress": 30, "closed": 40}

        ids = param.get("ids")
        ids = [x.strip() for x in ids.split(",")]
        ids = list(filter(None, ids))

        # Default data we will send
        data = {"action_parameters": [], "ids": ids}

        if param.get("add_tag"):
            add_tags = param.get("add_tag")
            add_tags = [x.strip() for x in add_tags.split(",")]
            add_tags = list(filter(None, add_tags))
            for tag in add_tags:
                data["action_parameters"].append({"name": "add_tag", "value": tag})

        if param.get("delete_tag"):
            delete_tags = param.get("delete_tag")
            delete_tags = [x.strip() for x in delete_tags.split(",")]
            delete_tags = list(filter(None, delete_tags))
            for tag in delete_tags:
                data["action_parameters"].append({"name": "delete_tag", "value": tag})

        if param.get("update_name"):
            name = param.get("update_name")
            data["action_parameters"].append({"name": "update_name", "value": name})

        if param.get("update_description"):
            description = param.get("update_description")
            data["action_parameters"].append({"name": "update_description", "value": description})

        data_list = ["New", "Reopened", "In Progress", "Closed"]
        if param.get("update_status"):
            if param.get("update_status") not in data_list:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Please provide a valid value in the 'update_status' parameter",
                )
            status = param.get("update_status").lower()
            data["action_parameters"].append({"name": "update_status", "value": str(statuses[status])})

        if param.get("add_comment"):
            comment = param.get("add_comment")
            data["action_parameters"].append({"name": "add_comment", "value": comment})

        endpoint = CROWDSTRIKE_UPDATE_INCIDENT_ENDPOINT

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, json_data=data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Incident updated successfully")

    def _handle_list_users(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get all the UIDS from your Customer ID
        endpoint = CROWDSTRIKE_LIST_USERS_UIDS_ENDPOINT

        ids = self._paginator(action_result, endpoint)

        if ids is None:
            return action_result.get_status()

        if not ids:
            return action_result.set_status(phantom.APP_SUCCESS, "No data found for user resources")

        data = {"ids": ids}

        endpoint = CROWDSTRIKE_GET_USER_INFO_ENDPOINT

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, json_data=data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary["total_users"] = len(response.get("resources", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_user_roles(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {"user_uuid": param["user_uuid"]}

        endpoint = CROWDSTRIKE_GET_USER_ROLES_ENDPOINT

        user_role_list = self._paginator(action_result, endpoint, params)

        if user_role_list is None:
            return action_result.get_status()

        # Add the response into the data section
        for data in user_role_list:
            action_result.add_data(data)

        return action_result.set_status(phantom.APP_SUCCESS, "User roles fetched successfully")

    def _handle_get_role(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        list_ids = param.get("role_id")
        list_ids = [x.strip() for x in list_ids.split(",")]
        list_ids = list(filter(None, list_ids))
        return self._paginate_get_endpoint(
            action_result,
            list_ids,
            CROWDSTRIKE_GET_ROLE_ENDPOINT,
            CROWDSTRIKE_STATUS_CODE_MESSAGE,
            "Role",
        )

    def _handle_list_roles(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get all the Roles from your Customer ID
        endpoint = CROWDSTRIKE_LIST_USER_ROLES_ENDPOINT

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Create the param variable to send
        params = {"ids": response["resources"]}

        endpoint = CROWDSTRIKE_GET_ROLE_ENDPOINT

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Roles listed successfully")

    def _handle_query_device(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))
        max_limit = 5000

        params = {
            k: param[k]
            for k in param.keys()
            if k
            in [
                CROWDSTRIKE_FILTER,
                CROWDSTRIKE_LIMIT,
                CROWDSTRIKE_OFFSET,
                CROWDSTRIKE_SORT,
            ]
        }

        resp = self._check_data(action_result, params, max_limit)
        if phantom.is_fail(resp):
            return action_result.get_status()

        subtenant = param.get(CROWDSTRIKE_CID)

        id_tenant_map = self._get_ids_with_subtenants(action_result, CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT, params, subtenant=subtenant)
        if id_tenant_map is None:
            return action_result.get_status()

        if id_tenant_map and isinstance(id_tenant_map, dict):
            # Group IDs by tenant
            tenant_id_groups = {}
            for device_id, tenant in id_tenant_map.items():
                if tenant not in tenant_id_groups:
                    tenant_id_groups[tenant] = []
                tenant_id_groups[tenant].append(device_id)

            # Query each tenant for its specific devices
            for tenant, device_ids in tenant_id_groups.items():
                params.update({"ids": device_ids})
                device_details_list = self._get_details(action_result, CROWDSTRIKE_GET_DEVICE_DETAILS_ENDPOINT, params, subtenant=tenant)
                if device_details_list is None:
                    return action_result.get_status()

                for device in device_details_list:
                    action_result.add_data(device)
        else:
            params.update({"ids": id_tenant_map})
            device_details_list = self._get_details(action_result, CROWDSTRIKE_GET_DEVICE_DETAILS_ENDPOINT, params, subtenant=subtenant)
            if device_details_list is None:
                return action_result.get_status()

            for device in device_details_list:
                action_result.add_data(device)

        summary = action_result.update_summary({})
        summary["total_devices"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_groups(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))
        max_limit = None

        sort_data = [
            "created_by.asc",
            "created_by.desc",
            "created_timestamp.asc",
            "created_timestamp.desc",
            "group_type.asc",
            "group_type.desc",
            "modified_by.asc",
            "modified_by.desc",
            "modified_timestamp.asc",
            "modified_timestamp.desc",
            "name.asc",
            "name.desc",
        ]

        params = {k: param[k] for k in param.keys() if k in [CROWDSTRIKE_FILTER, CROWDSTRIKE_LIMIT, CROWDSTRIKE_SORT]}

        resp = self._check_data(action_result, params, max_limit, sort_data)

        if phantom.is_fail(resp):
            return action_result.get_status()

        host_group_id_list = self._get_ids(action_result, CROWDSTRIKE_GET_HOST_GROUP_ID_ENDPOINT, params)

        if host_group_id_list is None:
            return action_result.get_status()

        if not isinstance(host_group_id_list, list):
            return action_result.set_status(phantom.APP_ERROR, "Unknown response retrieved")

        id_list = host_group_id_list
        host_group_details_list = list()

        while id_list:
            # Endpoint creation
            ids = id_list[: min(100, len(id_list))]
            endpoint_param = ""
            for resource in ids:
                endpoint_param += f"ids={resource}&"

            endpoint_param = endpoint_param.strip("&")
            endpoint = CROWDSTRIKE_GET_HOST_GROUP_DETAILS_ENDPOINT

            endpoint = f"{endpoint}?{endpoint_param}"

            # Make REST call
            ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if response.get("resources"):
                host_group_details_list.extend(response.get("resources"))

            del id_list[: min(100, len(id_list))]

        if not host_group_details_list:
            return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_NO_DATA_MESSAGE)

        for host_group in host_group_details_list:
            action_result.add_data(host_group)

        summary = action_result.update_summary({})
        summary["total_host_groups"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def helper_sort_ioc_data(self, indicator_sort_criteria, value):
        sort_criteria, data_ordering = indicator_sort_criteria.split(".")
        if data_ordering == "asc":
            return sorted(
                value,
                key=lambda x: x[CROWDSTRIKE_SORT_FOR_CRITERIA_IOC_DICT[sort_criteria]],
            )
        return sorted(
            value,
            key=lambda x: x[CROWDSTRIKE_SORT_FOR_CRITERIA_IOC_DICT[sort_criteria]],
            reverse=True,
        )

    def helper_create_query(self, param, filter_query):
        if CROWDSTRIKE_JSON_LIST_IOC in param:
            if filter_query:
                filter_query = f"{filter_query}+value:'{param.get(CROWDSTRIKE_JSON_LIST_IOC)}'"
            else:
                filter_query = f"value:'{param.get(CROWDSTRIKE_JSON_LIST_IOC)}'"
        if CROWDSTRIKE_IOCS_ACTION in param:
            ioc_action = param.get(CROWDSTRIKE_IOCS_ACTION).lower()
            if filter_query:
                filter_query = f"{filter_query}+action:'{ioc_action}'"
            else:
                filter_query = f"action:'{ioc_action}'"
        if CROWDSTRIKE_SEARCH_IOCS_FROM_EXPIRATION in param:
            if filter_query:
                filter_query = f"{filter_query}+expiration:>='{param.get(CROWDSTRIKE_SEARCH_IOCS_FROM_EXPIRATION)}'"
            else:
                filter_query = f"expiration:>='{param.get(CROWDSTRIKE_SEARCH_IOCS_FROM_EXPIRATION)}'"
        if CROWDSTRIKE_SEARCH_IOCS_TO_EXPIRATION in param:
            if filter_query:
                filter_query = f"{filter_query}+expiration:<='{param.get(CROWDSTRIKE_SEARCH_IOCS_TO_EXPIRATION)}'"
            else:
                filter_query = f"expiration:<='{param.get(CROWDSTRIKE_SEARCH_IOCS_TO_EXPIRATION)}'"
        if CROWDSTRIKE_IOCS_SOURCE in param:
            if filter_query:
                filter_query = f"{filter_query}+source:'{param.get(CROWDSTRIKE_IOCS_SOURCE)}'"
            else:
                filter_query = f"source:'{param.get(CROWDSTRIKE_IOCS_SOURCE)}'"
        if CROWDSTRIKE_SEARCH_IOCS_TYPE in param and param.get(CROWDSTRIKE_SEARCH_IOCS_TYPE).lower() != "all":
            search_ioc_type = param.get(CROWDSTRIKE_SEARCH_IOCS_TYPE).lower()
            if search_ioc_type == "hash":
                source_list = ["md5", "sha256"]
                if filter_query:
                    filter_query = f"{filter_query}+type:{source_list}"
                else:
                    filter_query = f"type:{source_list}"
            else:
                if filter_query:
                    filter_query = f"{filter_query}+type:'{search_ioc_type}'"
                else:
                    filter_query = f"type:'{search_ioc_type}'"
        return filter_query

    def _handle_list_custom_indicators(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        indicator_limit = self._validate_integers(
            action_result,
            param.get(CROWDSTRIKE_IOCS_LIMIT, 100),
            CROWDSTRIKE_IOCS_LIMIT,
        )
        if indicator_limit is None:
            return action_result.get_status()

        indicator_sort_criteria = param.get(CROWDSTRIKE_IOCS_SORT)
        if indicator_sort_criteria:
            indicator_sort_criteria = indicator_sort_criteria.lower()
            if indicator_sort_criteria not in CROWDSTRIKE_SORT_CRITERIA_LIST:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    CROWDSTRIKE_VALUE_LIST_MESSAGE_ERROR.format(CROWDSTRIKE_IOCS_SORT),
                )
        if CROWDSTRIKE_IOCS_ACTION in param:
            ioc_action = param.get(CROWDSTRIKE_IOCS_ACTION).lower()
            if ioc_action not in [
                "no_action",
                "allow",
                "prevent_no_ui",
                "prevent",
                "detect",
            ]:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    CROWDSTRIKE_VALUE_LIST_MESSAGE_ERROR.format(CROWDSTRIKE_IOCS_ACTION),
                )
        if CROWDSTRIKE_SEARCH_IOCS_TYPE in param:
            search_ioc_type = param.get(CROWDSTRIKE_SEARCH_IOCS_TYPE).lower()
            if search_ioc_type not in [
                "all",
                "hash",
                "ipv4",
                "ipv6",
                "md5",
                "sha256",
                "domain",
            ]:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    CROWDSTRIKE_VALUE_LIST_MESSAGE_ERROR.format(CROWDSTRIKE_SEARCH_IOCS_TYPE),
                )
        api_data = {"limit": 2000}  # 2000 is the max, this could be tuned
        filter_query = self.helper_create_query(param, "")

        if filter_query:
            api_data["filter"] = filter_query

        more = True

        self.send_progress("Completed 0 %")
        ioc_infos = []
        while more:
            ret_val, response = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_GET_COMBINED_CUSTOM_INDICATORS_ENDPOINT,
                params=api_data,
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if response.get("errors") and len(response.get("errors")) > 0:
                error = response.get("errors")[0]
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Error occurred in results:\r\nCode: {}\r\nMessage: {}".format(error.get("code"), error.get("message")),
                )

            if response.get("resources"):
                ioc_infos.extend(response.get("resources"))

            after = response.get("meta", {}).get("pagination", {}).get("after")
            if after is None:
                break
            total = response.get("meta", {}).get("pagination", {}).get("total")

            if total:
                self.send_progress(CROWDSTRIKE_COMPLETED, float(len(ioc_infos)) / float(total))

            if len(ioc_infos) >= indicator_limit:
                ioc_infos = ioc_infos[:indicator_limit]
                more = False
            else:
                api_data["after"] = after

        self.save_progress("Processing results")

        data = defaultdict(list)

        for ioc_info in ioc_infos:
            data[ioc_info["type"]].append(ioc_info)

        summary_keys = ["ipv4", "ipv6", "domain", "md5", "sha256"]

        if data:
            data = dict(data)
            if indicator_sort_criteria:
                for key, value in data.items():
                    data[key] = self.helper_sort_ioc_data(indicator_sort_criteria, value)

            action_result.add_data(data)

            for key in summary_keys:
                summary_data_key = f"total_{key}"

                if key not in data:
                    action_result.update_summary({summary_data_key: 0})
                    continue

                action_result.update_summary({summary_data_key: len(data[key])})

        action_result.update_summary({"alerts_found": len(ioc_infos)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_put_files(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {
            k: param[k]
            for k in param.keys()
            if k
            in [
                CROWDSTRIKE_FILTER,
                CROWDSTRIKE_LIMIT,
                CROWDSTRIKE_OFFSET,
                CROWDSTRIKE_SORT,
            ]
        }

        resp = self._check_data(action_result, params)

        if phantom.is_fail(resp):
            return action_result.get_status()

        put_file_ids_list = self._get_ids(action_result, CROWDSTRIKE_RTR_ADMIN_GET_PUT_FILES, params)

        if put_file_ids_list is None:
            return action_result.get_status()

        test_data = list()
        test_data.extend(put_file_ids_list)
        params.update({"ids": put_file_ids_list})
        put_file_details_list = self._get_details(action_result, CROWDSTRIKE_RTR_ADMIN_PUT_FILES, params, method="get")

        if put_file_details_list is None:
            return action_result.get_status()

        put_file_sorted_list = list()
        test_details = dict()
        for data in put_file_details_list:
            test_details.update({data["id"]: data})
        for id in test_data:
            try:
                if test_details[id] not in put_file_sorted_list:
                    put_file_sorted_list.append(test_details[id])
            except Exception as ex:
                self.debug_print(f"Error occurred while sorting the 'put' file details, {self._get_error_message_from_exception(ex)}")

        for put_file in put_file_sorted_list:
            action_result.add_data(put_file)

        summary = action_result.update_summary({})
        summary["total_files"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_params(self, action_result, param, subtenant=None):
        ids = list()
        device_id = param.get("device_id", "")
        hostname = param.get("hostname")
        device_id_flag, hostname_flag = False, False
        intermediate_device_ids = list()
        if not device_id and not hostname:
            return (
                action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_NO_PARAMETER_ERROR),
                None,
            )

        if device_id:
            device_ids = [x.strip() for x in device_id.split(",")]
            device_ids = " ".join(device_ids).split()
            if len(device_ids) == 0:
                return (
                    action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_INPUT_ERROR),
                    None,
                )

            ret_val, device_id_flag, interim_devices_list = self._set_error_flag_inputs(action_result, device_ids, "device_id", subtenant)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            intermediate_device_ids.extend(interim_devices_list)

        if hostname:
            hostnames = [x.strip() for x in hostname.split(",")]
            hostnames = " ".join(hostnames).split()
            if len(hostnames) == 0:
                return (
                    action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_INPUT_ERROR),
                    None,
                )

            ret_val, hostname_flag, interim_hostnames_list = self._set_error_flag_inputs(action_result, hostnames, "hostname", subtenant)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            intermediate_device_ids.extend(interim_hostnames_list)

        if device_id_flag and hostname_flag:
            return (
                action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_DEVICE_ID_AND_HOSTNAME_ERROR),
                None,
            )
        elif device_id_flag:
            return (
                action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_DEVICE_ID_ERROR),
                None,
            )
        elif hostname_flag:
            return (
                action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_HOSTNAME_ERROR),
                None,
            )
        else:
            ids.extend(intermediate_device_ids)

        return action_result.set_status(phantom.APP_SUCCESS), list(set(ids))

    def _set_error_flag_inputs(self, action_result, list_items, key, subtenant=None):
        flag = False
        check_list_items = list()
        filter = ""

        for item in list_items:
            filter = f"{filter}{key}: '{item}', "  # or opeartion with given hostname/s
        filter = filter[:-2]  # removing last trailing , and space

        check_list_items = self._get_ids_with_subtenants(
            action_result, CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT, param={"filter": filter}, subtenant=subtenant
        )

        if check_list_items is None:
            return action_result.get_status(), flag, []

        if len(list_items) != len(check_list_items):
            flag = True
            check_list_items = []

        return phantom.APP_SUCCESS, flag, check_list_items

    def _perform_device_action(self, action_result, param):
        count = 0

        # Handle subtenant parameter
        subtenant = param.get(CROWDSTRIKE_CID)
        if subtenant:
            if subtenant == "main":
                subtenant = None
        else:
            # Find which tenant device belongs to
            id_tenant_map = self._get_ids_with_subtenants(action_result, CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT)
            if id_tenant_map is None:
                return action_result.get_status(phantom.APP_ERROR, "Device ID not found among any tenant")

            subtenant = id_tenant_map.get(param.get("device_id"))

        ret_val, list_ids = self._check_params(action_result, param, subtenant)

        if phantom.is_fail(ret_val):
            msg = action_result.get_message()
            if "Invalid filter expression supplied" in msg:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Error occurred while validating given input parameters. Error : {msg}",
                )
            return action_result.get_status()

        if not list_ids:
            return action_result.set_status(
                phantom.APP_ERROR,
                "No correct device IDs could be found for the provided input parameters values",
            )

        data = {}
        endpoint = None
        count = len(list_ids)

        action_name = param.get("action_name")
        params = {"action_name": action_name}

        if action_name == "contain" or action_name == "lift_containment":
            endpoint = CROWDSTRIKE_DEVICE_ACTION_ENDPOINT

            while list_ids:
                data = {"ids": list_ids[: min(100, len(list_ids))]}

                ret_val, response = self._make_rest_call_helper_oauth2(
                    action_result,
                    endpoint,
                    params=params,
                    data=json.dumps(data),
                    subtenant=subtenant,
                    method="post",
                )

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                if not response.get("resources"):
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        "No action could be performed on the provided devices",
                    )

                for device in response.get("resources"):
                    action_result.add_data(device)

                del list_ids[: min(100, len(list_ids))]

            summary = action_result.update_summary({})

            if action_name == "contain":
                summary["total_quarantined_device"] = action_result.get_data_size()
            elif action_name == "lift_containment":
                summary["total_unquarantined_device"] = action_result.get_data_size()

            return phantom.APP_SUCCESS

        elif action_name == "add-hosts" or action_name == "remove-hosts":
            endpoint = CROWDSTRIKE_GROUP_DEVICE_ACTION_ENDPOINT

            while list_ids:
                data = {
                    "action_parameters": [
                        {
                            "name": "filter",
                            "value": f"(device_id:{list_ids[: min(100, len(list_ids))]})",
                        }
                    ],
                    "ids": [param.get("host_group_id")],
                }

                ret_val, response = self._make_rest_call_helper_oauth2(
                    action_result,
                    endpoint,
                    params=params,
                    data=json.dumps(data),
                    method="post",
                )

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                del list_ids[: min(100, len(list_ids))]

            if not response.get("resources"):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "No action could be performed on the provided devices",
                )

            for device in response.get("resources"):
                action_result.add_data(device)

            summary = action_result.update_summary({})

            if action_name == "add-hosts":
                summary["total_assigned_device"] = count
            elif action_name == "remove-hosts":
                summary["total_removed_device"] = count

            return phantom.APP_SUCCESS

        else:
            return action_result.set_status(phantom.APP_ERROR, "Incorrect action name")

    def _handle_quarantine_device(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {k: param[k] for k in param.keys() if k in ["device_id", "hostname", "cid"]}

        params["action_name"] = "contain"

        ret_val = self._perform_device_action(action_result, params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Device quarantined successfully")

    def _handle_unquarantine_device(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {k: param[k] for k in param.keys() if k in ["device_id", "hostname", "cid"]}

        params["action_name"] = "lift_containment"

        ret_val = self._perform_device_action(action_result, params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Device unquarantined successfully")

    def _handle_assign_hosts(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {k: param[k] for k in param.keys() if k in ["device_id", "hostname", "host_group_id"]}

        params["action_name"] = "add-hosts"

        ret_val = self._perform_device_action(action_result, params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Host added successfully")

    def _handle_remove_hosts(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {k: param[k] for k in param.keys() if k in ["device_id", "hostname", "host_group_id"]}

        params["action_name"] = "remove-hosts"

        ret_val = self._perform_device_action(action_result, params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Host removed successfully")

    def _handle_create_ioa_rule(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            field_values = json.loads(param["field_values"])
        except json.JSONDecodeError as e:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to parse field_values: {e}")

        create_comment = param.get("comment")

        create_params = {
            "rulegroup_id": param["rule_group_id"],
            "name": param["name"],
            "description": param["description"],
            "pattern_severity": param["severity"],
            "ruletype_id": str(param["rule_type_id"]),
            "disposition_id": param["disposition_id"],
            "field_values": field_values,
        }
        if create_comment:
            create_params["comment"] = create_comment

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT,
            json_data=create_params,
            method="post",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        rulegroup_id = resp_json["resources"][0].get("rulegroup_id")
        rulegroup_version = resp_json["resources"][0].get("magic_cookie")
        rule_id = resp_json["resources"][0].get("instance_id")
        rule_version = resp_json["resources"][0].get("instance_version")
        if not (rulegroup_id and rulegroup_version and rule_id and rule_version):
            return action_result.set_status(
                phantom.APP_ERROR,
                "CrowdStrike failed to return a Rule Group ID/Version and Rule ID/Version",
            )

        if param.get("enabled", False):
            update_params = {
                "rulegroup_id": rulegroup_id,
                "rulegroup_version": rulegroup_version,
                "instance_version": rule_version,
                "comment": "Rule enabled via Splunk SOAR",
                "rule_updates": [
                    {
                        "instance_id": rule_id,
                        "name": param["name"],
                        "description": param["description"],
                        "enabled": True,
                        "pattern_severity": param["severity"],
                        "disposition_id": param["disposition_id"],
                        "field_values": field_values,
                    }
                ],
            }
            ret_val, update_resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT,
                json_data=update_params,
                method="patch",
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # For consistency, we need to find and return the updated rule
            for resource in update_resp_json["resources"]:
                for rule in resource["rules"]:
                    if rule["instance_id"] == rule_id:
                        resp_rule = rule
                        rule["rulegroup_id"] = rulegroup_id
                        resp_json["resources"] = [resp_rule]

        action_result.add_data(resp_json)

        action_result.update_summary({"rule_group_id": rulegroup_id, "rule_id": rule_id})

        return action_result.set_status(phantom.APP_SUCCESS, "Rule created successfully")

    def _handle_create_ioa_rule_group(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        create_params = {
            "name": param["name"],
            "description": param["description"],
            "platform": param["platform"],
        }
        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_IOA_CREATE_RULE_GROUP_ENDPOINT,
            json_data=create_params,
            method="post",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        rulegroup_id = resp_json["resources"][0].get("id")
        rulegroup_version = resp_json["resources"][0].get("version")
        if rulegroup_id is None or rulegroup_version is None:
            return action_result.set_status(
                phantom.APP_ERROR,
                "CrowdStrike failed to return a Rule Group ID and Version",
            )

        if param.get("enabled", False):
            update_params = {
                "id": rulegroup_id,
                "rulegroup_version": rulegroup_version,
                "name": param["name"],
                "description": param["description"],
                "enabled": True,
                "comment": "Rule Group enabled via Splunk SOAR",
            }
            ret_val, resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_IOA_CREATE_RULE_GROUP_ENDPOINT,
                json_data=update_params,
                method="patch",
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        policy_ids_str = param.get("policy_id", "")
        policy_ids_list = phantom.get_list_from_string(policy_ids_str)
        for policy_id in policy_ids_list:
            assign_params = {
                "action_parameters": [{"name": "rule_group_id", "value": rulegroup_id}],
                "ids": [policy_id],
            }
            assign_ret_val, assign_resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_UPDATE_PREVENTION_ACTIONS_ENDPOINT,
                params={"action_name": "add-rule-group"},
                json_data=assign_params,
                method="post",
            )

            if phantom.is_fail(assign_ret_val):
                return action_result.get_status()

        resp_json["resources"][0]["assigned_policy_ids"] = policy_ids_list
        action_result.add_data(resp_json)

        action_result.update_summary({"rule_group_id": rulegroup_id})

        return action_result.set_status(phantom.APP_SUCCESS, "Rule group created successfully")

    def _handle_create_session(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {
            "device_id": param["device_id"],
            "origin": "phantom",
            "queue_offline": param.get("queue_offline", False),  # default to False to maintain original behavior
        }

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_RTR_SESSION_ENDPOINT,
            json_data=params,
            method="post",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        summary = action_result.update_summary({})
        try:
            summary["session_id"] = resp_json["resources"][0]["session_id"]
        except Exception as ex:
            return action_result.set_status(
                phantom.APP_SUCCESS,
                "Session created successfully, but unable to find session_id from the response. "
                f"Unexpected response retrieved, {self._get_error_message_from_exception(ex)}",
            )

        return action_result.set_status(phantom.APP_SUCCESS, "Session created successfully")

    def _handle_delete_ioa_rule(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        group_id = param["rule_group_id"]
        ids_str = param["rule_id"]
        ids_list = phantom.get_list_from_string(ids_str)
        ids_param = ",".join(ids_list)
        params = {"rule_group_id": group_id, "ids": ids_param}
        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT,
            params=params,
            method="delete",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        resources_affected = resp_json["meta"]["writes"]["resources_affected"]
        action_result.update_summary({"resources_affected": resources_affected})

        return action_result.set_status(phantom.APP_SUCCESS, f"Deleted {resources_affected} rules")

    def _handle_delete_ioa_rule_group(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        ids_str = param["id"]
        ids_list = phantom.get_list_from_string(ids_str)
        ids_param = ",".join(ids_list)
        params = {"ids": ids_param}
        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_IOA_CREATE_RULE_GROUP_ENDPOINT,
            params=params,
            method="delete",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        resources_affected = resp_json["meta"]["writes"]["resources_affected"]
        action_result.update_summary({"resources_affected": resources_affected})

        return action_result.set_status(phantom.APP_SUCCESS, f"Deleted {resources_affected} rule groups")

    def _handle_delete_session(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {"session_id": param["session_id"]}

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_RTR_SESSION_ENDPOINT,
            params=params,
            method="delete",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        summary = action_result.update_summary({})
        summary["results"] = "Successfully removed session: {}".format(param["session_id"])

        return action_result.set_status(phantom.APP_SUCCESS, "Session ended successfully")

    def _handle_list_alerts(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        resp = self._check_data(action_result, param)

        if phantom.is_fail(resp):
            return action_result.get_status()

        params = {
            k: param[k]
            for k in param.keys()
            if k
            in [
                CROWDSTRIKE_FILTER,
                CROWDSTRIKE_LIMIT,
                CROWDSTRIKE_SORT,
                CROWDSTRIKE_INCLUDE_HIDDEN,
            ]
        }

        if "include_hidden" not in params:
            params["include_hidden"] = False

        alert_id_list = self._get_ids(action_result, CROWDSTRIKE_LIST_ALERTS_ENDPOINT, params)
        if alert_id_list is None:
            return action_result.get_status()

        alert_id_data = list()
        alert_id_data.extend(alert_id_list)
        params.update({"ids": alert_id_list})

        alert_details_list = self._get_details(
            action_result,
            CROWDSTRIKE_LIST_ALERT_DETAILS_ENDPOINT,
            params,
            method="post",
        )

        if alert_details_list is None:
            return action_result.get_status()

        alerts_sorted_list = list()
        test_details = dict()

        for data in alert_details_list:
            test_details.update({data["composite_id"]: data})

        for id in alert_id_data:
            try:
                if test_details[id] not in alerts_sorted_list:
                    alerts_sorted_list.append(test_details[id])
            except Exception as ex:
                self.debug_print(f"Error occurred while sorting the alert details, Error: {self._get_error_message_from_exception(ex)}")

        for alert in alerts_sorted_list:
            action_result.add_data(alert)

        summary = action_result.update_summary({})
        summary["total_alerts"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_detections(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {k: param[k] for k in param.keys() if k in [CROWDSTRIKE_FILTER, CROWDSTRIKE_LIMIT, CROWDSTRIKE_SORT]}

        resp = self._check_data(action_result, params)

        if phantom.is_fail(resp):
            return action_result.get_status()

        detection_id_list = self._get_ids(action_result, CROWDSTRIKE_LIST_DETECTIONS_ENDPOINT, params)
        if detection_id_list is None:
            return action_result.get_status()

        detection_id_data = list()
        detection_id_data.extend(detection_id_list)
        params.update({"ids": detection_id_list})

        detection_details_list = self._get_details(
            action_result,
            CROWDSTRIKE_LIST_DETECTIONS_DETAILS_ENDPOINT,
            params,
            method="post",
        )

        if detection_details_list is None:
            return action_result.get_status()

        detection_sorted_list = list()
        test_details = dict()

        for data in detection_details_list:
            test_details.update({data["detection_id"]: data})

        for detection_id in detection_id_data:
            try:
                if test_details[detection_id] not in detection_sorted_list:
                    detection_sorted_list.append(test_details[detection_id])
            except Exception as ex:
                self.debug_print(f"Error occurred while sorting the alert details, Error: {self._get_error_message_from_exception(ex)}")

        for detection in detection_sorted_list:
            action_result.add_data(detection)

        summary = action_result.update_summary({})
        summary["total_detections"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_epp_alerts(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {k: param[k] for k in param.keys() if k in [CROWDSTRIKE_FILTER, CROWDSTRIKE_LIMIT, CROWDSTRIKE_SORT]}

        base_filter = "product:'epp'"
        if "filter" in params:
            params["filter"] = f"{base_filter}+{params['filter']}"
        else:
            params["filter"] = base_filter

        resp = self._check_data(action_result, params)
        if phantom.is_fail(resp):
            return action_result.get_status()

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_LIST_ALERTS_ENDPOINT, params=params, method="get")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        composite_ids = response.get("resources", [])

        if not composite_ids:
            return action_result.set_status(phantom.APP_SUCCESS, "No alerts found")

        all_alerts = []

        # Batch size to 5000 (get alert details can take max of 5000, list alerts can return 10000)
        for i in range(0, len(composite_ids), 5000):
            batch = composite_ids[i : i + 5000]
            ret_val, response = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_GET_ALERT_DETAILS_ENDPOINT,
                json_data={"composite_ids": batch},
                method="post",
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            all_alerts.extend(response.get("resources", []))

        for alert in all_alerts:
            action_result.add_data(alert)

        summary = action_result.update_summary({})
        summary["total_alerts"] = len(all_alerts)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_detections_details(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        ids = self.validate_comma_seperated_values(param.get("detection_ids"))
        if not ids:
            return action_result.set_status(
                phantom.APP_ERROR,
                CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="detection_ids"),
            )

        data = {"ids": ids}

        detection_details_list = self._get_details(
            action_result,
            CROWDSTRIKE_LIST_DETECTIONS_DETAILS_ENDPOINT,
            data,
            method="post",
        )

        if detection_details_list is None:
            return action_result.get_status()

        for detection in detection_details_list:
            action_result.add_data(detection)

        summary = action_result.update_summary({})
        summary["total_detections"] = len(detection_details_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_epp_alerts_details(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        composite_ids = self.validate_comma_seperated_values(param.get(CROWDSTRIKE_ALERT_IDS))
        if not composite_ids:
            return action_result.set_status(
                phantom.APP_ERROR,
                CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key=CROWDSTRIKE_ALERT_IDS),
            )

        ret_val, response = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_GET_ALERT_DETAILS_ENDPOINT,
            json_data={"composite_ids": composite_ids},
            method="post",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        alert_details_list = response.get("resources", [])

        for alert in alert_details_list:
            action_result.add_data(alert)

        summary = action_result.update_summary({})
        summary["total_alerts"] = len(alert_details_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_detections(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        assigned_to_user = param.get("assigned_to_user")
        comment = param.get("comment")
        show_in_ui = param.get("show_in_ui", True)
        status = param.get("status")
        ids = self.validate_comma_seperated_values(param.get("detection_ids"))
        if not ids:
            return action_result.set_status(
                phantom.APP_ERROR,
                CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="detection_ids"),
            )

        data = {"ids": ids, "show_in_ui": show_in_ui}

        if assigned_to_user:
            data["assigned_to_uuid"] = assigned_to_user

        if comment:
            data["comment"] = comment

        if status:
            if status not in CROWDSTRIKE_DETECTION_STATUSES:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key="status"),
                )
            data["status"] = status

        ret_val, response = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_RESOLVE_DETECTION_APIPATH,
            json_data=data,
            method="patch",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        if response.get("meta", {}).get("writes", {}).get("resources_affected", 0) != len(ids):
            errors = [error.get("message") for error in response.get("errors", [])]
            return action_result.set_status(
                phantom.APP_ERROR,
                "Errors occurred while updating detections: {}".format("\r\n".join(errors)),
            )

        summary = action_result.update_summary({})
        summary["detections_affected"] = len(ids)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_epp_alerts(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        composite_ids = self.validate_comma_seperated_values(param.get(CROWDSTRIKE_ALERT_IDS))
        if not composite_ids:
            return action_result.set_status(
                phantom.APP_ERROR,
                CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key=CROWDSTRIKE_ALERT_IDS),
            )

        data = {"composite_ids": composite_ids, "action_parameters": []}

        show_in_ui = param.get(CROWDSTRIKE_SHOW_IN_UI)
        if show_in_ui is not None:
            data["action_parameters"].append({"name": "show_in_ui", "value": str(show_in_ui).lower()})

        status = param.get(CROWDSTRIKE_STATUS)
        if status:
            if status not in CROWDSTRIKE_EPP_ALERT_STATUSES:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    CROWDSTRIKE_ERROR_INVALID_ACTION_PARAM.format(key=CROWDSTRIKE_STATUS),
                )
            data["action_parameters"].append({"name": "update_status", "value": status})

        assigned_to_user = param.get(CROWDSTRIKE_ASSIGNED_TO_USER)
        unassign = param.get("unassign", False)

        if unassign:
            data["action_parameters"].append({"name": "unassign", "value": ""})
        elif assigned_to_user:
            if "@" in assigned_to_user:
                assign_action = "assign_to_user_id"
            elif len(assigned_to_user) == 36 and "-" in assigned_to_user:
                assign_action = "assign_to_uuid"
            else:
                assign_action = "assign_to_name"

            data["action_parameters"].append({"name": assign_action, "value": assigned_to_user})

        add_tags = param.get(CROWDSTRIKE_ADD_TAGS)
        if add_tags:
            tags = [tag.strip() for tag in add_tags.split(",")]
            for tag in tags:
                if tag:
                    data["action_parameters"].append({"name": "add_tag", "value": tag})

        remove_tags = param.get(CROWDSTRIKE_REMOVE_TAGS)
        if remove_tags:
            tags = [tag.strip() for tag in remove_tags.split(",")]
            for tag in tags:
                if tag:
                    data["action_parameters"].append({"name": "remove_tag", "value": tag})

        remove_tags_prefix = param.get(CROWDSTRIKE_REMOVE_TAGS_BY_PREFIX)
        if remove_tags_prefix:
            data["action_parameters"].append({"name": "remove_tags_by_prefix", "value": remove_tags_prefix.strip()})

        comment = param.get(CROWDSTRIKE_COMMENT)
        if comment:
            data["action_parameters"].append({"name": "append_comment", "value": comment})

        ret_val, response = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_UPDATE_ALERT_ENDPOINT,
            json_data=data,
            method="patch",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        resources_affected = response.get("meta", {}).get("writes", {}).get("resources_affected", 0)
        if resources_affected != len(composite_ids):
            errors = [error.get("message") for error in response.get("errors", [])]
            return action_result.set_status(
                phantom.APP_ERROR,
                "Errors occurred while updating alerts: {}".format("\r\n".join(errors)),
            )

        summary = action_result.update_summary({})
        summary["alerts_affected"] = resources_affected

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_ioa_platforms(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        # We'll paginate here, just to be future-proof, but we probably won't ever need it.
        # Default page size is 100, and there are currently only three supported platforms.
        params = {}
        total_rows = 0
        offset = -1
        results = []
        while offset < total_rows:
            if offset >= 0:
                params["offset"] = offset

            ret_val, resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_IOA_LIST_PLATFORMS_ENDPOINT,
                params=params,
                method="get",
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            results += resp_json["resources"]

            total_rows = resp_json["meta"]["pagination"]["total"]
            offset = resp_json["meta"]["pagination"]["offset"]

        resp_json["resources"] = results
        action_result.add_data(resp_json)

        action_result.update_summary({"result_count": total_rows})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_ioa_rule_groups(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}
        if "fql_query" in param:
            # CrowdStrike allows spaces in FQL queries, but not if they are URL-encoded.
            # So we strip them all.
            params["filter"] = param["fql_query"].replace(" ", "")

        total_rows = 0
        offset = -1
        results = []
        while offset < total_rows:
            if offset >= 0:
                params["offset"] = offset

            ret_val, resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_IOA_QUERY_RULE_GROUPS_ENDPOINT,
                params=params,
                method="get",
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            results += resp_json["resources"]

            total_rows = resp_json["meta"]["pagination"]["total"]
            offset = resp_json["meta"]["pagination"]["offset"]

        resp_json["resources"] = results
        action_result.add_data(resp_json)

        action_result.update_summary({"result_count": total_rows})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_ioa_severities(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        # We'll paginate here, just to be future-proof, but we probably won't ever need it.
        # Default page size is 100, and there are currently only five values.
        params = {}
        total_rows = 0
        offset = -1
        results = []
        while offset < total_rows:
            if offset >= 0:
                params["offset"] = offset

            ret_val, resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_IOA_LIST_SEVERITIES_ENDPOINT,
                params=params,
                method="get",
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            results += resp_json["resources"]

            total_rows = resp_json["meta"]["pagination"]["total"]
            offset = resp_json["meta"]["pagination"]["offset"]

        resp_json["resources"] = results
        action_result.add_data(resp_json)

        action_result.update_summary({"result_count": total_rows})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_ioa_types(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        platform_filter = param.get("platform")

        # We'll paginate here, just to be future-proof, but we probably won't ever need it.
        # Default page size is 100, and there are currently only a dozen values or so.
        params = {}
        total_rows = 0
        offset = -1
        results = []
        while offset < total_rows:
            if offset >= 0:
                params["offset"] = offset

            ret_val, resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_IOA_LIST_TYPES_ENDPOINT,
                params=params,
                method="get",
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            next_ret_val, next_resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_IOA_GET_TYPE_ENDPOINT,
                params={"ids": resp_json["resources"]},
                method="get",
            )

            if phantom.is_fail(next_ret_val):
                return action_result.get_status()

            for resource in next_resp_json["resources"]:
                resource["fields_pretty"] = json.dumps(resource["fields"], indent=2)

            if platform_filter:
                results += [resource for resource in next_resp_json["resources"] if resource["platform"] == platform_filter]
            else:
                results += next_resp_json["resources"]

            total_rows = resp_json["meta"]["pagination"]["total"]
            offset = resp_json["meta"]["pagination"]["offset"]

        resp_json["resources"] = results
        total_rows = len(results)
        resp_json["meta"]["pagination"]["total"] = total_rows
        action_result.add_data(resp_json)

        action_result.update_summary({"result_count": total_rows})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_sessions(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {k: param[k] for k in param.keys() if k in [CROWDSTRIKE_FILTER, CROWDSTRIKE_LIMIT, CROWDSTRIKE_SORT]}

        resp = self._check_data(action_result, params)

        if phantom.is_fail(resp):
            return action_result.get_status()
        session_id_list = self._get_ids(action_result, CROWDSTRIKE_GET_RTR_SESSION_ID_ENDPOINT, params)

        if session_id_list is None:
            return action_result.get_status()

        session_id_data = list()
        session_id_data.extend(session_id_list)
        params.update({"ids": session_id_list})

        session_details_list = self._get_details(
            action_result,
            CROWDSTRIKE_GET_RTR_SESSION_DETAILS_ENDPOINT,
            params,
            method="post",
        )

        if session_details_list is None:
            return action_result.get_status()

        sessions_sorted_list = list()
        test_details = dict()

        for data in session_details_list:
            test_details.update({data["id"]: data})

        for id in session_id_data:
            try:
                if test_details[id] not in sessions_sorted_list:
                    sessions_sorted_list.append(test_details[id])
            except Exception as ex:
                self.debug_print(f"Error occurred while sorting the session details, Error: {self._get_error_message_from_exception(ex)}")

        for session in sessions_sorted_list:
            action_result.add_data(session)

        summary = action_result.update_summary({})
        summary["total_sessions"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_command(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {
            "session_id": param["session_id"],
            "device_id": param["device_id"],
            "base_command": param["command"],
            "command_string": param["command"] + " " + param.get("data", ""),
        }

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_RUN_COMMAND_ENDPOINT,
            json_data=params,
            method="post",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            cloud_request_id = resp_json["resources"][0]["cloud_request_id"]
        except Exception as ex:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Error occurred while fetching the cloud_request_id "
                f"from the response. Unexpected response retrieved, {self._get_error_message_from_exception(ex)}",
            )

        summary = action_result.update_summary({})
        summary["cloud_request_id"] = cloud_request_id

        self._poll_for_command_results(action_result, cloud_request_id, endpoint=CROWDSTRIKE_RUN_COMMAND_ENDPOINT)

        return action_result.get_status()

    def _handle_run_admin_command(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {
            "session_id": param["session_id"],
            "device_id": param["device_id"],
            "base_command": param["command"],
            "command_string": param["command"] + " " + param.get("data", ""),
        }
        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_ADMIN_COMMAND_ENDPOINT,
            json_data=params,
            method="post",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            cloud_request_id = resp_json["resources"][0]["cloud_request_id"]
        except Exception as ex:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Error occurred while fetching the cloud_request_id from the response."
                f" Unexpected response retrieved, {self._get_error_message_from_exception(ex)}",
            )

        summary = action_result.update_summary({})
        summary["cloud_request_id"] = cloud_request_id

        self._poll_for_command_results(action_result, cloud_request_id, endpoint=CROWDSTRIKE_ADMIN_COMMAND_ENDPOINT)

        return action_result.get_status()

    def _handle_get_command_details(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        timeout = self._validate_integers(action_result, param.get("timeout_seconds", 60), "timeout_seconds")
        if timeout is None:
            return action_result.get_status()

        param["timeout"] = timeout

        summary = action_result.update_summary({})
        summary["results"] = "Successfully executed command"

        self._poll_for_command_results(action_result, param["cloud_request_id"], timeout=timeout)

        return action_result.get_status()

    def _poll_for_command_results(
        self,
        action_result,
        cloud_request_id,
        endpoint=CROWDSTRIKE_COMMAND_ACTION_ENDPOINT,
        timeout=60,
    ):
        # poll for results
        self.save_progress("Start poll for command results...")
        # 5 second wait per request
        timeout_segment_length = 5
        timeout_segments = timeout / timeout_segment_length

        count = 0
        while count < int(timeout_segments):
            count += 1
            sequence_id = 0
            params = {"cloud_request_id": cloud_request_id, "sequence_id": sequence_id}
            ret_val, resp_json = self._make_rest_call_helper_oauth2(action_result, endpoint, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # check if command has completed
            resources = resp_json.get("resources")
            if resources and len(resources):
                # if complete, grab all sequences
                if resources[0].get("complete", False):
                    while True:
                        self.save_progress(f"sequence: {sequence_id}")
                        params = {
                            "cloud_request_id": cloud_request_id,
                            "sequence_id": sequence_id,
                        }
                        ret_val, resp_json = self._make_rest_call_helper_oauth2(action_result, endpoint, params=params)

                        if phantom.is_fail(ret_val):
                            return action_result.get_status()

                        if (
                            resources[0].get("complete")
                            and resources[0].get("stderr") is not None
                            and resp_json.get("resources", [{}])[0].get("sequence_id")
                        ):
                            return action_result.set_status(
                                phantom.APP_ERROR,
                                "Errors occurred while executing command {}".format("\r\n".join(resources[0].get("stderr"))),
                            )

                        action_result.add_data(resp_json)
                        # if sequence_id is not present, break out
                        if not resp_json.get("resources", [{}])[0].get("sequence_id"):
                            return action_result.set_status(phantom.APP_SUCCESS)

                        # increment sequence_id
                        sequence_id += 1
            # if errors occurred while executing the command
            elif len(resp_json.get("errors", [])):
                errors = [err.get("message") for err in resp_json.get("errors")]
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Errors occurred while executing command: {}".format("\r\n".join(errors)),
                )

            # wait 5 seconds and try again
            time.sleep(timeout_segment_length)

        return action_result.set_status(
            phantom.APP_ERROR,
            'Timeout while waiting for command execution. Please use cloud_request_id and execute  "get command details" action.',
        )

    def _handle_list_session_files(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {"session_id": param["session_id"]}

        ret_val, resp_json = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_GET_RTR_FILES_ENDPOINT, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if len(resp_json.get("resources", [])) == 0:
            action_result.add_data(resp_json)
            return action_result.set_status(
                phantom.APP_SUCCESS,
                "No session files present for session ID {}".format(param["session_id"]),
            )

        action_result.add_data(resp_json)

        summary = action_result.update_summary({})
        summary["total_files"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS, "Session files listed successfully")

    def _handle_get_session_file(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {"session_id": param["session_id"], "sha256": param["file_hash"]}
        self._stream_file_data = True
        ret_val, vault_results = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_GET_EXTRACTED_RTR_FILE_ENDPOINT, params=params)

        if phantom.is_fail(ret_val) and CROWDSTRIKE_STATUS_CODE_MESSAGE in action_result.get_message():
            return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_NO_DATA_MESSAGE)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(vault_results)

        summary = action_result.update_summary({})
        summary["vault_id"] = vault_results.get("vault_id")

        return action_result.set_status(phantom.APP_SUCCESS, "Session file fetched successfully")

    def _handle_upload_put_file(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            file_id = param["vault_id"]
            success, message, file_info = phantom_rules.vault_info(vault_id=file_id)
            file_info = next(iter(file_info))
        except IndexError:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Vault file could not be found with supplied Vault ID",
            )
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Vault ID not valid: {self._get_error_message_from_exception(e)}",
            )

        multipart_data = MultipartEncoder(
            fields={
                "file": (file_info.get("name"), open(file_info.get("path"), "rb")),
                "description": param["description"],
                "name": param.get("file_name", ""),
                "comments_for_audit_log": param.get("comment", ""),
            }
        )

        headers = {"Content-Type": multipart_data.content_type}

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_RTR_ADMIN_PUT_FILES,
            headers=headers,
            data=multipart_data,
            method="post",
            upload_file=True,
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Put file uploaded successfully")

    def _handle_get_indicator(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        ioc_type = param.get(CROWDSTRIKE_SEARCH_IOCS_TYPE)
        if ioc_type:
            ioc_type = ioc_type.lower()
            if ioc_type not in ["sha256", "md5", "domain", "ipv4", "ipv6"]:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    CROWDSTRIKE_VALUE_LIST_MESSAGE_ERROR.format(CROWDSTRIKE_SEARCH_IOCS_TYPE),
                )
        ioc = param.get(CROWDSTRIKE_JSON_LIST_IOC)
        resource_id = param.get(CROWDSTRIKE_RESOURCE_ID)

        if not ioc_type and not ioc and not resource_id:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_MISSING_PARAMETER_MESSAGE_ERROR)

        if ioc_type and not ioc and not resource_id:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_MISSING_INDICATOR_VALUE_MESSAGE_ERROR)

        if ioc and not ioc_type and not resource_id:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_MISSING_INDICATOR_TYPE_MESSAGE_ERROR)

        params = {}
        if resource_id:
            params = {"ids": resource_id}
            ret_val, resp_json = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_GET_INDICATOR_ENDPOINT, params=params)
        else:
            params = {"filter": CROWDSTRIKE_FILTER_GET_CUSTOM_IOC.format(ioc_type, ioc)}
            ret_val, resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_GET_COMBINED_CUSTOM_INDICATORS_ENDPOINT,
                params=params,
            )

        if phantom.is_fail(ret_val) and "404" not in action_result.get_message():
            return action_result.get_status()

        if "404" not in action_result.get_message():
            for indicator_data in resp_json.get("resources", []):
                action_result.add_data(indicator_data)
        else:
            action_result.add_data(resp_json)

        if "404" in action_result.get_message() or len(resp_json.get("resources", [])) == 0:
            return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_GET_RESOURCE_NOT_FOUND)

        return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_SUCC_GET_ALERT)

    def _parse_resp_data(self, data):
        event = None
        try:
            event = json.loads(data)
        except Exception as e:
            self.debug_print(traceback.format_exc())
            self.debug_print(
                "Exception while parsing data: ",
                self._get_error_message_from_exception(e),
            )
            return (phantom.APP_ERROR, data)

        return (phantom.APP_SUCCESS, event)

    def _get_stream(self, action_result):
        # Progress
        self.save_progress(CROWDSTRIKE_USING_BASE_URL_ERROR, base_url=self._base_url_oauth)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._base_url_oauth)

        self._token = None
        self._data_feed_url = None

        ret_val, resp = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_BASE_ENDPOINT, params=self._parameters)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        meta = resp.get("meta")
        if not meta:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_META_KEY_EMPTY_ERROR)

        # Extract values that we require for other calls
        resources = resp.get("resources")
        if not resources:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_RESOURCES_KEY_EMPTY_ERROR)

        self._data_feed_url = resources[0].get("dataFeedURL")
        if not self._data_feed_url:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_DATAFEED_EMPTY_ERROR)

        session_token = resources[0].get("sessionToken")
        if not session_token:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_SESSION_TOKEN_NOT_FOUND_ERROR)

        self._token = session_token["token"]

        return phantom.APP_SUCCESS

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :return: integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    action_result.set_status(
                        phantom.APP_ERROR,
                        CROWDSTRIKE_VALIDATE_INTEGER_MESSAGE.format(key=key),
                    )
                    return None
                parameter = int(parameter)

            except Exception:
                action_result.set_status(
                    phantom.APP_ERROR,
                    CROWDSTRIKE_VALIDATE_INTEGER_MESSAGE.format(key=key),
                )
                return None

            if parameter < 0:
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Please provide a valid non-negative integer value in the {key} parameter",
                )
                return None
            if not allow_zero and parameter == 0:
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Please provide non-zero positive integer in {key}",
                )
                return None

        return parameter

    def _validate_on_poll_config_params(self, action_result, config):
        self.debug_print("Validating 'max_crlf' asset configuration parameter")
        max_crlf = self._validate_integers(
            action_result,
            config.get("max_crlf", DEFAULT_BLANK_LINES_ALLOWABLE_LIMIT),
            "max_crlf",
        )

        self.debug_print("Validating 'merge_time_interval' asset configuration parameter")
        merge_time_interval = self._validate_integers(
            action_result,
            config.get("merge_time_interval", 0),
            "merge_time_interval",
            allow_zero=True,
        )

        ingest_incidents = config.get("ingest_incidents", False)

        if self.is_poll_now():
            # Manual Poll Now
            try:
                self.debug_print("Validating 'max_events_poll_now' asset configuration parameter")
                max_events = self._validate_integers(
                    action_result,
                    config.get("max_events_poll_now", DEFAULT_POLLNOW_EVENTS_COUNT),
                    "max_events_poll_now",
                )
                self.debug_print("Validating 'max_incidents_poll_now' asset configuration parameter")
                max_incidents = self._validate_integers(
                    action_result, config.get("max_incidents_poll_now", DEFAULT_POLLNOW_INCIDENTS_COUNT), "max_incidents_poll_now"
                )
            except Exception as ex:
                self.debug_print("Error occurred while validating poll now parameters")
                error_messages_from_exception = self._get_error_message_from_exception(ex)
                max_events = f"{DEFAULT_POLLNOW_EVENTS_COUNT}: {error_messages_from_exception}"
                max_incidents = f"{DEFAULT_POLLNOW_INCIDENTS_COUNT}: {error_messages_from_exception}"
        else:
            # Scheduled and Interval Polling
            try:
                self.debug_print("Validating 'max_events' asset configuration parameter")
                max_events = self._validate_integers(action_result, config.get("max_events", DEFAULT_EVENTS_COUNT), "max_events")
                self.debug_print("Validating 'max_incidents' asset configuration parameter")
                max_incidents = self._validate_integers(action_result, config.get("max_incidents", DEFAULT_INCIDENTS_COUNT), "max_incidents")
            except Exception as ex:
                error_messages_from_exception = self._get_error_message_from_exception(ex)
                max_events = f"{DEFAULT_EVENTS_COUNT}: {error_messages_from_exception}"
                max_incidents = f"{DEFAULT_INCIDENTS_COUNT}: {error_messages_from_exception}"

        return max_crlf, merge_time_interval, max_events, max_incidents, ingest_incidents

    def _on_poll(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Connect to the server
        if phantom.is_fail(self._get_stream(action_result)):
            return action_result.get_status()

        if self._data_feed_url is None:
            return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_NO_MORE_FEEDS_AVAILABLE)

        config = self.get_config()

        max_crlf, merge_time_interval, max_events, max_incidents, ingest_incidents = self._validate_on_poll_config_params(action_result, config)

        if max_crlf is None or merge_time_interval is None or max_events is None:
            return action_result.get_status()

        # Handle detection events
        ret_val = self._poll_detection_events(action_result, param, config, max_crlf, max_events)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Handle incident ingestion if enabled
        if ingest_incidents:
            ret_val = self._poll_incidents(action_result, param, max_incidents)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _poll_detection_events(self, action_result, param, config, max_crlf, max_events):
        lower_id = 0
        if not self.is_poll_now():
            # we only mange the ids in case of on_poll on the interval
            # For POLL NOW always start on 0
            # lower_id = int(self._get_lower_id())
            try:
                self.debug_print("Fetching last_offset_id from the state file")
                lower_id = int(self._state.get("last_offset_id", 0))
            except Exception as ex:
                self.debug_print(
                    f"Error occurred while fetching last_offset_id from the state file, {self._get_error_message_from_exception(ex)}"
                )
                self.debug_print("Considering this run as first run")
                lower_id = 0

        # In case of invalid lower_id, set the lower_id offset to the starting point 0
        if lower_id < 0:
            lower_id = 0

        self.save_progress(CROWDSTRIKE_GETTING_EVENTS_MESSAGE.format(lower_id=lower_id, max_events=max_events))

        # Query for the events
        try:
            # Need to check both event types
            self._data_feed_url = self._data_feed_url + f"&offset={lower_id}&eventType=DetectionSummaryEvent,EppDetectionSummaryEvent"
            kwargs = {
                "headers": {
                    "Authorization": f"Token {self._token}",
                    "Connection": "Keep-Alive",
                },
                "stream": True,
            }
            r = requests.request("get", self._data_feed_url, **kwargs)
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                CROWDSTRIKE_CONNECTIVITY_ERROR,
                self._get_error_message_from_exception(e),
            )

        # Handle any errors
        if r.status_code != requests.codes.ok:  # pylint: disable=E1101
            resp_json = r.json()
            try:
                err_message = resp_json["errors"][0]["message"]
            except Exception as ex:
                err_message = "{}: {}".format("None", self._get_error_message_from_exception(ex))
            return action_result.set_status(
                phantom.APP_ERROR,
                CROWDSTRIKE_FROM_SERVER_ERROR,
                status=r.status_code,
                message=err_message,
            )

        # Parse the events
        counter = 0  # counter for continuous blank lines
        total_blank_lines_count = 0  # counter for total number of blank lines

        try:
            for stream_data in r.iter_lines(chunk_size=None):
                if stream_data is None:
                    # Done with all the event data for now
                    self.debug_print(CROWDSTRIKE_NO_DATA_MESSAGE)
                    self.save_progress(CROWDSTRIKE_NO_DATA_MESSAGE)
                    break

                if not stream_data.strip():
                    # increment counter for counting of the continuous as well as total blank lines
                    counter += 1
                    total_blank_lines_count += 1

                    if counter > max_crlf:
                        self.debug_print(CROWDSTRIKE_REACHED_CR_LF_COUNT_MESSAGE.format(counter))
                        self.save_progress(CROWDSTRIKE_REACHED_CR_LF_COUNT_MESSAGE.format(counter))
                        break
                    else:
                        self.debug_print(CROWDSTRIKE_RECEIVED_CR_LF_MESSAGE.format(counter))
                        self.save_progress(CROWDSTRIKE_RECEIVED_CR_LF_MESSAGE.format(counter))
                        continue

                ret_val, stream_data = self._parse_resp_data(stream_data)

                if phantom.is_fail(ret_val):
                    self.save_progress(
                        f"Failed to parse the stream_data. Find stream_data details in logs. Error Message: {action_result.get_status_message()}"
                    )
                    self.save_progress("Continuing with next event.")
                    self.debug_print(f"Failed to parse the stream_data: {stream_data}")
                    continue

                # Check for both event types
                if stream_data and stream_data.get("metadata", {}).get("eventType") in CROWDSTRIKE_EVENT_TYPES:
                    self._events.append(stream_data)
                    counter = 0  # reset the continuous blank lines counter as we received a valid data in between

                # Calculate length of DetectionSummaryEvents until now
                len_events = len(self._events)

                if max_events and len_events >= max_events:
                    self._events = self._events[:max_events]
                    break

                self.send_progress(CROWDSTRIKE_PULLED_EVENTS_MESSAGE.format(len(self._events)))
                self.debug_print(CROWDSTRIKE_PULLED_EVENTS_MESSAGE.format(len(self._events)))

        except Exception as e:
            err_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR,
                f"{CROWDSTRIKE_EVENTS_FETCH_ERROR}. Error response from server: {err_message}",
            )

        # Check if to collate the data or not
        collate = config.get("collate", True)

        self.send_progress(" ")

        self.debug_print(CROWDSTRIKE_BLANK_LINES_COUNT_MESSAGE.format(total_blank_lines_count))
        self.save_progress(CROWDSTRIKE_BLANK_LINES_COUNT_MESSAGE.format(total_blank_lines_count))
        self.debug_print(CROWDSTRIKE_GOT_EVENTS_MESSAGE.format(len(self._events)))  # total events count
        self.save_progress(CROWDSTRIKE_GOT_EVENTS_MESSAGE.format(len(self._events)))

        if self._events:
            # Update messages to reference both event types
            self.send_progress("Parsing the fetched Detection Events...")
            results = events_parser.parse_events(self._events, self, collate)
            self.save_progress(f"Created {len(results)} relevant results from the fetched Detection Events")
            if results:
                self.save_progress(
                    "Adding {} event artifact{}. Empty containers will be skipped.".format(len(results), "s" if len(results) > 1 else "")
                )
                self._save_results(results, param)
                self.send_progress("Done")
            if not self.is_poll_now():
                last_event = self._events[-1]
                last_offset_id = last_event["metadata"]["offset"]
                self._state["last_offset_id"] = last_offset_id + 1

        return phantom.APP_SUCCESS

    def _poll_incidents(self, action_result, param, max_incidents):
        self.save_progress("Starting incident ingestion...")
        try:
            # Get incidents
            params = {"limit": max_incidents, "sort": "modified_timestamp.asc"}

            if not self.is_poll_now():
                try:
                    # Track timestamps to ensure ingesting new incidents
                    last_ingestion_time = self._state.get("last_incident_timestamp", "")
                    params["filter"] = f"modified_timestamp:>'{last_ingestion_time}'"
                except Exception as e:
                    self.debug_print(f"Error getting last incident timestamp, starting from epoch: {e!s}")

            self.send_progress(f"Fetching incidents with filter: {params}")

            # Get incident IDs
            incident_ids = self._get_ids(action_result, CROWDSTRIKE_LIST_INCIDENTS_ENDPOINT, params)
            if incident_ids is None:
                return action_result.get_status()

            if not incident_ids:
                self.save_progress("No incidents found")
                return phantom.APP_SUCCESS

            # Get incident details
            ret_val, response = self._make_rest_call_helper_oauth2(
                action_result, CROWDSTRIKE_GET_INCIDENT_DETAILS_ID_ENDPOINT, json_data={"ids": incident_ids}, method="post"
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            incidents = response.get("resources", [])

            if incidents:
                # Update timestamp for next poll if not poll_now
                if not self.is_poll_now():
                    latest_timestamp = max(incident.get("modified_timestamp", 0) for incident in incidents)
                    self._state["last_incident_timestamp"] = latest_timestamp

                # Process incidents through parser
                self.save_progress(f"Processing {len(incidents)} incidents...")
                incident_results = incidents_parser.process_incidents(incidents)
                self._save_results(incident_results, param, True)
                self.save_progress("Successfully processed incidents")
            else:
                self.save_progress("No incidents found in response")

            return phantom.APP_SUCCESS

        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.save_progress(f"Error ingesting incidents: {error_message}")
            return action_result.set_status(phantom.APP_ERROR, f"Error ingesting incidents: {error_message}")

    def _handle_list_processes(self, param):
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        ioc = param[CROWDSTRIKE_JSON_IOC]
        fdid = param[CROWDSTRIKE_GET_PROCESSES_RAN_ON_FALCON_DEVICE_ID]

        ret_val, ioc_type = self._get_ioc_type(ioc, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        limit = self._validate_integers(action_result, param.get("limit", 100), "limit")
        if limit is None:
            return action_result.get_status()

        api_data = {"type": ioc_type, "value": ioc, "device_id": fdid, "limit": limit}

        response = self._hunt_paginator(action_result, CROWDSTRIKE_GET_PROCESSES_RAN_ON_APIPATH, params=api_data)

        if response is None:
            return action_result.get_status()

        if not response:
            return action_result.set_status(
                phantom.APP_SUCCESS,
                "No resources found from the response for the list processes action",
            )

        for process_id in response:
            action_result.add_data({"falcon_process_id": process_id})

        action_result.set_summary({"process_count": len(response)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_time_string(self, days):
        expiry_date = datetime.now(pytz.utc) + timedelta(days=days)
        time_str = expiry_date.strftime(CROWDSTRIKE_TIME_FORMAT)

        return f"{time_str[:-2]}:{time_str[-2:]}"

    def _handle_upload_iocs(self, param):
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        # required parameters
        ioc = param[CROWDSTRIKE_JSON_IOC]
        action = param[CROWDSTRIKE_IOCS_ACTION]

        ret_val, ioc_type = self._get_ioc_type(ioc, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        platforms = [x.strip() for x in param[CROWDSTRIKE_IOCS_PLATFORMS].split(",")]
        platforms = list(filter(None, platforms))

        indicator = {
            CROWDSTRIKE_IOCS_ACTION: action,
            CROWDSTRIKE_IOCS_PLATFORMS: platforms,
            CROWDSTRIKE_IOCS_TYPE: ioc_type,
            CROWDSTRIKE_IOCS_VALUE: ioc,
        }
        api_data = {"indicators": [indicator]}

        # optional parameters
        if CROWDSTRIKE_IOCS_EXPIRATION in param:
            days = self._validate_integers(
                action_result,
                param.get(CROWDSTRIKE_IOCS_EXPIRATION),
                CROWDSTRIKE_IOCS_EXPIRATION,
            )
            if days is None:
                return action_result.get_status()

            indicator[CROWDSTRIKE_IOCS_EXPIRATION] = self._get_time_string(days)

        if CROWDSTRIKE_IOCS_SEVERITY in param:
            indicator[CROWDSTRIKE_IOCS_SEVERITY] = param.get(CROWDSTRIKE_IOCS_SEVERITY)

        if CROWDSTRIKE_IOCS_SOURCE in param:
            indicator[CROWDSTRIKE_IOCS_SOURCE] = param.get(CROWDSTRIKE_IOCS_SOURCE)

        if CROWDSTRIKE_IOCS_DESCRIPTION in param:
            indicator[CROWDSTRIKE_IOCS_DESCRIPTION] = param.get(CROWDSTRIKE_IOCS_DESCRIPTION)

        if CROWDSTRIKE_IOCS_TAGS in param:
            tags = [x.strip() for x in param.get(CROWDSTRIKE_IOCS_TAGS, "").split(",")]
            tags = list(filter(None, tags))
            indicator[CROWDSTRIKE_IOCS_TAGS] = tags

        if CROWDSTRIKE_IOCS_HOSTS in param:
            hosts = [x.strip() for x in param.get(CROWDSTRIKE_IOCS_HOSTS, "").split(",")]
            hosts = list(filter(None, hosts))
            indicator[CROWDSTRIKE_IOCS_HOSTS] = hosts
        else:
            indicator[CROWDSTRIKE_IOCS_ALL_HOSTS] = True

        if CROWDSTRIKE_IOCS_FILENAME in param:
            indicator[CROWDSTRIKE_IOCS_METADATA] = dict()
            indicator[CROWDSTRIKE_IOCS_METADATA][CROWDSTRIKE_IOCS_FILENAME] = param.get(CROWDSTRIKE_IOCS_FILENAME)
        ret_val, response = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
            json_data=api_data,
            method="post",
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for indicator_data in response.get("resources", []):
            action_result.add_data(indicator_data)

        return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_SUCC_POST_ALERT)

    def _handle_update_ioa_rule(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            field_values = json.loads(param["field_values"])
        except json.JSONDecodeError as e:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to parse field_values: {e}")

        update_params = {
            "rulegroup_id": param["rule_group_id"],
            "rulegroup_version": param["rule_group_version"],
            "instance_version": param["rule_version"],
            "rule_updates": [
                {
                    "instance_id": param["rule_id"],
                    "pattern_severity": param["severity"],
                    "enabled": param.get("enabled", False),
                    "name": param["name"],
                    "description": param["description"],
                    "disposition_id": param["disposition_id"],
                    "field_values": field_values,
                }
            ],
        }
        update_comment = param.get("comment")
        if update_comment:
            update_params["comment"] = update_comment

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_IOA_CREATE_RULE_ENDPOINT,
            json_data=update_params,
            method="patch",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        rulegroup_id = resp_json["resources"][0]["id"]
        rulegroup_version = 0
        rule_id = param["rule_id"]
        rule_version = 0

        for rule in resp_json["resources"][0]["rules"]:
            if rule["instance_id"] == rule_id:
                rulegroup_version = rule["magic_cookie"]
                rule_version = rule["instance_version"]

        action_result.add_data(resp_json)

        action_result.update_summary(
            {
                "rule_group_id": rulegroup_id,
                "rule_group_version": rulegroup_version,
                "rule_id": rule_id,
                "rule_version": rule_version,
            }
        )

        return action_result.set_status(phantom.APP_SUCCESS, "Rule updated successfully")

    def _handle_update_ioa_rule_group(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        update_params = {
            "id": param["id"],
            "rulegroup_version": param["version"],
            "name": param["name"],
            "description": param["description"],
            "enabled": param.get("enabled", False),
            "comment": param["comment"],
        }
        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_IOA_CREATE_RULE_GROUP_ENDPOINT,
            json_data=update_params,
            method="patch",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        rulegroup_id = resp_json["resources"][0]["id"]

        assign_policy_ids_str = param.get("assign_policy_id", "")
        assign_policy_ids_list = phantom.get_list_from_string(assign_policy_ids_str)
        for policy_id in assign_policy_ids_list:
            assign_params = {
                "action_parameters": [{"name": "rule_group_id", "value": rulegroup_id}],
                "ids": [policy_id],
            }
            assign_ret_val, assign_resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_UPDATE_PREVENTION_ACTIONS_ENDPOINT,
                params={"action_name": "add-rule-group"},
                json_data=assign_params,
                method="post",
            )

            if phantom.is_fail(assign_ret_val):
                return action_result.get_status()

        remove_policy_ids_str = param.get("remove_policy_id", "")
        remove_policy_ids_list = phantom.get_list_from_string(remove_policy_ids_str)
        for policy_id in remove_policy_ids_list:
            remove_params = {
                "action_parameters": [{"name": "rule_group_id", "value": rulegroup_id}],
                "ids": [policy_id],
            }
            remove_ret_val, remove_resp_json = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_UPDATE_PREVENTION_ACTIONS_ENDPOINT,
                params={"action_name": "remove-rule-group"},
                json_data=remove_params,
                method="post",
            )

            if phantom.is_fail(remove_ret_val):
                return action_result.get_status()

        resp_json["resources"][0]["assigned_policy_ids"] = assign_policy_ids_list
        resp_json["resources"][0]["removed_policy_ids"] = remove_policy_ids_list
        action_result.add_data(resp_json)

        action_result.update_summary({"rule_group_id": rulegroup_id})

        return action_result.set_status(phantom.APP_SUCCESS, "Rule group updated successfully")

    def _handle_update_iocs(self, param):
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        ioc = param[CROWDSTRIKE_JSON_IOC]
        ret_val, ioc_type = self._get_ioc_type(ioc, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        update_data = {"filter": CROWDSTRIKE_FILTER_GET_IOC.format(ioc_type, ioc)}

        update_body = {"bulk_update": update_data}

        # optional parameters
        if CROWDSTRIKE_IOCS_ACTION in param:
            update_data[CROWDSTRIKE_IOCS_ACTION] = param.get(CROWDSTRIKE_IOCS_ACTION)

        if CROWDSTRIKE_IOCS_EXPIRATION in param:
            days = self._validate_integers(
                action_result,
                param.get(CROWDSTRIKE_IOCS_EXPIRATION),
                CROWDSTRIKE_IOCS_EXPIRATION,
            )
            if days is None:
                return action_result.get_status()

            update_data[CROWDSTRIKE_IOCS_EXPIRATION] = self._get_time_string(days)

        if CROWDSTRIKE_IOCS_SOURCE in param:
            update_data[CROWDSTRIKE_IOCS_SOURCE] = param.get(CROWDSTRIKE_IOCS_SOURCE)

        if CROWDSTRIKE_IOCS_SEVERITY in param:
            update_data[CROWDSTRIKE_IOCS_SEVERITY] = param.get(CROWDSTRIKE_IOCS_SEVERITY)

        if CROWDSTRIKE_IOCS_PLATFORMS in param:
            platforms = [x.strip() for x in param.get(CROWDSTRIKE_IOCS_PLATFORMS, "").split(",")]
            platforms = list(filter(None, platforms))
            update_data[CROWDSTRIKE_IOCS_PLATFORMS] = platforms

        if CROWDSTRIKE_IOCS_DESCRIPTION in param:
            update_data[CROWDSTRIKE_IOCS_DESCRIPTION] = param.get(CROWDSTRIKE_IOCS_DESCRIPTION)

        if CROWDSTRIKE_IOCS_TAGS in param:
            tags = [x.strip() for x in param.get(CROWDSTRIKE_IOCS_TAGS, "").split(",")]
            tags = list(filter(None, tags))
            update_data[CROWDSTRIKE_IOCS_TAGS] = tags

        if CROWDSTRIKE_IOCS_HOSTS in param:
            if param.get(CROWDSTRIKE_IOCS_HOSTS, "") == "all":
                update_data[CROWDSTRIKE_IOCS_ALL_HOSTS] = True
            else:
                hosts = [x.strip() for x in param.get(CROWDSTRIKE_IOCS_HOSTS, "").split(",")]
                hosts = list(filter(None, hosts))
                update_data[CROWDSTRIKE_IOCS_HOSTS] = hosts

        if CROWDSTRIKE_IOCS_FILENAME in param:
            update_data[CROWDSTRIKE_IOCS_METADATA] = dict()
            update_data[CROWDSTRIKE_IOCS_METADATA][CROWDSTRIKE_IOCS_FILENAME] = param.get(CROWDSTRIKE_IOCS_FILENAME)

        ret_val, _ = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
            json_data=update_body,
            method="patch",
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_SUCC_UPDATE_ALERT)

    def _handle_delete_iocs(self, param):
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        ioc = param.get(CROWDSTRIKE_JSON_IOC)
        resource_id = param.get(CROWDSTRIKE_RESOURCE_ID)

        if not ioc and not resource_id:
            return action_result.set_status(
                phantom.APP_ERROR,
                CROWDSTRIKE_MISSING_PARAMETER_MESSAGE_DELETE_IOC_ERROR,
            )

        if resource_id:
            api_data = {"ids": resource_id}
            ret_val, _ = self._make_rest_call_helper_oauth2(
                action_result,
                CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
                params=api_data,
                method="delete",
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_SUCC_DELETE_ALERT)

        ret_val, ioc_type = self._get_ioc_type(ioc, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        api_data = {"filter": CROWDSTRIKE_FILTER_GET_IOC.format(ioc_type, ioc)}

        ret_val, response = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_GET_CUSTOM_INDICATORS_ENDPOINT, params=api_data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        resource_id = None
        if "resources" in list(response.keys()):
            if response["resources"] is not None and len(response["resources"]) > 0:
                resource_id = response["resources"][0]
            else:
                return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_DELETE_RESOURCE_NOT_FOUND)
        else:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_DELETE_RESOURCE_NOT_FOUND)

        api_data = {"ids": resource_id}
        ret_val, _ = self._make_rest_call_helper_oauth2(
            action_result,
            CROWDSTRIKE_GET_INDICATOR_ENDPOINT,
            params=api_data,
            method="delete",
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, CROWDSTRIKE_SUCC_DELETE_ALERT)

    def _paginate_endpoint(self, action_result, resource_id_list, endpoint, param):
        id_list = list()
        id_list.extend(resource_id_list)
        resource_details_list = list()
        summary_data = action_result.update_summary({})
        while id_list:
            # Endpoint creation
            ids = id_list[: min(100, len(id_list))]
            endpoint_param = ""
            for resource in ids:
                endpoint_param += f"ids={resource}&"

            endpoint_param = endpoint_param.strip("&")

            endpoint = f"{endpoint}?{endpoint_param}"

            # Make REST call
            ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint)

            if phantom.is_fail(ret_val):
                self.debug_print(f"Error response returned from the API : {endpoint}")
                return action_result.get_status()

            if response.get("resources"):
                resource_details_list.extend(response.get("resources"))

            del id_list[: min(100, len(id_list))]

        if not resource_details_list:
            return action_result.set_status(phantom.APP_SUCCESS, "No data found")

        try:
            sort_criteria = param.get("sort")
            if sort_criteria is not None:
                sort_criteria = sort_criteria.lower()
                if sort_criteria == "verdict.asc":
                    resource_details_list = sorted(resource_details_list, key=lambda x: x["verdict"])
                if sort_criteria == "verdict.desc":
                    resource_details_list = sorted(resource_details_list, key=lambda x: x["verdict"], reverse=True)
                if sort_criteria == "created_timestamp.asc":
                    resource_details_list = sorted(resource_details_list, key=lambda x: x["created_timestamp"])
                if sort_criteria == "created_timestamp.desc":
                    resource_details_list = sorted(
                        resource_details_list,
                        key=lambda x: x["created_timestamp"],
                        reverse=True,
                    )
                if sort_criteria == "environment_description.asc":
                    resource_details_list = sorted(
                        resource_details_list,
                        key=lambda x: x["sandbox"][0]["environment_description"],
                    )
                if sort_criteria == "environment_description.desc":
                    resource_details_list = sorted(
                        resource_details_list,
                        key=lambda x: x["sandbox"][0]["environment_description"],
                        reverse=True,
                    )
                if sort_criteria == "threat_score.asc":
                    resource_details_list = sorted(
                        resource_details_list,
                        key=lambda x: x["sandbox"][0].get("threat_score", 0),
                    )
                if sort_criteria == "threat_score.desc":
                    resource_details_list = sorted(
                        resource_details_list,
                        key=lambda x: x["sandbox"][0].get("threat_score", 0),
                        reverse=True,
                    )
        except Exception as e:
            err_message = self._get_error_message_from_exception(e)
            self.debug_print(f"Error occurred while sorting the response : {err_message}")
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Error occurred while sorting the response : {err_message}",
            )

        for report in resource_details_list:
            action_result.add_data(report)

        if len(resource_details_list) == 1 and "verdict" in list(resource_details_list[0].keys()):
            summary_data["verdict"] = resource_details_list[0]["verdict"]
            summary_data["total_reports"] = len(resource_details_list)
        else:
            summary_data["total_reports"] = len(resource_details_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_file_reputation(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))
        if param.get("vault_id"):
            endpoint = CROWDSTRIKE_QUERY_FILE_ENDPOINT
            try:
                file_id = param.get("vault_id")
                _, _, file_info = phantom_rules.vault_info(vault_id=file_id)
                file_info = next(iter(file_info))
                file_hash = file_info["metadata"]["sha256"]
            except IndexError:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Vault file could not be found with supplied Vault ID",
                )
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Vault ID not valid: {self._get_error_message_from_exception(e)}",
                )
        elif param.get("sha256"):
            endpoint = CROWDSTRIKE_QUERY_REPORT_ENDPOINT
            file_hash = param.get("sha256")
        else:
            return action_result.set_status(phantom.APP_ERROR, "No Vault ID or SHA256 was provided")

        filter_query = f"sandbox.sha256:'{file_hash}'"

        max_limit = CROWDSTRIKE_FALCONX_API_LIMIT

        sort_data = [
            "created_timestamp.asc",
            "created_timestamp.desc",
            "threat_score.asc",
            "threat_score.desc",
        ]
        if param.get("sort") == "--":
            return action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid value in the 'sort' parameter",
            )

        custom_list = [
            "environment_description.asc",
            "environment_description.desc",
            "threat_score.asc",
            "threat_score.desc",
            "verdict.desc",
            "verdict.asc",
        ]

        param_dict = {"filter": filter_query}
        if "offset" in param:
            param_dict["offset"] = param.get("offset")
        if "limit" in param:
            param_dict["limit"] = param.get("limit")
        if "sort" in param:
            param_dict["sort"] = param.get("sort").lower()
        if param_dict.get("sort") in custom_list:
            del param_dict["sort"]

        resp = self._check_data(action_result, param_dict, max_limit, sort_data)

        if phantom.is_fail(resp):
            self.debug_print("Error occurred while checking the data")
            return action_result.get_status()

        resource_id_list = self._get_ids(action_result, endpoint, param_dict)

        if resource_id_list is None:
            return action_result.get_status()

        if not isinstance(resource_id_list, list):
            return action_result.set_status(phantom.APP_ERROR, "Unknown response retrieved")

        is_detail = param.get("detail_report", False)
        if is_detail:
            endpoint = CROWDSTRIKE_GET_FULL_REPORT_ENDPOINT
        else:
            endpoint = CROWDSTRIKE_GET_REPORT_SUMMARY_ENDPOINT

        return self._paginate_endpoint(action_result, resource_id_list, endpoint, param)

    def _handle_url_reputation(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Find for the example rest call query just for checking
        url = param["url"]
        if "https://" in url:
            url = url.replace("https://", "hxxps://")
        elif "http://" in url:
            url = url.replace("http://", "hxxp://")
        elif "ftp://" in url:
            url = url.replace("ftp://", "fxp://")

        filter_query = f"sandbox.submit_url.raw:'{url}'"

        # Define constant in consts file
        max_limit = CROWDSTRIKE_FALCONX_API_LIMIT

        sort_data = [
            "verdict.desc",
            "verdict.asc",
            "created_timestamp.asc",
            "created_timestamp.desc",
        ]
        if param.get("sort") == "--":
            return action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid value in the 'sort' parameter",
            )

        custom_list = [
            "environment_description.asc",
            "environment_description.desc",
            "threat_score.asc",
            "threat_score.desc",
        ]

        param_dict = {"filter": filter_query}
        if "offset" in param:
            param_dict["offset"] = param.get("offset")
        if "limit" in param:
            param_dict["limit"] = param.get("limit")
        if "sort" in param:
            param_dict["sort"] = param.get("sort").lower()
        if param_dict.get("sort") in custom_list:
            del param_dict["sort"]

        resp = self._check_data(action_result, param_dict, max_limit, sort_data)

        if phantom.is_fail(resp):
            self.debug_print("Error occurred while checking the data")
            return action_result.get_status()

        resource_id_list = self._get_ids(action_result, CROWDSTRIKE_QUERY_REPORT_ENDPOINT, param_dict)

        if resource_id_list is None:
            return action_result.get_status()

        if not isinstance(resource_id_list, list):
            return action_result.set_status(phantom.APP_ERROR, "Unknown response retrieved")

        is_detail = param.get("detail_report", False)
        if is_detail:
            endpoint = CROWDSTRIKE_GET_FULL_REPORT_ENDPOINT
        else:
            endpoint = CROWDSTRIKE_GET_REPORT_SUMMARY_ENDPOINT

        return self._paginate_endpoint(action_result, resource_id_list, endpoint, param)

    def _handle_download_report(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(param)))

        query_param = {"id": param["artifact_id"]}
        header = {"Accept-Encoding": "application/gzip"}
        ret_val, _ = self._make_rest_call_helper_oauth2(
            action_result,
            params=query_param,
            headers=header,
            endpoint=CROWDSTRIKE_DOWNLOAD_REPORT_ENDPOINT,
        )

        if phantom.is_fail(ret_val):
            self.debug_print("Error response returned from the API")
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Report downloaded successfully")

    def _handle_check_detonate_status(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))
        query_param = {"ids": param["resource_id"]}
        header = {"accept": "application/json"}

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result,
            params=query_param,
            headers=header,
            endpoint=CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT,
        )

        if phantom.is_fail(ret_val):
            self.debug_print("Error response returned from the API")
            return action_result.get_status()

        if not resp_json["resources"]:
            return action_result.set_status(phantom.APP_SUCCESS, "No data found")

        summary_data = action_result.update_summary({})
        try:
            if "state" in list(resp_json["resources"][0].keys()):
                summary_data["state"] = resp_json["resources"][0]["state"]
            else:
                summary_data["state"] = "No state found"

            action_result.add_data(resp_json["resources"][0])
        except Exception as e:
            err_message = self._get_error_message_from_exception(e)
            self.debug_print(f"Error occurred while parsing the response : {err_message}")
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Error occurred while parsing the response : {err_message}",
            )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_url(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param["url"]
        if "https://" in url:
            url = url.replace("https://", "hxxps://")
        elif "http://" in url:
            url = url.replace("http://", "hxxp://")
        elif "ftp://" in url:
            url = url.replace("ftp://", "fxp://")

        environment_param = param["environment"].lower()

        if environment_param not in list(CROWDSTRIKE_ENVIRONMENT_ID_DICT.keys()):
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid environment")

        filter_query = f"sandbox.submit_url.raw:'{url}'+sandbox.environment_id:'{CROWDSTRIKE_ENVIRONMENT_ID_DICT[environment_param]}'"

        max_limit = CROWDSTRIKE_FALCONX_API_LIMIT

        sort_data = [
            "verdict.desc",
            "verdict.asc",
            "created_timestamp.asc",
            "created_timestamp.desc",
        ]
        if param.get("sort") == "--":
            return action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid value in the 'sort' parameter",
            )

        custom_list = ["threat_score.asc", "threat_score.desc"]

        param_dict = {"filter": filter_query}
        if "offset" in param:
            param_dict["offset"] = param.get("offset")
        if "limit" in param:
            param_dict["limit"] = param.get("limit")
        if "sort" in param:
            param_dict["sort"] = param.get("sort").lower()
        if param_dict.get("sort") in custom_list:
            del param_dict["sort"]
        resp = self._check_data(action_result, param_dict, max_limit, sort_data)

        if phantom.is_fail(resp):
            self.debug_print("Error occurred while checking the data")
            return action_result.get_status()

        resource_id_list = self._get_ids(action_result, CROWDSTRIKE_QUERY_REPORT_ENDPOINT, param_dict)

        if resource_id_list is None:
            return action_result.get_status()

        if not isinstance(resource_id_list, list):
            return action_result.set_status(phantom.APP_ERROR, "Unknown response retrieved")

        if (not resource_id_list) and self._required_detonation:
            return self._submit_resource_for_detonation(action_result, param, url=param["url"])

        is_detail = param.get("detail_report", False)
        if is_detail:
            endpoint = CROWDSTRIKE_GET_FULL_REPORT_ENDPOINT
        else:
            endpoint = CROWDSTRIKE_GET_REPORT_SUMMARY_ENDPOINT

        return self._paginate_endpoint(action_result, resource_id_list, endpoint, param)

    def _handle_detonate_file(self, param):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            file_id = param["vault_id"]
            _, _, file_info = phantom_rules.vault_info(vault_id=file_id)
            file_info = next(iter(file_info))
            file_hash = file_info["metadata"]["sha256"]
        except IndexError:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Vault file could not be found with supplied Vault ID",
            )
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Vault ID not valid: {self._get_error_message_from_exception(e)}",
            )

        environment_param = param["environment"].lower()
        if environment_param not in list(CROWDSTRIKE_ENVIRONMENT_ID_DICT.keys()):
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid environment")

        filter_query = f"sandbox.sha256:'{file_hash}'+sandbox.environment_id:'{CROWDSTRIKE_ENVIRONMENT_ID_DICT[environment_param]}'"

        max_limit = CROWDSTRIKE_FALCONX_API_LIMIT

        sort_data = ["created_timestamp.asc", "created_timestamp.desc"]
        if param.get("sort") == "--":
            return action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid value in the 'sort' parameter",
            )

        custom_list = [
            "threat_score.asc",
            "threat_score.desc",
            "verdict.desc",
            "verdict.asc",
        ]

        param_dict = {"filter": filter_query}
        if "offset" in param:
            param_dict["offset"] = param.get("offset")
        if "limit" in param:
            param_dict["limit"] = param.get("limit")
        if "sort" in param:
            param_dict["sort"] = param.get("sort").lower()
        if param_dict.get("sort") in custom_list:
            del param_dict["sort"]

        resp = self._check_data(action_result, param_dict, max_limit, sort_data)

        if phantom.is_fail(resp):
            self.debug_print("Error occurred while checking the data")
            return action_result.get_status()

        resource_id_list = self._get_ids(action_result, CROWDSTRIKE_QUERY_FILE_ENDPOINT, param_dict)

        if resource_id_list is None:
            return action_result.get_status()

        if not isinstance(resource_id_list, list):
            return action_result.set_status(phantom.APP_ERROR, "Unknown response retrieved")

        if (not resource_id_list) and self._required_detonation:
            return self._upload_file(action_result, param, file_info=file_info)

        is_detail = param.get("detail_report", False)
        if is_detail:
            endpoint = CROWDSTRIKE_GET_FULL_REPORT_ENDPOINT
        else:
            endpoint = CROWDSTRIKE_GET_REPORT_SUMMARY_ENDPOINT

        return self._paginate_endpoint(action_result, resource_id_list, endpoint, param)

    def _upload_file(self, action_result, param, file_info=None):
        file_path = file_info["path"]
        file_name = file_info["name"]

        query_param = {
            "file_name": file_name,
            "is_confidential": param.get("is_confidential", True),
            "comment": param.get("comment"),
        }

        with open(file_path, "rb") as f:
            data = f.read()

        headers = {"Content-Type": "application/octet-stream"}

        ret_val, json_resp = self._make_rest_call_helper_oauth2(
            action_result,
            params=query_param,
            headers=headers,
            endpoint=CROWDSTRIKE_UPLOAD_FILE_ENDPOINT,
            data=data,
            method="post",
        )

        if phantom.is_fail(ret_val):
            self.debug_print(f"Error response returned from the API : {CROWDSTRIKE_UPLOAD_FILE_ENDPOINT}")
            return action_result.get_status()

        try:
            sha256 = json_resp["resources"][0]["sha256"]
        except Exception as e:
            err_message = self._get_error_message_from_exception(e)
            self.debug_print(f"Error while fetching sha256. Error: {err_message}")
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching sha256 for the file")

        return self._submit_resource_for_detonation(action_result, param, sha256=sha256)

    def _submit_resource_for_detonation(self, action_result, param, sha256=None, url=None):
        environment_id = param["environment"].lower()
        action_script = None
        if "action_script" in param:
            action_script = param.get("action_script").lower()

        # Checking environment id
        if environment_id not in list(CROWDSTRIKE_ENVIRONMENT_ID_DICT.keys()):
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid environment")

        # Checking action script
        action_script_list = [
            "default",
            "default_maxantievasion",
            "default_randomfiles",
            "default_randomtheme",
            "default_openie",
        ]
        if action_script is not None and action_script not in action_script_list:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid action script")

        user_tags = param.get("user_tags")
        tag_list = None
        if user_tags is not None:
            tag_list = [x.strip() for x in user_tags.split(",")]
            tag_list = list(filter(None, tag_list))

        json_payload = {
            "sandbox": [
                {
                    "environment_id": CROWDSTRIKE_ENVIRONMENT_ID_DICT[environment_id],
                    "enable_tor": param.get("enable_tor", False),
                }
            ]
        }

        # optional parameters
        if sha256 is not None:
            json_payload["sandbox"][0]["sha256"] = sha256
        if url is not None:
            json_payload["sandbox"][0]["url"] = url
        if "action_script" in param:
            json_payload["sandbox"][0]["action_script"] = param.get("action_script")
        if "command_line" in param:
            json_payload["sandbox"][0]["command_line"] = param.get("command_line")
        if "document_password" in param:
            json_payload["sandbox"][0]["document_password"] = param.get("document_password")
        if "submit_name" in param:
            json_payload["sandbox"][0]["submit_name"] = param.get("submit_name")
        if tag_list and "user_tags" in param:
            json_payload["user_tags"] = tag_list

        ret_val, json_resp = self._make_rest_call_helper_oauth2(
            action_result,
            json_data=json_payload,
            endpoint=CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT,
            method="post",
        )
        if phantom.is_fail(ret_val):
            self.debug_print(f"Error response returned from the API : {CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT}")
            return action_result.get_status()

        try:
            resource_id = json_resp["resources"][0]["id"]
        except Exception as e:
            err_message = self._get_error_message_from_exception(e)
            self.debug_print(f"Error occurred while fetching the resource id : {err_message}")
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Error occurred while fetching the resource id : {err_message}",
            )
        return self._poll_for_detonate_results(action_result, param, resource_id)

    def _poll_for_detonate_results(self, action_result, param, resource_id):
        counter = 0
        prev_resp = None
        while counter < self._poll_interval:
            query_param = {"ids": resource_id}
            ret_val, json_resp = self._make_rest_call_helper_oauth2(
                action_result,
                params=query_param,
                endpoint=CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT,
            )
            if phantom.is_fail(ret_val):
                self.debug_print(f"Error response returned from the API : {CROWDSTRIKE_DETONATE_RESOURCE_ENDPOINT}")
                return action_result.get_status()

            prev_resp = json_resp
            if (
                "resources" in json_resp
                and json_resp["resources"] is not None
                and len(json_resp["resources"]) > 0
                and "state" in json_resp["resources"][0]
                and json_resp["resources"][0]["state"] == "success"
            ):
                self.debug_print("Success status returned from the CrowdStrike Server")
                return self._get_resource_report(action_result, param, resource_id)

            if (
                "resources" in json_resp
                and json_resp["resources"] is not None
                and len(json_resp["resources"]) > 0
                and "state" in json_resp["resources"][0]
                and json_resp["resources"][0]["state"] not in ["success", "running"]
            ):
                self.debug_print("Error state returned from the CrowdStrike Server")
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"Analysis of the report failed for resource id : {resource_id}",
                )

            counter += 1
            time.sleep(60)

        try:
            if prev_resp and prev_resp["resources"]:
                action_result.add_data(prev_resp["resources"][0])
        except Exception as e:
            err_message = self._get_error_message_from_exception(e)
            self.debug_print(f"Error occurred while adding the response to action result : {err_message}")
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Error occurred while adding the response to action result : {err_message}",
            )

        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Timed out while waiting for the result. To know the status of submitted \
            sample please run the check status action with {resource_id} resource id.",
        )

    def _get_resource_report(self, action_result, param, resource_id):
        endpoint = CROWDSTRIKE_GET_REPORT_SUMMARY_ENDPOINT
        is_detail = param.get("detail_report", False)
        if is_detail:
            endpoint = CROWDSTRIKE_GET_FULL_REPORT_ENDPOINT

        summary_data = action_result.update_summary({})
        query_param = {"ids": resource_id}
        ret_val, json_resp = self._make_rest_call_helper_oauth2(action_result, params=query_param, endpoint=endpoint)
        if phantom.is_fail(ret_val):
            self.debug_print(f"Error response returned from the API : {endpoint}")
            return action_result.get_status()

        try:
            summary_data["verdict"] = json_resp["resources"][0]["verdict"]
            summary_data["total_reports"] = len(json_resp["resources"])
            action_result.add_data(json_resp["resources"][0])
        except Exception as e:
            err_message = self._get_error_message_from_exception(e)
            self.debug_print(f"Error occurred while parsing the response : {err_message}")
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Error occurred while parsing the response : {err_message}",
            )

        return action_result.set_status(phantom.APP_SUCCESS)

    def _process_empty_response(self, response, action_result):
        """This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code in CROWDSTRIKE_API_SUCC_CODES:
            return RetVal(phantom.APP_SUCCESS, f"Status code: {response.status_code}")

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR,
                CROWDSTRIKEOAUTH_EMPTY_RESPONSE_ERROR.format(code=response.status_code),
            ),
            None,
        )

    def _process_html_response(self, response, action_result):
        """This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        if status_code == 400:
            message = f"Status Code: {status_code}. Data from server:\n{CROWDSTRIKE_HTML_ERROR}\n"

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception as ex:
            error_text = f"Cannot parse error details, Error: {self._get_error_message_from_exception(ex)}"

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace("{", "{{").replace("}", "}}")

        if len(message) > 500:
            message = "Error occurred while connecting to the CrowdStrike server"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            err_message = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Unable to parse JSON response. Error: {err_message}",
                ),
                None,
            )

        try:
            if "resources" in list(resp_json.keys()):
                if "errors" in list(resp_json.keys()):
                    if (
                        (resp_json["resources"] is None or len(resp_json["resources"]) == 0)
                        and resp_json["errors"]
                        and len(resp_json["errors"]) != 0
                    ):
                        error_msg = ""
                        for error_data in resp_json["errors"]:
                            error_msg += "{} - {}, ".format(error_data["code"], error_data["message"])
                        self.debug_print("Error from server. Error details: {}".format(error_msg.strip(", ")))
                        return RetVal(
                            action_result.set_status(
                                phantom.APP_ERROR,
                                "Error from server. Error details: {}".format(error_msg.strip(", ")),
                            ),
                            None,
                        )
                    if resp_json["resources"] and len(resp_json["resources"]) != 0 and resp_json["errors"] and len(resp_json["errors"]) != 0:
                        error_msg = ""
                        for error_data in resp_json["errors"]:
                            error_msg += "{} - {}, ".format(error_data["code"], error_data["message"])
                        self.debug_print("Error from server. Error details: {}".format(error_msg.strip(", ")))
                        if resp_json["resources"][0].get("message"):
                            return RetVal(
                                action_result.set_status(
                                    phantom.APP_ERROR,
                                    "Error from server. Error details: {}, {}".format(
                                        error_msg.strip(", "),
                                        resp_json["resources"][0]["message"],
                                    ),
                                ),
                                None,
                            )
                        else:
                            return RetVal(
                                action_result.set_status(
                                    phantom.APP_SUCCESS,
                                    "Error from server. Error details: {}".format(error_msg.strip(", ")),
                                ),
                                resp_json,
                            )
        except Exception:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error occurred while processing error response from server",
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)
        error_message = response.text.replace("{", "{{").replace("}", "}}")
        message = f"Error from server. Status Code: {response.status_code} Data from server: {error_message}"

        # Show only error message if available
        if isinstance(resp_json.get("errors", []), list):
            msg = ""
            for error in resp_json.get("errors", []):
                msg = "{} {}".format(msg, error.get("message"))
            message = f"Error from server. Status Code: {response.status_code} Data from server: {msg}"
        else:
            message = f"Error from server. Status Code: {response.status_code}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_file_name(self, action_params, type, file_extension):
        """This function is used to generate the file name from the provided parameter.

        :param action_params: action parameters
        :param type: file type
        :param file extension: file extension
        :return: filename
        """

        filename = ""
        if type == "compress":
            filename = "{}.7z".format(action_params.get("file_name", action_params["file_hash"]))
        elif type == "csv":
            filename = "{}.csv".format(action_params.get("file_name", action_params["artifact_id"]))
        elif type == "json":
            filename = "{}.json".format(action_params.get("file_name", action_params["artifact_id"]))
        elif type == "plain":
            if file_extension == "pcap":
                filename = "{}.pcap".format(action_params.get("file_name", action_params["artifact_id"]))
            else:
                filename = "{}.zip".format(action_params.get("file_name", action_params["artifact_id"]))
        elif type == "png":
            filename = "{}.png".format(action_params.get("file_name", action_params["artifact_id"]))

        return filename

    def _process_compressed_file_response(self, response, action_result, type, file_extension=None):
        guid = uuid.uuid4()

        if hasattr(Vault, "get_vault_tmp_dir"):
            vault_tmp_dir = Vault.get_vault_tmp_dir().rstrip("/")
            local_dir = f"{vault_tmp_dir}/{guid}"
        else:
            local_dir = os.path.join(paths.PHANTOM_VAULT, "tmp", str(guid))

        self.save_progress(f"Using temp directory: {guid}")
        self.debug_print(f"Using temp directory: {guid}")

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unable to create temporary vault folder.",
                self._get_error_message_from_exception(e),
            )

        action_params = self.get_current_param()

        filename = self._get_file_name(action_params, type, file_extension)

        compressed_file_path = f"{local_dir}/{filename}"

        # Try to stream the response to a file
        if response.status_code == 200:
            try:
                compressed_file_path = UnicodeDammit(compressed_file_path).unicode_markup
                with open(compressed_file_path, "wb") as f:
                    if self._stream_file_data:
                        for chunk in response.iter_content(chunk_size=10 * 1024 * 1024):
                            f.write(chunk)
                    else:
                        f.write(response.content)
            except OSError as e:
                error_message = self._get_error_message_from_exception(e)
                if "File name too long" in error_message:
                    new_file_name = "ph_long_file_name_temp"
                    compressed_file_path = f"{local_dir}/{new_file_name}"
                    self.debug_print(f"Original filename : {filename}")
                    self.debug_print(f"Modified filename : {new_file_name}")
                    with open(compressed_file_path, "wb") as f:
                        if self._stream_file_data:
                            for chunk in response.iter_content(chunk_size=10 * 1024 * 1024):
                                f.write(chunk)
                        else:
                            f.write(response.content)
                else:
                    return RetVal(
                        action_result.set_status(
                            phantom.APP_ERROR,
                            f"Unable to write file to disk. Error: {self._get_error_message_from_exception(e)}",
                        ),
                        None,
                    )

            except Exception as e:
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR,
                        f"Unable to write file to disk. Error: {self._get_error_message_from_exception(e)}",
                    ),
                    None,
                )

            try:
                vault_results = phantom_rules.vault_add(
                    container=self.get_container_id(),
                    file_location=compressed_file_path,
                    file_name=filename,
                )
                if vault_results[0]:
                    try:
                        _, _, vault_result_information = phantom_rules.vault_info(
                            vault_id=vault_results[2],
                            container_id=self.get_container_id(),
                            file_name=filename,
                        )
                        if not vault_result_information:
                            vault_result_information = None
                            # If filename contains special characters, vault_info will return None when passing filename as argument,
                            # hence this call is executed
                            _, _, vault_info = phantom_rules.vault_info(
                                vault_id=vault_results[2],
                                container_id=self.get_container_id(),
                            )
                            if vault_info:
                                for vault_meta_info in vault_info:
                                    if vault_meta_info["name"] == filename:
                                        vault_result_information = [vault_meta_info]
                                        break
                        vault_info = next(iter(vault_result_information))
                    except IndexError:
                        return RetVal(
                            action_result.set_status(
                                phantom.APP_ERROR,
                                "Vault file could not be found with supplied Vault ID",
                            ),
                            None,
                        )
                    except Exception as e:
                        return RetVal(
                            action_result.set_status(
                                phantom.APP_ERROR,
                                f"Vault ID not valid: {self._get_error_message_from_exception(e)}",
                            ),
                            None,
                        )
                    return RetVal(phantom.APP_SUCCESS, vault_info)
            except Exception as e:
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR,
                        f"Unable to store file in Phantom Vault. Error: {self._get_error_message_from_exception(e)}",
                    ),
                    None,
                )

        # You should process the error returned in the json
        error_message = response.text.replace("{", "{{").replace("}", "}}")
        message = f"Error from server. Status Code: {response.status_code} Data from server: {error_message}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result, is_download=False):
        """This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": response.status_code})
            if not self._stream_file_data:
                action_result.add_debug_data({"r_text": response.text})
            action_result.add_debug_data({"r_headers": response.headers})

        # Reset_password returns empty body
        if not self._stream_file_data and not response.text and 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, {})

        if is_download:
            if "csv" in response.headers.get("Content-Type", ""):
                return self._process_compressed_file_response(response, action_result, "csv")

            if "plain" in response.headers.get("Content-Type", ""):
                if "pcap" in response.headers.get("Content-Disposition", ""):
                    return self._process_compressed_file_response(response, action_result, "plain", file_extension="pcap")
                return self._process_compressed_file_response(response, action_result, "plain", file_extension="zip")

            if "png" in response.headers.get("Content-Type", ""):
                return self._process_compressed_file_response(response, action_result, "png")

        # Process each 'Content-Type' of response separately
        if "x-7z-compressed" in response.headers.get("Content-Type", ""):
            return self._process_compressed_file_response(response, action_result, "compress")

        # Process a json response
        if "json" in response.headers.get("Content-Type", ""):
            if is_download:
                return self._process_compressed_file_response(response, action_result, "json")
            return self._process_json_response(response, action_result)

        if "text/javascript" in response.headers.get("Content-Type", ""):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in response.headers.get("Content-Type", ""):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        error_message = response.text.replace("{", "{{").replace("}", "}}")
        message = f"Can't process response from server. Status Code: {response.status_code} Data from server: {error_message}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call_oauth2(
        self,
        endpoint,
        action_result,
        headers=None,
        params=None,
        data=None,
        json=None,
        method="get",
    ):
        """Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            kwargs = {
                "json": json,
                "data": data,
                "headers": headers,
                "params": params,
                "stream": self._stream_file_data,
            }
            r = requests.request(method, endpoint, **kwargs)
        except Exception as e:
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Error connecting to server. Details: {self._get_error_message_from_exception(e)}",
                ),
                resp_json,
            )

        is_download = False
        if CROWDSTRIKE_DOWNLOAD_REPORT_ENDPOINT in endpoint:
            is_download = True
        return self._process_response(r, action_result, is_download)

    def _make_rest_call_helper_oauth2(
        self,
        action_result,
        endpoint,
        headers=None,
        params=None,
        data=None,
        json_data=None,
        subtenant=None,
        method="get",
        upload_file=False,
    ):
        """Function that helps setting REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param subtenant: Optional subtenant dictionary with name and CID
        :param upload_file: Boolean to check if the file is being uploaded (needed for token refresh)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        url = f"{self._base_url_oauth}{endpoint}"
        if headers is None:
            headers = {}

        if subtenant and subtenant == "main":  # Main tenant is not a valid subtenant
            subtenant = None

        token_key = "oauth2_token{}".format(subtenant if subtenant else "")
        # Get new token if in old format
        if not isinstance(self._oauth_access_token, dict):
            self._get_token(action_result, member_cid=subtenant)

        token = self._oauth_access_token.get(token_key, {})

        # Get token if not present (or upload file because it needs a fresh token)
        if upload_file or not token.get("access_token"):
            ret_val = self._get_token(action_result, member_cid=subtenant)
            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR, None
            token = self._oauth_access_token[token_key]

        # Set Headers
        try:
            access_token = token.get("access_token")
            if access_token:
                headers.update({"Authorization": f"Bearer {access_token}"})
        except Exception as e:
            self.debug_print(f"Error handling token: {e!s}")
            return phantom.APP_ERROR, None

        if not headers.get("Content-Type"):
            headers["Content-Type"] = "application/json"

        ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, headers, params, data, json_data, method)

        # If token is expired, generate a new token
        msg = action_result.get_message()
        if (
            (msg and "token is invalid" in msg)
            or "token has expired" in msg
            or "ExpiredAuthenticationToken" in msg
            or "authorization failed" in msg
            or "access denied" in msg
        ):
            ret_val = self._get_token(action_result, member_cid=subtenant)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            action_result.set_status(phantom.APP_SUCCESS, "Successfully fetched access token")

            # Get the new token and update headers
            token = self._oauth_access_token[token_key]
            try:
                access_token = token.get("access_token")
                if access_token:
                    headers.update({"Authorization": f"Bearer {access_token}"})
            except Exception as e:
                self.debug_print(f"Error handling token: {e!s}")
                return phantom.APP_ERROR, None

            ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, headers, params, data, json_data, method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _get_token(self, action_result, member_cid=None):
        """This function is used to get a token via REST Call.

        :param action_result: Object of action result
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        data = {"client_id": self._client_id, "client_secret": self._client_secret}

        if member_cid:
            data["member_cid"] = member_cid

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        tenant_name = member_cid if member_cid else ""
        self.save_progress("_get_token for tenant {}".format(tenant_name if tenant_name else "current"))

        url = f"{self._base_url_oauth}{CROWDSTRIKE_OAUTH_TOKEN_ENDPOINT}"

        ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, headers=headers, data=data, method="post")

        token_key = "oauth2_token{}".format(member_cid if member_cid else "")

        if phantom.is_fail(ret_val):
            self._oauth_access_token.pop(token_key, None)
            return action_result.get_status()

        if not isinstance(self._oauth_access_token, dict):
            self._oauth_access_token = {}
        self._oauth_access_token[token_key] = resp_json
        return phantom.APP_SUCCESS

    def _get_fips_enabled(self):
        try:
            from phantom_common.install_info import is_fips_enabled
        except ImportError:
            return False

        fips_enabled = is_fips_enabled()
        if fips_enabled:
            self.debug_print("FIPS is enabled")
        else:
            self.debug_print("FIPS is not enabled")
        return fips_enabled

    def handle_action(self, param):
        # Get the action that we are supposed to execute for this App Run
        self.debug_print("action_id ", self.get_action_identifier())

        if self.get_action_identifier() == phantom.ACTION_ID_INGEST_ON_POLL:
            start_time = time.time()
            result = self._on_poll(param)
            end_time = time.time()
            diff_time = end_time - start_time
            human_time = str(timedelta(seconds=int(diff_time)))
            self.save_progress(f"Time taken: {human_time}")

            return result

        action_mapping = {
            "test_asset_connectivity": self._handle_test_connectivity,
            "run_query": self._handle_run_query,
            "query_device": self._handle_query_device,
            "list_groups": self._handle_list_groups,
            "quarantine_device": self._handle_quarantine_device,
            "unquarantine_device": self._handle_unquarantine_device,
            "remove_hosts": self._handle_remove_hosts,
            "assign_hosts": self._handle_assign_hosts,
            "create_session": self._handle_create_session,
            "delete_session": self._handle_delete_session,
            "list_alerts": self._handle_list_alerts,
            "list_epp_alerts": self._handle_list_epp_alerts,
            "list_detections": self._handle_list_detections,
            "get_detections_details": self._handle_get_detections_details,
            "get_epp_alerts_details": self._handle_get_epp_alerts_details,
            "update_detections": self._handle_update_detections,
            "update_epp_alerts": self._handle_update_epp_alerts,
            "list_sessions": self._handle_list_sessions,
            "run_command": self._handle_run_command,
            "run_admin_command": self._handle_run_admin_command,
            "get_command_details": self._handle_get_command_details,
            "list_session_files": self._handle_list_session_files,
            "get_session_file": self._handle_get_session_file,
            "upload_put_file": self._handle_upload_put_file,
            "get_indicator": self._handle_get_indicator,
            "list_custom_indicators": self._handle_list_custom_indicators,
            "list_put_files": self._handle_list_put_files,
            "hunt_file": self._handle_hunt_file,
            "hunt_domain": self._handle_hunt_domain,
            "hunt_ip": self._handle_hunt_ip,
            "get_process_detail": self._handle_get_process_detail,
            "get_device_detail": self._handle_get_device_detail,
            "resolve_detection": self._handle_resolve_detection,
            "resolve_epp_alerts": self._handle_resolve_epp_alerts,
            "list_incidents": self._handle_list_incidents,
            "list_incident_behaviors": self._handle_list_incident_behaviors,
            "get_incident_details": self._handle_get_incident_details,
            "get_incident_behaviors": self._handle_get_incident_behaviors,
            "list_crowdscores": self._handle_list_crowdscores,
            "update_incident": self._handle_update_incident,
            "list_users": self._handle_list_users,
            "get_user_roles": self._handle_get_user_roles,
            "list_roles": self._handle_list_roles,
            "get_role": self._handle_get_role,
            "list_processes": self._handle_list_processes,
            "upload_iocs": self._handle_upload_iocs,
            "delete_iocs": self._handle_delete_iocs,
            "update_iocs": self._handle_update_iocs,
            "file_reputation": self._handle_file_reputation,
            "url_reputation": self._handle_url_reputation,
            "download_report": self._handle_download_report,
            "detonate_file": self._handle_detonate_file,
            "detonate_url": self._handle_detonate_url,
            "check_detonate_status": self._handle_check_detonate_status,
            "get_device_scroll": self._handle_get_device_scroll,
            "get_zta_data": self._handle_get_zta_data,
            "create_ioa_rule_group": self._handle_create_ioa_rule_group,
            "update_ioa_rule_group": self._handle_update_ioa_rule_group,
            "delete_ioa_rule_group": self._handle_delete_ioa_rule_group,
            "list_ioa_rule_groups": self._handle_list_ioa_rule_groups,
            "list_ioa_platforms": self._handle_list_ioa_platforms,
            "list_ioa_severities": self._handle_list_ioa_severities,
            "list_ioa_types": self._handle_list_ioa_types,
            "create_ioa_rule": self._handle_create_ioa_rule,
            "update_ioa_rule": self._handle_update_ioa_rule,
            "delete_ioa_rule": self._handle_delete_ioa_rule,
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        action_keys = list(action_mapping.keys())
        if action in action_keys:
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status


if __name__ == "__main__":
    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        help="verify",
        required=False,
        default=False,
    )

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            r = requests.get(  # nosemgrep: python.requests.best-practice.use-timeout.use-timeout
                BaseConnector._get_phantom_base_url() + "login", verify=verify
            )
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = BaseConnector._get_phantom_base_url() + "login"

            print("Logging into Platform to get the session id")
            r2 = requests.post(  # nosemgrep: python.requests.best-practice.use-timeout.use-timeout
                BaseConnector._get_phantom_base_url() + "login",
                verify=verify,
                data=data,
                headers=headers,
            )
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CrowdstrikeConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
