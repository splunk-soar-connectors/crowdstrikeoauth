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

import ipaddress
import json
import re
import time

import requests
from bs4 import BeautifulSoup
from soar_sdk.logging import getLogger

from .consts import (
    CROWDSTRIKE_API_SUCC_CODES,
    CROWDSTRIKE_BASE_ENDPOINT,
    CROWDSTRIKE_COMMAND_ACTION_ENDPOINT,
    CROWDSTRIKE_CONNECTIVITY_ERROR,
    CROWDSTRIKE_DATAFEED_EMPTY_ERROR,
    CROWDSTRIKE_DEFAULT_TIMEOUT,
    CROWDSTRIKE_DEVICE_ACTION_ENDPOINT,
    CROWDSTRIKE_DOWNLOAD_REPORT_ENDPOINT,
    CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT,
    CROWDSTRIKE_GET_EXTRACTED_RTR_FILE_ENDPOINT,
    CROWDSTRIKE_GROUP_DEVICE_ACTION_ENDPOINT,
    CROWDSTRIKE_HTML_ERROR,
    CROWDSTRIKE_INVALID_DEVICE_ID_AND_HOSTNAME_ERROR,
    CROWDSTRIKE_INVALID_DEVICE_ID_ERROR,
    CROWDSTRIKE_INVALID_HOSTNAME_ERROR,
    CROWDSTRIKE_INVALID_INPUT_ERROR,
    CROWDSTRIKE_META_KEY_EMPTY_ERROR,
    CROWDSTRIKE_NO_PARAMETER_ERROR,
    CROWDSTRIKE_OAUTH_ACCESS_TOKEN_STRING,
    CROWDSTRIKE_OAUTH_TOKEN_ENDPOINT,
    CROWDSTRIKE_OAUTH_TOKEN_STRING,
    CROWDSTRIKE_RESOURCES_KEY_EMPTY_ERROR,
    CROWDSTRIKE_SESSION_TOKEN_NOT_FOUND_ERROR,
    CROWDSTRIKE_VALIDATE_INTEGER_MESSAGE,
    CROWDSTRIKEOAUTH_EMPTY_RESPONSE_ERROR,
)


logger = getLogger()

# Substrings that indicate the access token is no longer valid and must be refreshed.
TOKEN_INVALID_MARKERS = (
    "token is invalid",
    "token has expired",
    "ExpiredAuthenticationToken",
    "authorization failed",
    "access denied",
)


class CrowdStrikeClient:
    """Multi-tenant OAuth2 client-credentials client for the CrowdStrike OAuth API.

    Tokens are stored per tenant in ``asset.auth_state`` (encrypted by SOAR). The
    token dict is keyed by ``oauth2_token<member_cid>`` so the optional subtenant
    feature is preserved.
    """

    def __init__(self, asset):
        self.asset = asset
        self._base_url = asset.url.rstrip("/").replace("\\", "/")
        self._client_id = asset.client_id
        self._client_secret = asset.client_secret
        self._stream_file_data = False
        self._required_detonation = False
        self._tokens = self._load_tokens()

    # ------------------------------------------------------------------ #
    # Token state persistence
    # ------------------------------------------------------------------ #
    def _load_tokens(self) -> dict:
        state = dict(self.asset.auth_state.get_all())
        tokens = state.get(CROWDSTRIKE_OAUTH_TOKEN_STRING, {}).get(
            CROWDSTRIKE_OAUTH_ACCESS_TOKEN_STRING
        )
        if isinstance(tokens, dict):
            return dict(tokens)
        return {}

    def _save_tokens(self) -> None:
        state = dict(self.asset.auth_state.get_all())
        state[CROWDSTRIKE_OAUTH_TOKEN_STRING] = {
            CROWDSTRIKE_OAUTH_ACCESS_TOKEN_STRING: self._tokens
        }
        self.asset.auth_state.put_all(state)

    @staticmethod
    def _token_key(member_cid: str | None) -> str:
        return "oauth2_token{}".format(member_cid if member_cid else "")

    # ------------------------------------------------------------------ #
    # Token acquisition
    # ------------------------------------------------------------------ #
    def _get_token(self, member_cid: str | None = None) -> None:
        data = {"client_id": self._client_id, "client_secret": self._client_secret}
        if member_cid:
            data["member_cid"] = member_cid

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        url = f"{self._base_url}{CROWDSTRIKE_OAUTH_TOKEN_ENDPOINT}"
        token_key = self._token_key(member_cid)

        try:
            resp_json = self._make_rest_call(
                url, headers=headers, data=data, method="post"
            )
        except Exception:
            self._tokens.pop(token_key, None)
            self._save_tokens()
            raise

        self._tokens[token_key] = resp_json
        self._save_tokens()

    def access_token(self, subtenant: str | None = None) -> str | None:
        """Return the current OAuth access token for the given tenant, fetching one if needed."""
        if subtenant and subtenant == "main":
            subtenant = None
        token_key = self._token_key(subtenant)
        token = self._tokens.get(token_key, {})
        if not token.get("access_token"):
            self._get_token(member_cid=subtenant)
            token = self._tokens[token_key]
        return token.get("access_token")

    # ------------------------------------------------------------------ #
    # Streaming data feed (on_poll)
    # ------------------------------------------------------------------ #
    def get_datafeed(self, app_id: str, subtenant: str | None = None) -> dict:
        """Fetch the detection-event data feed descriptor.

        Returns a dict with keys: data_feed_url, token, refresh_url, refresh_interval.
        """
        params = {"appId": app_id.replace("-", "")}
        resp = self.make_rest_call(
            CROWDSTRIKE_BASE_ENDPOINT, params=params, subtenant=subtenant
        )

        if not resp.get("meta"):
            raise Exception(CROWDSTRIKE_META_KEY_EMPTY_ERROR)

        resources = resp.get("resources")
        if not resources:
            raise Exception(CROWDSTRIKE_RESOURCES_KEY_EMPTY_ERROR)

        data_feed_url = resources[0].get("dataFeedURL")
        if not data_feed_url:
            raise Exception(CROWDSTRIKE_DATAFEED_EMPTY_ERROR)

        session_token = resources[0].get("sessionToken")
        if not session_token:
            raise Exception(CROWDSTRIKE_SESSION_TOKEN_NOT_FOUND_ERROR)

        return {
            "data_feed_url": data_feed_url,
            "token": session_token["token"],
            "refresh_url": resources[0].get("refreshActiveSessionURL"),
            "refresh_interval": resources[0].get("refreshActiveSessionInterval", 1800),
        }

    @staticmethod
    def stream_datafeed(data_feed_url: str, token: str, lower_id: int):
        """Open the streaming detection-event feed. Returns the raw streaming response."""
        url = f"{data_feed_url}&offset={lower_id}&eventType=DetectionSummaryEvent,EppDetectionSummaryEvent"
        headers = {
            "Authorization": f"Token {token}",
            "Connection": "Keep-Alive",
        }
        try:
            return requests.request(
                "get", url, headers=headers, stream=True, timeout=(30, None)
            )
        except Exception as e:
            raise ConnectionError(
                f"{CROWDSTRIKE_CONNECTIVITY_ERROR}. Details: {e}"
            ) from e

    def refresh_datafeed_session(
        self, refresh_url: str, subtenant: str | None = None
    ) -> None:
        """Refresh an active streaming session using the OAuth bearer token."""
        access_token = self.access_token(subtenant)
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Connection": "Keep-Alive",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.make_rest_call(refresh_url, headers=headers, method="post", append=False)

    def stream_extracted_file(self, session_id: str, sha256: str):
        """Stream the RTR extracted-file-contents archive. Returns the raw streaming response."""
        access_token = self.access_token()
        headers = {"Authorization": f"Bearer {access_token}"}
        url = f"{self._base_url}{CROWDSTRIKE_GET_EXTRACTED_RTR_FILE_ENDPOINT}"
        params = {"session_id": session_id, "sha256": sha256}
        try:
            return requests.request(
                "get",
                url,
                headers=headers,
                params=params,
                stream=True,
                timeout=CROWDSTRIKE_DEFAULT_TIMEOUT,
            )
        except Exception as e:
            raise ConnectionError(f"Error connecting to server. Details: {e}") from e

    def stream_report_artifact(self, artifact_id: str):
        """Stream a detonation report artifact. Returns the raw streaming response."""
        access_token = self.access_token()
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept-Encoding": "application/gzip",
        }
        url = f"{self._base_url}{CROWDSTRIKE_DOWNLOAD_REPORT_ENDPOINT}"
        params = {"id": artifact_id}
        try:
            return requests.request(
                "get",
                url,
                headers=headers,
                params=params,
                stream=True,
                timeout=CROWDSTRIKE_DEFAULT_TIMEOUT,
            )
        except Exception as e:
            raise ConnectionError(f"Error connecting to server. Details: {e}") from e

    @staticmethod
    def parse_stream_event(data: str):
        """Parse a single streamed event line. Returns (ok, event_or_raw)."""
        try:
            return True, json.loads(data)
        except Exception:
            return False, data

    # ------------------------------------------------------------------ #
    # REST calls
    # ------------------------------------------------------------------ #
    def _make_rest_call(
        self,
        url: str,
        headers: dict | None = None,
        params: dict | None = None,
        data=None,
        json_data=None,
        method: str = "get",
    ):
        try:
            response = requests.request(
                method,
                url,
                json=json_data,
                data=data,
                headers=headers,
                params=params,
                stream=self._stream_file_data,
                timeout=CROWDSTRIKE_DEFAULT_TIMEOUT,
            )
        except Exception as e:
            raise ConnectionError(f"Error connecting to server. Details: {e}") from e

        is_download = CROWDSTRIKE_DOWNLOAD_REPORT_ENDPOINT in url
        return self._process_response(response, is_download)

    def make_rest_call(
        self,
        endpoint: str,
        headers: dict | None = None,
        params: dict | None = None,
        data=None,
        json_data=None,
        subtenant: str | None = None,
        method: str = "get",
        upload_file: bool = False,
        append: bool = True,
    ):
        url = f"{self._base_url}{endpoint}" if append else endpoint
        if headers is None:
            headers = {}

        if subtenant and subtenant == "main":
            subtenant = None

        token_key = self._token_key(subtenant)
        token = self._tokens.get(token_key, {})

        if upload_file or not token.get("access_token"):
            self._get_token(member_cid=subtenant)
            token = self._tokens[token_key]

        access_token = token.get("access_token")
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        if not headers.get("Content-Type"):
            headers["Content-Type"] = "application/json"

        try:
            return self._make_rest_call(url, headers, params, data, json_data, method)
        except Exception as e:
            message = str(e)
            if not any(marker in message for marker in TOKEN_INVALID_MARKERS):
                raise

        # Token rejected. Refresh and retry once.
        self._get_token(member_cid=subtenant)
        token = self._tokens[token_key]
        access_token = token.get("access_token")
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        return self._make_rest_call(url, headers, params, data, json_data, method)

    # ------------------------------------------------------------------ #
    # Response processing
    # ------------------------------------------------------------------ #
    def _process_response(self, response, is_download: bool = False):
        content_type = response.headers.get("Content-Type", "")

        if (
            not self._stream_file_data
            and not response.text
            and 200 <= response.status_code < 399
        ):
            return {}

        if "json" in content_type or "text/javascript" in content_type:
            return self._process_json_response(response)
        if "html" in content_type:
            return self._process_html_response(response)
        if not response.text:
            return self._process_empty_response(response)

        error_message = response.text.replace("{", "{{").replace("}", "}}")
        raise Exception(
            f"Can't process response from server. Status Code: {response.status_code} "
            f"Data from server: {error_message}"
        )

    def _process_empty_response(self, response):
        if response.status_code in CROWDSTRIKE_API_SUCC_CODES:
            return {}
        raise Exception(
            CROWDSTRIKEOAUTH_EMPTY_RESPONSE_ERROR.format(code=response.status_code)
        )

    def _process_html_response(self, response):
        status_code = response.status_code
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = [x.strip() for x in error_text.split("\n") if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = CROWDSTRIKE_HTML_ERROR

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"
        message = message.replace("{", "{{").replace("}", "}}")
        if len(message) > 500:
            message = "Error occurred while connecting to the CrowdStrike server"
        raise Exception(message)

    def _process_json_response(self, response):
        try:
            resp_json = response.json()
        except Exception as e:
            raise Exception(f"Unable to parse JSON response. Error: {e}") from e

        resources = resp_json.get("resources")
        errors = resp_json.get("errors")
        if "resources" in resp_json and "errors" in resp_json and errors:
            if not resources:
                error_msg = ", ".join(
                    "{} - {}".format(err.get("code"), err.get("message"))
                    for err in errors
                )
                raise Exception(f"Error from server. Error details: {error_msg}")
            if (
                resources
                and isinstance(resources, list)
                and resources[0].get("message")
            ):
                error_msg = ", ".join(
                    "{} - {}".format(err.get("code"), err.get("message"))
                    for err in errors
                )
                raise Exception(
                    "Error from server. Error details: {}, {}".format(
                        error_msg, resources[0]["message"]
                    )
                )

        if 200 <= response.status_code < 399:
            return resp_json

        msg = ""
        if isinstance(resp_json.get("errors", []), list):
            for error in resp_json.get("errors", []):
                msg = "{} {}".format(msg, error.get("message"))
            raise Exception(
                f"Error from server. Status Code: {response.status_code} Data from server: {msg}"
            )
        raise Exception(f"Error from server. Status Code: {response.status_code}")

    # ------------------------------------------------------------------ #
    # Pagination
    # ------------------------------------------------------------------ #
    def paginator(
        self,
        endpoint: str,
        param: dict | None = None,
        subtenant: str | None = None,
    ) -> list:
        if param is None:
            param = {}
        list_ids = []

        limit = None
        if param.get("limit"):
            limit = int(param.pop("limit"))
        offset = param.get("offset", 0)

        while True:
            param.update({"offset": offset})
            response = self.make_rest_call(endpoint, params=param, subtenant=subtenant)

            prev_offset = offset
            offset = response.get("meta", {}).get("pagination", {}).get("offset")
            if offset == prev_offset:
                offset += len(response.get("resources", []))

            total = response.get("meta", {}).get("pagination", {}).get("total")

            if response.get("errors"):
                error = response["errors"][0]
                raise Exception(
                    "Error occurred in results:\r\nCode: {}\r\nMessage: {}".format(
                        error.get("code"), error.get("message")
                    )
                )

            if offset is None or total is None:
                raise Exception(
                    "Error occurred in fetching 'offset' and 'total' key-values while fetching paginated results"
                )

            if response.get("resources"):
                list_ids.extend(response["resources"])

            if limit and len(list_ids) >= limit:
                return list_ids[:limit]

            if total == 0:
                self._required_detonation = True

            if offset >= total:
                return list_ids

    def hunt_paginator(
        self,
        endpoint: str,
        params: dict,
        search_subtenants: bool = False,
        subtenant: str | None = None,
    ) -> list:
        list_ids = []
        offset = ""
        limit = None
        if params.get("limit"):
            limit = params.pop("limit")

        subtenants = [None]
        if subtenant:
            subtenants = [None] if subtenant == "main" else [subtenant]
            search_subtenants = False

        if search_subtenants:
            configured = get_subtenants(self.asset, subtenant)
            if configured:
                subtenants.extend(configured)

        for sub in subtenants:
            while True:
                params.update({"offset": offset, "limit": 100})
                try:
                    response = self.make_rest_call(
                        endpoint, params=params, subtenant=sub
                    )
                except Exception as e:
                    if "Error details: 404" in str(e):
                        break
                    raise

                offset = response.get("meta", {}).get("pagination", {}).get("offset")

                if response.get("errors"):
                    error = response["errors"][0]
                    raise Exception(
                        "Error occurred in results:\r\nCode: {}\r\nMessage: {}".format(
                            error.get("code"), error.get("message")
                        )
                    )

                if response.get("resources"):
                    list_ids.extend(response["resources"])

                if limit and len(list_ids) >= limit:
                    return list_ids[:limit]

                if not offset and not response.get("meta", {}).get(
                    "pagination", {}
                ).get("next_page"):
                    break

        return list_ids

    # ------------------------------------------------------------------ #
    # Device ID resolution (multi-tenant)
    # ------------------------------------------------------------------ #
    def get_ids_with_subtenants(
        self, endpoint: str, param: dict | None = None, subtenant: str | None = None
    ):
        """Resolve IDs across tenants.

        When a subtenant is specified, returns a plain list of IDs for that tenant.
        Otherwise returns a dict mapping each ID to the tenant it was found in.
        """
        subtenants = [None]
        search_subtenants = True

        if subtenant:
            subtenants = [None] if subtenant == "main" else [subtenant]
            search_subtenants = False

        if search_subtenants:
            configured = get_subtenants(self.asset)
            if configured:
                subtenants.extend(configured)

        id_tenant_map = {}
        for tenant in subtenants:
            response = self.make_rest_call(endpoint, params=param, subtenant=tenant)
            ids = response.get("resources", [])
            if not ids:
                continue
            for device_id in ids:
                id_tenant_map[device_id] = tenant

        if search_subtenants:
            return id_tenant_map
        return list(id_tenant_map.keys())

    def _set_error_flag_inputs(
        self, list_items: list, key: str, subtenant: str | None = None
    ):
        """Resolve device IDs/hostnames to confirmed device IDs.

        Returns (flag, confirmed_ids). ``flag`` is True when some inputs could not
        be resolved (count mismatch), in which case ``confirmed_ids`` is empty.
        """
        filter_str = "".join(f"{key}: '{item}', " for item in list_items)
        filter_str = filter_str[:-2]

        check_items = self.get_ids_with_subtenants(
            CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT,
            param={"filter": filter_str},
            subtenant=subtenant,
        )

        if len(list_items) != len(check_items):
            return True, []
        return False, list(check_items)

    def check_device_params(self, param: dict, subtenant: str | None = None) -> list:
        """Validate and resolve device_id/hostname params into a device-ID list."""
        ids = []
        device_id = param.get("device_id", "")
        hostname = param.get("hostname")
        device_id_flag, hostname_flag = False, False
        intermediate_device_ids = []

        if not device_id and not hostname:
            raise ValueError(CROWDSTRIKE_NO_PARAMETER_ERROR)

        if device_id:
            device_ids = " ".join(x.strip() for x in device_id.split(",")).split()
            if not device_ids:
                raise ValueError(CROWDSTRIKE_INVALID_INPUT_ERROR)
            device_id_flag, interim = self._set_error_flag_inputs(
                device_ids, "device_id", subtenant
            )
            intermediate_device_ids.extend(interim)

        if hostname:
            hostnames = " ".join(x.strip() for x in hostname.split(",")).split()
            if not hostnames:
                raise ValueError(CROWDSTRIKE_INVALID_INPUT_ERROR)
            hostname_flag, interim = self._set_error_flag_inputs(
                hostnames, "hostname", subtenant
            )
            intermediate_device_ids.extend(interim)

        if device_id_flag and hostname_flag:
            raise ValueError(CROWDSTRIKE_INVALID_DEVICE_ID_AND_HOSTNAME_ERROR)
        if device_id_flag:
            raise ValueError(CROWDSTRIKE_INVALID_DEVICE_ID_ERROR)
        if hostname_flag:
            raise ValueError(CROWDSTRIKE_INVALID_HOSTNAME_ERROR)

        ids.extend(intermediate_device_ids)
        return list(set(ids))

    def paginate_get_endpoint(
        self, resource_id_list: list, endpoint: str, check_message: str | None = None
    ) -> list:
        """Fetch resource details by batching IDs as repeated query params (ids=x&ids=y)."""
        id_list = list(resource_id_list)
        resource_details_list: list = []
        while id_list:
            batch = id_list[: min(100, len(id_list))]
            endpoint_param = "&".join(f"ids={resource}" for resource in batch)
            batch_endpoint = f"{endpoint}?{endpoint_param}"

            try:
                response = self.make_rest_call(batch_endpoint)
            except Exception as e:
                if check_message and check_message in str(e):
                    response = {}
                else:
                    raise

            if response.get("resources"):
                resource_details_list.extend(response["resources"])

            del id_list[: min(100, len(id_list))]

        deduped: list = []
        for item in resource_details_list:
            if item not in deduped:
                deduped.append(item)
        return deduped

    def get_details(self, resource_id_list: list, endpoint: str) -> list:
        """Fetch resource details by batching IDs in a POST body ({"ids": batch})."""
        id_list = list(resource_id_list)
        resource_details_list: list = []
        while id_list:
            batch = id_list[: min(100, len(id_list))]
            response = self.make_rest_call(
                endpoint, json_data={"ids": batch}, method="post"
            )
            if response.get("resources"):
                resource_details_list.extend(response["resources"])
            del id_list[: min(100, len(id_list))]
        return resource_details_list

    def perform_device_action(self, param: dict) -> list:
        """Perform a contain / lift_containment device action.

        Returns the list of per-device result dicts from the CrowdStrike response.
        """
        subtenant = param.get("cid")
        if subtenant:
            if subtenant == "main":
                subtenant = None
        else:
            id_tenant_map = self.get_ids_with_subtenants(
                CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT
            )
            subtenant = id_tenant_map.get(param.get("device_id"))

        list_ids = self.check_device_params(param, subtenant)
        if not list_ids:
            raise ValueError(
                "No correct device IDs could be found for the provided input parameters values"
            )

        action_name = param.get("action_name")
        params = {"action_name": action_name}
        results = []

        if action_name in ("contain", "lift_containment"):
            while list_ids:
                batch = list_ids[: min(100, len(list_ids))]
                data = {"ids": batch}
                response = self.make_rest_call(
                    CROWDSTRIKE_DEVICE_ACTION_ENDPOINT,
                    params=params,
                    data=json.dumps(data),
                    subtenant=subtenant,
                    method="post",
                )
                if not response.get("resources"):
                    raise ValueError(
                        "No action could be performed on the provided devices"
                    )
                results.extend(response.get("resources"))
                del list_ids[: min(100, len(list_ids))]
            return results

        if action_name in ("add-hosts", "remove-hosts"):
            response = {}
            while list_ids:
                batch = list_ids[: min(100, len(list_ids))]
                data = {
                    "action_parameters": [
                        {"name": "filter", "value": f"(device_id:{batch})"}
                    ],
                    "ids": [param.get("host_group_id")],
                }
                response = self.make_rest_call(
                    CROWDSTRIKE_GROUP_DEVICE_ACTION_ENDPOINT,
                    params=params,
                    data=json.dumps(data),
                    method="post",
                )
                del list_ids[: min(100, len(list_ids))]

            if not response.get("resources"):
                raise ValueError("No action could be performed on the provided devices")
            results.extend(response.get("resources"))
            return results

        raise ValueError("Incorrect action name")

    def poll_command_results(
        self,
        cloud_request_id: str,
        endpoint: str = CROWDSTRIKE_COMMAND_ACTION_ENDPOINT,
        timeout: int = 60,
    ) -> list:
        """Poll for RTR command results. Returns the list of polled response dicts."""
        timeout_segment_length = 5
        timeout_segments = timeout / timeout_segment_length

        results: list = []
        count = 0
        while count < int(timeout_segments):
            count += 1
            sequence_id = 0
            params = {"cloud_request_id": cloud_request_id, "sequence_id": sequence_id}
            resp_json = self.make_rest_call(endpoint, params=params)

            resources = resp_json.get("resources")
            if resources and len(resources):
                if resources[0].get("complete", False):
                    while True:
                        params = {
                            "cloud_request_id": cloud_request_id,
                            "sequence_id": sequence_id,
                        }
                        resp_json = self.make_rest_call(endpoint, params=params)

                        if (
                            resources[0].get("complete")
                            and resources[0].get("stderr") is not None
                            and resp_json.get("resources", [{}])[0].get("sequence_id")
                        ):
                            raise Exception(
                                "Errors occurred while executing command {}".format(
                                    "\r\n".join(resources[0].get("stderr"))
                                )
                            )

                        results.append(resp_json)
                        if not resp_json.get("resources", [{}])[0].get("sequence_id"):
                            return results

                        sequence_id += 1
            elif len(resp_json.get("errors", [])):
                errors = [err.get("message") for err in resp_json.get("errors")]
                raise Exception(
                    "Errors occurred while executing command: {}".format(
                        "\r\n".join(errors)
                    )
                )

            time.sleep(timeout_segment_length)

        raise Exception(
            "Timeout while waiting for command execution. Please use cloud_request_id "
            'and execute  "get command details" action.'
        )


def validate_integer(value, key: str, allow_zero: bool = False) -> int | None:
    """Replicate the connector's _validate_integers. Returns int or raises ValueError."""
    if value is None:
        return None
    try:
        if not float(value).is_integer():
            raise ValueError(CROWDSTRIKE_VALIDATE_INTEGER_MESSAGE.format(key=key))
        value = int(value)
    except (TypeError, ValueError) as e:
        raise ValueError(CROWDSTRIKE_VALIDATE_INTEGER_MESSAGE.format(key=key)) from e

    if value < 0:
        raise ValueError(
            f"Please provide a valid non-negative integer value in the {key} parameter"
        )
    if not allow_zero and value == 0:
        raise ValueError(f"Please provide non-zero positive integer in {key}")
    return value


def get_subtenants(asset, cid: str | None = None) -> list:
    """Return the configured subtenant CID list from the asset config."""
    subtenants_config = asset.subtenants or ""
    subtenants = [x.strip() for x in subtenants_config.split(",") if x.strip()]
    if cid:
        if cid not in subtenants:
            raise ValueError(f"No subtenant found with CID {cid}")
        return [cid]
    return subtenants


def migrate_legacy_ingest_state(asset) -> None:
    """Seed SDK ingest state from the pre-SDK connector's flat checkpoint keys.

    The legacy BaseConnector app stored `last_offset_id` as a top-level key in the asset
    state file. The SDK keeps ingestion checkpoints in a separate encrypted partition, so
    upgrading in place would otherwise reset checkpoints and re-ingest everything. Only the
    main tenant had checkpoints pre-SDK, so this only migrates the non-subtenant key, and
    only until the SDK partition has its own value.
    """
    if "last_offset_id" in asset.ingest_state:
        return

    legacy_state = asset.ingest_state.backend.load_state() or {}

    if (legacy_offset_id := legacy_state.get("last_offset_id")) is not None:
        asset.ingest_state["last_offset_id"] = legacy_offset_id


def validate_comma_separated_values(values: str) -> list:
    return list({val.strip() for val in values.split(",") if val.strip()})


def serialize_complex_fields(resp: dict, fields: list[str]) -> dict:
    """Serialize complex fields (dict/list) to JSON strings for ActionOutput."""
    for field in fields:
        if field in resp and isinstance(resp[field], dict | list):
            resp[field] = json.dumps(resp[field])
    return resp


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _is_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def get_ioc_type(ioc: str) -> str:
    """Detect the IOC type for the given indicator value.

    Returns one of: ipv4, ipv6, md5, sha1, sha256, domain. Raises ValueError if
    the type cannot be detected.
    """
    if _is_ipv4(ioc):
        return "ipv4"
    if _is_ipv6(ioc):
        return "ipv6"

    if re.fullmatch(r"[0-9a-fA-F]{32}", ioc):
        return "md5"
    if re.fullmatch(r"[0-9a-fA-F]{40}", ioc):
        return "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{64}", ioc):
        return "sha256"

    if re.fullmatch(r"(?!-)[A-Za-z0-9_-]+(?<!-)(?:\.(?!-)[A-Za-z0-9_-]+(?<!-))*", ioc):
        return "domain"

    raise ValueError("Failed to detect the IOC type")
