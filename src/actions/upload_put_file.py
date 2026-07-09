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
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_RTR_ADMIN_PUT_FILES


class UploadPutFileParams(Params):
    vault_id: str = Param(
        description="Vault ID of file to upload",
        required=True,
        primary=True,
        cef_types=["vault id"],
        column_name="Vault ID",
    )
    description: str = Param(
        description="File description",
        required=True,
        column_name="Description",
    )
    file_name: str = Param(
        description="Filename to use (if different than actual file name)",
        required=False,
        primary=True,
        cef_types=["filename"],
    )
    comment: str = Param(
        description="Comment for the audit log",
        required=False,
    )


class UploadPutFileMeta(PermissiveActionOutput):
    powered_by: str | None = None
    query_time: float | None = None
    trace_id: str | None = None


class UploadPutFileOutput(PermissiveActionOutput):
    meta: UploadPutFileMeta | None = None


@app.action(
    description="Upload a new put-file to use for the RTR `put` command",
    action_type="generic",
    read_only=False,
    render_as="table",
)
def upload_put_file(
    params: UploadPutFileParams, soar: SOARClient, asset: Asset
) -> list[UploadPutFileOutput]:
    from requests_toolbelt.multipart.encoder import MultipartEncoder

    client = get_client(asset)

    attachments = soar.vault.get_attachment(vault_id=params.vault_id)
    if not attachments:
        raise ValueError("Vault file could not be found with supplied Vault ID")

    file_info = attachments[0]

    multipart_data = MultipartEncoder(
        fields={
            "file": (file_info.name, open(file_info.path, "rb")),  # noqa: SIM115
            "description": params.description,
            "name": params.file_name or "",
            "comments_for_audit_log": params.comment or "",
        }
    )

    headers = {"Content-Type": multipart_data.content_type}

    try:
        resp_json = client.make_rest_call(
            CROWDSTRIKE_RTR_ADMIN_PUT_FILES,
            headers=headers,
            data=multipart_data,
            method="post",
            upload_file=True,
        )
    except Exception as e:
        raise ActionFailure(str(e)) from e

    soar.set_message("Put file uploaded successfully")

    return [UploadPutFileOutput(**resp_json)]
