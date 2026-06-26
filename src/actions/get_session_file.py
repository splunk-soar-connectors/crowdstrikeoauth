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

import uuid
from pathlib import Path

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import CROWDSTRIKE_NO_DATA_MESSAGE


class GetSessionFileParams(Params):
    session_id: str = Param(
        description="RTR Session ID",
        required=True,
        primary=True,
        cef_types=["crowdstrike rtr session id"],
    )
    file_hash: str = Param(
        description="SHA256 hash to retrieve",
        required=True,
        primary=True,
        cef_types=["sha256"],
    )
    file_name: str = Param(
        description="Filename to use for the archive name and the file within the archive",
        required=False,
        primary=True,
        cef_types=["filename"],
    )


class GetSessionFileOutput(PermissiveActionOutput):
    vault_id: str | None = OutputField(
        cef_types=["sha1", "vault id"], column_name="Vault ID"
    )
    hash: str | None = OutputField(cef_types=["sha1"], column_name="Hash")
    name: str | None = None
    size: int | None = None
    container_id: int | None = None


class GetSessionFileSummary(ActionOutput):
    vault_id: str | None = OutputField(cef_types=["sha1", "vault id"])


@app.action(
    description="Get RTR extracted file contents for the specified session and sha256 and add it to the vault",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=GetSessionFileSummary,
)
def get_session_file(
    params: GetSessionFileParams, soar: SOARClient, asset: Asset
) -> list[GetSessionFileOutput]:
    client = get_client(asset)

    response = client.stream_extracted_file(params.session_id, params.file_hash)

    if response.status_code != 200:
        soar.set_message(CROWDSTRIKE_NO_DATA_MESSAGE)
        return []

    filename = f"{params.file_name or params.file_hash}.7z"

    vault_tmp_dir = Path(soar.vault.get_vault_tmp_dir())
    local_dir = vault_tmp_dir / str(uuid.uuid4())
    local_dir.mkdir(parents=True)
    file_path = local_dir / filename

    with open(file_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=10 * 1024 * 1024):
            f.write(chunk)

    container_id = soar.get_executing_container_id()
    vault_id = soar.vault.add_attachment(
        container_id=container_id,
        file_location=str(file_path),
        file_name=filename,
    )

    attachments = soar.vault.get_attachment(vault_id=vault_id)
    if not attachments:
        raise ValueError("Vault file could not be found with supplied Vault ID")

    attachment = attachments[0]

    soar.set_summary(GetSessionFileSummary(vault_id=attachment.vault_id))
    soar.set_message("Session file fetched successfully")

    return [
        GetSessionFileOutput(
            vault_id=attachment.vault_id,
            hash=attachment.hash,
            name=attachment.name,
            size=attachment.size,
            container_id=attachment.container_id,
        )
    ]
