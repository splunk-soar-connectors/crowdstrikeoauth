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


class DownloadReportParams(Params):
    artifact_id: str = Param(
        description="Artifact ID to download",
        required=True,
        primary=True,
        cef_types=["crowdstrike artifact id"],
        column_name="Artifact ID",
    )
    file_name: str = Param(
        description="Filename to use for the downloaded artifact",
        required=False,
        primary=True,
        cef_types=["filename"],
        column_name="Filename",
    )


class DownloadReportOutput(PermissiveActionOutput):
    vault_id: str | None = OutputField(
        cef_types=["sha1", "vault id"], column_name="Vault ID"
    )
    name: str | None = OutputField(column_name="Name")
    size: int | None = None
    container_id: int | None = None


class DownloadReportSummary(ActionOutput):
    vault_id: str | None = OutputField(cef_types=["sha1", "vault id"])


def _artifact_extension(content_type: str, content_disposition: str) -> str:
    if "csv" in content_type:
        return "csv"
    if "plain" in content_type:
        return "pcap" if "pcap" in content_disposition else "zip"
    if "png" in content_type:
        return "png"
    if "json" in content_type:
        return "json"
    return "gz"


@app.action(
    name="download report",
    description="Download the report of a detonated file or URL",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=DownloadReportSummary,
)
def download_report(
    params: DownloadReportParams, soar: SOARClient, asset: Asset
) -> list[DownloadReportOutput]:
    client = get_client(asset)

    response = client.stream_report_artifact(params.artifact_id)

    if response.status_code != 200:
        soar.set_message("No report artifact found for the supplied artifact id")
        return []

    extension = _artifact_extension(
        response.headers.get("Content-Type", ""),
        response.headers.get("Content-Disposition", ""),
    )
    filename = f"{params.file_name or params.artifact_id}.{extension}"

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

    soar.set_summary(DownloadReportSummary(vault_id=attachment.vault_id))
    soar.set_message("Report downloaded successfully")

    return [
        DownloadReportOutput(
            vault_id=attachment.vault_id,
            name=attachment.name,
            size=attachment.size,
            container_id=attachment.container_id,
        )
    ]
