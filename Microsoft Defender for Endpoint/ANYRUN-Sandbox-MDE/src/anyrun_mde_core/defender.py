from __future__ import annotations

import base64
import os
import json
import re
import time
from datetime import datetime, timedelta, timezone
from itertools import islice
from typing import Callable
from uuid import uuid4

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from azure.storage.blob import BlobServiceClient
from azure.storage.blob import BlobSasPermissions, generate_blob_sas
from anyrun import RunTimeException

from .config import Config
from .utils import (
    get_env_variable,
    generate_filepath,
    generate_ioc_comment,
    generate_task_uuid_comment,
    generate_analysis_summary_comment,
    sanitize_error_text,
)


LIVE_RESPONSE_PAYLOAD_VERSION = 'v2'


def batched(iterable, size):
    """Yield fixed-size tuples without requiring a particular Python minor version."""
    iterator = iter(iterable)
    while batch := tuple(islice(iterator, size)):
        yield batch


def encode_live_response_payload(
    upload_targets: list[dict[str, str]],
    storage_account_name: str,
    container_name: str,
) -> str:
    """Encode Live Response parameters using a shell-safe, versioned envelope."""
    values = [storage_account_name, container_name]
    for target in upload_targets:
        values.extend((target['filepath'], target['blob_name'], target['sas_token']))
    encoded_values = [
        base64.urlsafe_b64encode(value.encode('utf-8')).decode('ascii').rstrip('=')
        for value in values
    ]
    return '.'.join([LIVE_RESPONSE_PAYLOAD_VERSION, *encoded_values])


class MicrosoftDefender:
    """ Class - wrapper to interact with MS Defender REST API """
    def __init__(self, log, deadline_monotonic: float | None = None) -> None:
        self._headers = None
        self._token_expires_at = 0.0
        self._config = Config
        self._log = log
        self._deadline_monotonic = deadline_monotonic
        self.deduplicate_comments = False

        self._authenticate()

    def _authenticate(self):
        """
        Authenticates connector in MS Defender API
        """
        url = f"https://login.microsoftonline.com/{get_env_variable('AzureTenantID')}/oauth2/token"
        body = {
            'resource': self._config.DEFENDER_OAUTH_RESOURCE,
            'client_id': get_env_variable('AzureClientID'),
            'client_secret': get_env_variable('AzureClientSecret'),
            'grant_type': 'client_credentials',
        }
        response = self._make_request(
            method='POST',
            url=url,
            data=body,
            allow_reauthentication=False,
            authenticated=False,
        )

        if response.status_code >= 300:
            self._throw_error(
                f'Failed to authenticate at: {self._config.DEFENDER_OAUTH_RESOURCE}. Please, check your credentials.',
                response
            )

        self._headers = {
            'Authorization': f"Bearer {response.json().get('access_token')}",
            'Content-Type': 'application/json',
        }
        try:
            expires_in = int(response.json().get('expires_in', 3600))
        except (TypeError, ValueError):
            expires_in = 3600
        self._token_expires_at = time.monotonic() + max(60, expires_in - 120)

    def _generate_sas_token(self, blob_name: str) -> str:
        """
        Generates a short-lived, create-only SAS token for one destination blob.

        :return: SAS token
        """
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=30)

        try:
            sas_token = generate_blob_sas(
                account_name=get_env_variable('AzureStorageAccountName'),
                container_name=get_env_variable('AzureBlobContainerName'),
                blob_name=blob_name,
                account_key=get_env_variable('AzureStorageAccountKey'),
                permission=BlobSasPermissions(create=True),
                expiry=expiry_time,
            )
        except Exception as error:
            self._throw_error(
                'Failed to generate SAS token. Please, check your credentials. '
                f'Reason: {sanitize_error_text(error, limit=1000)}.'
            )

        return sas_token

    def get_evidences(self, alert_id: str, machine_os_platform: str) -> tuple[str, dict[str, list]]:
        """
        Retrieves File and URL evidences from the alert

        :param alert_id: Alert ID
        :param machine_os_platform: OS platform type
        :return: machine ID, evidences collection
        """
        url = f'{self._config.DEFENDER_API_BASE_URL}/api/alerts/{alert_id}'
        evidences: dict = {'urls': [], 'filenames': [], 'filepaths': []}

        response = self._make_request(method='GET', url=url)

        if response.status_code >= 300:
            self._throw_error(f'Failed to retrieve evidences for alert: {alert_id}.', response)

        if not (found_evidences := response.json().get('evidence')):
            self._throw_error(f'No evidences found in the alert: {alert_id}.')

        for evidence in found_evidences:
            if evidence.get('entityType') == 'File':
                evidences['filenames'].append(evidence.get('fileName'))
                evidences['filepaths'].append(
                    generate_filepath(evidence.get("filePath"), evidence.get("fileName"), machine_os_platform)
                )
            elif evidence.get('entityType') == 'Url':
                evidences['urls'].append(evidence.get('url'))
            else:
                self._log.warning(f'Received not supported evidence entity type: {evidence.get("entityType")}.')

        if not evidences.get('urls') and not evidences.get('filenames'):
            self._throw_error(f'No evidences of the type [File, Url] found in the alert: {alert_id}.')

        return response.json().get('machineId'), evidences

    def upload_ps_script_to_library(self, machine_os_platform: str) -> None:
        """
        Loads PowerShell script to the scripts library

        :param machine_os_platform: OS platform type
        """
        url = f'{self._config.DEFENDER_API_BASE_URL}/api/libraryfiles'

        if machine_os_platform == 'windows':
            script_name = self._config.PS_SCRIPT_NAME
        elif machine_os_platform == 'linux':
            script_name = self._config.BASH_SCRIPT_NAME

        script_path = os.path.join(os.path.dirname(__file__), script_name)

        with open(script_path) as script_file:
            script_content = script_file.read()

        def build_multipart() -> MultipartEncoder:
            return MultipartEncoder(
                fields={
                    'HasParameters': 'true',
                    'OverrideIfExists': 'true',
                    'Description': 'description',
                    'file': (script_name, script_content, 'text/plain'),
                }
            )

        response = self._make_request(
            method='POST',
            url=url,
            data=build_multipart(),
            retry_data_factory=build_multipart,
        )

        if response.status_code >= 300:
            self._throw_error(f'Failed to load PowerShell script to the library.', response)

    def execute_ps_script_on_machine(
        self,
        machine_id: str,
        machine_os_platform: str,
        files: list[tuple[str, str]],
        job_id: str,
    ) -> list[tuple[str, str]]:
        """
        Remotely executes PowerShell or Bash script on the target machine

        :param machine_id: Machine ID
        :param machine_os_platform: OS platform type
        :param files: Quarantine file paths paired with original file names
        :param job_id: Asynchronous job identifier
        :return: Original file names paired with their unique blob names
        """
        if not files:
            return []

        if machine_os_platform == 'windows':
            script_name = self._config.PS_SCRIPT_NAME
        elif machine_os_platform == 'linux':
            script_name = self._config.BASH_SCRIPT_NAME

        # Wait before minting the 30-minute SAS tokens so contention does not
        # consume most of their useful lifetime.
        self._wait_run_other_machine_actions(machine_id)

        safe_job_id = re.sub(r'[^A-Za-z0-9-]', '', job_id)[:64]
        upload_targets = []
        blob_targets = []
        for filepath, filename in files:
            extension = re.sub(r'[^A-Za-z0-9.]', '', os.path.splitext(filename)[1])[:16]
            blob_name = f'{safe_job_id}-{uuid4().hex}{extension}'
            upload_targets.append({
                'filepath': filepath,
                'blob_name': blob_name,
                'sas_token': self._generate_sas_token(blob_name),
            })
            blob_targets.append((filename, blob_name))

        payload = encode_live_response_payload(
            upload_targets=upload_targets,
            storage_account_name=get_env_variable('AzureStorageAccountName'),
            container_name=get_env_variable('AzureBlobContainerName'),
        )
        values = f'-payload {payload}'

        live_response_command = {
            'Commands': [
                {
                    'type': 'RunScript',
                    'params': [
                        {
                            'key': 'ScriptName',
                            'value': script_name,
                        },
                        {
                            'key': 'Args',
                            'value': values
                        }
                    ],
                }
            ],
            'Comment': 'Live response job to submit alerted evidences to the ANY.RUN BlobStorage.',
        }

        live_response_id = self._run_live_response(
            machine_id,
            live_response_command,
            wait_for_slot=False,
        )
        try:
            self._wait_run_script_live_response_job(live_response_id)
        except Exception:
            self.delete_files_from_storage([blob_name for _, blob_name in blob_targets])
            raise
        return blob_targets

    def _get_machine_actions(self, machine_id: str) -> list | None:
        """
        Retrieves machine actions info using machine ID

        :param machine_id: Machine ID
        :return: Machine actions list
        """
        url = f"{self._config.DEFENDER_API_BASE_URL}/api/machineactions?$filter=machineId+eq+'{machine_id}'"

        response = self._make_request(method='GET', url=url)

        if response.status_code >= 300:
            self._throw_error('Failed to get machine actions.', response)

        return response.json().get('value')

    def download_file_from_storage(self, filename: str) -> bytes | None:
        """
        Downloads file from the BlobStorage

        :param filename: Filename
        :return: File content
        """
        blob_service_client = BlobServiceClient.from_connection_string(get_env_variable('AzureStorageConnectionString'))
        container_client = blob_service_client.get_container_client(get_env_variable('AzureBlobContainerName'))

        try:
            file_data = container_client.get_blob_client(filename).download_blob().readall()
        except Exception as error:
            self._log.error(
                'Could not download evidence from Blob Storage: %s: %s',
                type(error).__name__,
                sanitize_error_text(error, limit=1000),
            )
            return None

        try:
            container_client.delete_blob(filename)
        except Exception:
            self._log.warning('Downloaded evidence blob %s but could not delete it.', filename)
        return file_data

    def delete_files_from_storage(self, blob_names: list[str]) -> None:
        """Best-effort cleanup for evidence uploaded before a failed RunScript."""
        if not blob_names:
            return
        try:
            blob_service_client = BlobServiceClient.from_connection_string(
                get_env_variable('AzureStorageConnectionString')
            )
            container_client = blob_service_client.get_container_client(
                get_env_variable('AzureBlobContainerName')
            )
            for blob_name in blob_names:
                try:
                    container_client.delete_blob(blob_name, delete_snapshots='include')
                except Exception:
                    self._log.warning(
                        'Could not clean up evidence blob %s after a failed Live Response action.',
                        blob_name,
                    )
        except Exception as error:
            self._log.error(
                'Could not initialize Blob Storage cleanup after Live Response failure: %s: %s',
                type(error).__name__,
                sanitize_error_text(error, limit=1000),
            )

    def download_file_from_machine(self, machine_id: str, filepath: str) -> bytes | None:
        """
        Downloads file from the target machine

        :param machine_id: Machine ID
        :param filepath: Filepath
        :return: File content
        """
        live_response_command = {
            'Commands': [
                {
                    'type': 'GetFile',
                    'params': [
                        {
                            'key': 'Path',
                            'value': filepath,
                        }
                    ],
                }
            ],
            'Comment': 'Live response job to submit alerted evidences to the ANY.RUN Sandbox.',
        }

        live_response_id = self._run_live_response(machine_id, live_response_command)

        if not (machine_action := self._wait_run_script_live_response_job(live_response_id)):
            return

        for command in machine_action.get('commands'):
            if command.get('command').get('type') == 'GetFile':
                file_url = self._get_file_download_link(command.get('index'), live_response_id)
                return self._download_file_by_link(file_url)

    def add_task_reference_comment(
        self,
        alert_id: str,
        evidence: str,
        task_uuid: str | None = None,
    ) -> None:
        """
        Adds task reference comment to alert

        :param alert_id: Alert ID
        :param evidence: Alert evidence
        :param task_uuid: Analysis uuid
        """
        comment = generate_task_uuid_comment(evidence, task_uuid)
        self.add_comment(alert_id, comment)

    def add_ioc_comment(
        self,
        alert_id: str,
        indicators: list[dict] | None = None
    ) -> None:
        """
        Adds found IOCs to alert

        :param alert_id: Alert ID
        :param indicators: List of indicators
        """
        sorted_indicators = sorted(
            [indicator for indicator in indicators],
            key=lambda indicator: indicator['reputation']
        )

        for chunk in batched(sorted_indicators, 10):
            comment = generate_ioc_comment(chunk)
            self.add_comment(alert_id, comment)

    def add_summary_comment(
        self,
        alert_id: str,
        evidence: str,
        analysis_verdict: str,
        report: dict
    ) -> None:
        """
        Adds summary comment to alert

        :param alert_id: Alert ID
        :param evidence: Alert Evidence
        :param analysis_verdict: Analysis Threat Level
        :param report: Analysis json summary
        """
        score = (
            report.get('data')
            .get('analysis')
            .get('scores')
            .get('verdict')
            .get('score')
        )
        task_url = (
            report.get('data')
            .get('analysis')
            .get('permanentUrl')
        )

        comment = generate_analysis_summary_comment(
            evidence,
            analysis_verdict,
            score,
            task_url
        )

        self.add_comment(alert_id, comment)


    def add_comment(self, alert_id: str, comment: str) -> None:
        """
        Adds comment to alert

        :param alert_id: Alert ID
        :param comment: Text comment
        """
        url = f'{self._config.DEFENDER_API_BASE_URL}/api/alerts/{alert_id}'
        if getattr(self, 'deduplicate_comments', False):
            existing = self._make_request('GET', url=url)
            if existing.status_code >= 300:
                self._throw_error('Failed to check existing alert comments.', existing)
            if any(item.get('comment') == comment for item in (existing.json().get('comments') or [])):
                return
        payload = {'comment': comment}

        response = self._make_request('PATCH', url=url, data=json.dumps(payload))

        if response.status_code >= 300:
            self._throw_error(f'Failed to update alert comment.', response)

    def _get_file_download_link(self, live_response_index: int, live_response_id: str) -> str:
        """
        Retrieves file download link

        :param live_response_index: Live response index
        :param live_response_id: Live response ID
        :return: File download link
        """
        url = (
            f'{self._config.DEFENDER_API_BASE_URL}/api/machineactions/{live_response_id}/'
           f'GetLiveResponseResultDownloadLink(index={live_response_index})'
        )

        response = self._make_request(method='GET', url=url)

        if response.status_code >= 300:
            self._throw_error(
                f'Failed to retrieve file download url. '
                f'Live response index: {live_response_index}. Live response ID: {live_response_id}.',
                response
            )

        return response.json().get('value')

    def _download_file_by_link(self, download_link) -> bytes | None:
        """
        Downloads file using download link

        :param download_link: File download link
        :return: File content
        """
        response = self._make_request('GET', url=download_link, stream=True)

        if response.status_code >= 300:
            self._log.warning(
                'Failed to download the Live Response result. HTTP status: %s.',
                response.status_code,
            )
            return None

        return response.content or b''

    def _cancel_machine_action(self, action_id: str) -> None:
        """
        Cancels live response job

        :param action_id: Live response job ID
        """
        url = f'{self._config.DEFENDER_API_BASE_URL}/api/machineactions/{action_id}/cancel'
        payload = {'Comment': 'Live response action was cancelled by ANY.RUN Logic App request.'}

        response = self._make_request('POST', url=url, data=json.dumps(payload))

        if response.status_code >= 300:
            self._throw_error(f'Failed to cancel machine action: {action_id}', response)

    def _get_live_response_action_info(self, live_response_id: str) -> dict | None:
        """
        Retrieves live response job info

        :param live_response_id: Live response job ID
        :return: Live response job info, or None while a newly created action
            is not yet visible through the machineactions read endpoint
        """
        url = f'{self._config.DEFENDER_API_BASE_URL}/api/machineactions/{live_response_id}'

        response = self._make_request(method='GET', url=url)

        if response.status_code == 404:
            try:
                error_code = (response.json().get('error') or {}).get('code')
            except (AttributeError, TypeError, ValueError):
                error_code = None
            if error_code == 'ResourceNotFound':
                return None

        if response.status_code >= 300:
            self._throw_error(f'Failed to retrieve live response action info.', response)

        return response.json()

    def _run_live_response(
        self,
        machine_id: str,
        live_response_command: dict,
        wait_for_slot: bool = True,
    ) -> str:
        """
        Remotely executes PowerShell or Bash script on the specified machine

        :param machine_id: Machine ID
        :param live_response_command: Command
        :return: Live response job ID
        """
        if wait_for_slot:
            self._wait_run_other_machine_actions(machine_id)

        url = f'{self._config.DEFENDER_API_BASE_URL}/api/machines/{machine_id}/runliveresponse'

        self._log.info(f'Run live response job on machine: {machine_id}.')
        for attempt in range(1, self._config.LIVE_RESPONSE_SUBMIT_RETRIES + 1):
            response = self._make_request(
                method='POST',
                url=url,
                data=json.dumps(live_response_command),
            )
            response_text = response.text or ''
            retryable = (
                response.status_code == 429
                or (
                    response.status_code == 400
                    and 'ActiveRequestAlreadyExists' in response_text
                )
            )
            if response.status_code < 300:
                live_response_id = response.json().get('id')
                if not live_response_id:
                    self._throw_error('Live Response response did not include an action ID.', response)
                self._log.info(
                    'Live Response action %s accepted; waiting %s seconds before the first status check.',
                    live_response_id,
                    self._config.LIVE_RESPONSE_INITIAL_DELAY_SECONDS,
                )
                time.sleep(self._config.LIVE_RESPONSE_INITIAL_DELAY_SECONDS)
                return live_response_id
            if not retryable or attempt == self._config.LIVE_RESPONSE_SUBMIT_RETRIES:
                self._throw_error('Failed to execute live response job.', response)

            retry_after = response.headers.get('Retry-After') if response.headers else None
            try:
                delay = max(self._config.ACTION_TIMEOUT, int(retry_after))
            except (TypeError, ValueError):
                delay = min(self._config.ACTION_TIMEOUT * attempt, 120)
            self._log.warning(
                'Live Response is busy or throttled; retrying in %s seconds (%s/%s).',
                delay,
                attempt,
                self._config.LIVE_RESPONSE_SUBMIT_RETRIES,
            )
            time.sleep(delay)

        raise AssertionError('unreachable')

    def _wait_run_other_machine_actions(self, machine_id: str) -> None:
        """
        Checks if other live response jobs are running on machine.

        :param machine_id: Machine ID
        """
        self._log.info('Check if other live response jobs are active.')
        deadline = self._bounded_deadline(self._config.LIVE_RESPONSE_WAIT_SECONDS)

        while True:
            machine_actions = self._get_machine_actions(machine_id)

            if not machine_actions:
                self._log.info(f'No active live response jobs found.')
                return

            active_actions = [
                action for action in machine_actions
                if action.get('type') == 'LiveResponse'
                and action.get('status') in ('Pending', 'InProgress')
            ]
            if not active_actions:
                return

            if time.monotonic() >= deadline:
                self._throw_error(
                    'Timed out waiting for another Live Response session to finish. '
                    'The existing session was left untouched.'
                )

            self._log.info('Waiting for %s active Live Response action(s).', len(active_actions))
            time.sleep(self._config.ACTION_TIMEOUT)

    def _wait_run_script_live_response_job(self, live_response_id: str) -> dict:
        """
        Waiting for live response job to finish

        :param live_response_id: Live response ID
        :return: Live response job info
        """
        deadline = self._bounded_deadline(self._config.LIVE_RESPONSE_WAIT_SECONDS)
        visibility_deadline = None
        while True:
            machine_action = self._get_live_response_action_info(live_response_id)
            if machine_action is None:
                now = time.monotonic()
                if visibility_deadline is None:
                    visibility_deadline = min(
                        deadline,
                        now + self._config.LIVE_RESPONSE_VISIBILITY_WAIT_SECONDS,
                    )
                if now >= visibility_deadline:
                    self._throw_error(
                        'Live Response action was created but did not become visible through '
                        f'the machineactions API within '
                        f'{self._config.LIVE_RESPONSE_VISIBILITY_WAIT_SECONDS} seconds. '
                        f'Action ID: {live_response_id}.'
                    )
                self._log.warning(
                    'Live Response action %s is not visible through machineactions yet; '
                    'retrying in %s seconds.',
                    live_response_id,
                    self._config.LIVE_RESPONSE_VISIBILITY_POLL_SECONDS,
                )
                time.sleep(self._config.LIVE_RESPONSE_VISIBILITY_POLL_SECONDS)
                continue

            visibility_deadline = None
            status = machine_action.get('status')

            if status == 'Succeeded':
                return machine_action
            elif status in ['Cancelled', 'TimeOut', 'Failed']:
                self._throw_error(
                    f'Live Response failed with status {status}. Action ID: {live_response_id}.'
                )

            if time.monotonic() >= deadline:
                try:
                    self._cancel_machine_action(live_response_id)
                except Exception as error:
                    self._log.error(
                        'Failed to cancel timed-out Live Response action %s: %s: %s',
                        live_response_id,
                        type(error).__name__,
                        sanitize_error_text(error, limit=1000),
                    )
                self._throw_error(
                    f'Live Response exceeded {self._config.LIVE_RESPONSE_WAIT_SECONDS} seconds. '
                    f'Action ID: {live_response_id}.'
                )

            time.sleep(self._config.ACTION_TIMEOUT)

    def submit_indicators(self, indicators: list[dict], task_uuid: str) -> list[dict]:
        """
        Loads Malicious and Suspicious IOCs to the MS Defender

        :param indicators: List of indicators
        :param task_uuid: Analysis uuid
        """
        url = f'{self._config.DEFENDER_API_BASE_URL}/api/indicators/import'
        indicator_action = get_env_variable('DefenderIndicatorAction', default='Audit')
        if indicator_action not in {'Audit', 'Block'}:
            raise ValueError('DefenderIndicatorAction must be Audit or Block.')
        generate_alert = str(
            get_env_variable('DefenderIndicatorGenerateAlert', default='false')
        ).casefold() == 'true'

        payload = {
            'Indicators': [
                {
                    'indicatorValue': indicator.get('ioc'),
                    'title': 'IoC from ANY.RUN Sandbox',
                    'description': f'https://app.any.run/tasks/{task_uuid}',
                    'action': indicator_action,
                    'generateAlert': generate_alert,
                    'severity': {
                        1: 'Medium',
                        2: 'High'
                    }.get(indicator.get('reputation')),
                    'indicatorType': {
                        'sha256': 'FileSha256',
                        'ip': 'IpAddress',
                        'domain': 'DomainName',
                        'url': 'Url'
                    }.get(indicator.get('type'))
                } for indicator in indicators
            ]
        }

        response = self._make_request('POST', url=url, data=json.dumps(payload))

        if response.status_code >= 300:
            self._throw_error('Failed to submit indicators.', response)

        results = response.json().get('value') or []
        if len(results) != len(payload['Indicators']):
            self._throw_error(
                'Defender returned an incomplete Sandbox indicator import result.',
                response,
            )
        failures = [result for result in results if result.get('isFailed')]
        if failures:
            self._log.error(
                'Defender rejected %s Sandbox indicators: %s',
                len(failures),
                json.dumps([
                    {
                        'indicator': item.get('indicator'),
                        'failureReason': item.get('failureReason'),
                    }
                    for item in failures[:10]
                ], ensure_ascii=False),
            )
        self._log.info(
            'Sandbox indicator import completed: accepted=%s, rejected=%s.',
            len(results) - len(failures),
            len(failures),
        )
        return failures

    def _make_request(
            self,
            method: str,
            url: str,
            data: dict | MultipartEncoder | str | None = None,
            stream: bool = False,
            allow_reauthentication: bool = True,
            authenticated: bool = True,
            retry_data_factory: Callable[[], dict | MultipartEncoder | str] | None = None,
        ) -> requests.Response:
        """
        Executes a request ti the specified API endpoint

        :param method: HTTP Request method
        :param url: Endpoint URL
        :param data: Request body
        :param stream: Enable/disable data streaming
        :param authenticated: Include Defender authorization headers
        :param retry_data_factory: Recreate one-shot request bodies for a 401 retry
        :return: Response object
        """
        self._check_job_deadline()
        if (
            authenticated
            and allow_reauthentication
            and not stream
            and self._headers
            and time.monotonic() >= self._token_expires_at
        ):
            self._authenticate()

        try:
            headers = self._setup_headers(data, stream) if authenticated else None
            response = requests.request(method, url, headers=headers, data=data, stream=stream, timeout=(10, 60))
        except (requests.RequestException, OSError) as error:
            self._throw_error(f'Network request failed: {error}.')

        if authenticated and allow_reauthentication and not stream and self._headers and response.status_code == 401:
            self._log.info('Defender access token expired; refreshing it and retrying once.')
            self._authenticate()
            retry_data = retry_data_factory() if retry_data_factory else data
            try:
                response = requests.request(
                    method,
                    url,
                    headers=self._setup_headers(retry_data, stream),
                    data=retry_data,
                    stream=stream,
                    timeout=(10, 60),
                )
            except (requests.RequestException, OSError) as error:
                self._throw_error(f'Network request failed after token refresh: {error}.')
        return response

    def _bounded_deadline(self, seconds: int) -> float:
        operation_deadline = time.monotonic() + seconds
        if self._deadline_monotonic is None:
            return operation_deadline
        return min(operation_deadline, self._deadline_monotonic)

    def _check_job_deadline(self) -> None:
        if (
            self._deadline_monotonic is not None
            and time.monotonic() >= self._deadline_monotonic
        ):
            self._throw_error(
                'ANY.RUN analysis exceeded the 90-minute job time budget.'
            )

    def _setup_headers(
            self,
            data: dict | MultipartEncoder | str | None = None,
            stream: bool = False
    ) -> dict[str, str] | None:
        """
        Generates request headers according to the params received

        :param data: Request body
        :param stream: Enable/disable data streaming
        :return: Headers dict
        """
        if isinstance(data, MultipartEncoder):
            return {**self._headers, **{'Content-Type': data.content_type}}
        elif stream:
            return
        else:
            return self._headers


    def _throw_error(self, error_message: str, response: requests.Response | None = None) -> None:
        """
        Logs error text then builds and raises exception

        :param error_message: Error text
        :param response: Response object
        """
        safe_message = sanitize_error_text(error_message, limit=1500)
        self._log.error(safe_message)

        if response is not None:
            safe_response = sanitize_error_text(response.text, limit=1000)
            raise RunTimeException(
                f'{safe_message} Response: {safe_response}',
                response.status_code
            )
        raise RunTimeException(safe_message)
