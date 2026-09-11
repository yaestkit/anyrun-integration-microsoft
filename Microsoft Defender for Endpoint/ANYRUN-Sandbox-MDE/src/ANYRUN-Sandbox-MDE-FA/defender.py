import base64
import os
import json
import time
import traceback
from datetime import datetime, timedelta, UTC
from itertools import batched

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from azure.storage.blob import BlobServiceClient
from azure.storage.blob import ContainerSasPermissions, generate_container_sas
from anyrun import RunTimeException

from .config import Config
from .utils import (
    get_env_variable,
    generate_filepath,
    generate_ioc_comment,
    generate_task_uuid_comment,
    generate_analysis_summary_comment
)


LIVE_RESPONSE_PAYLOAD_VERSION = 'v1'


def encode_live_response_payload(
    filepaths: list[str],
    sas_token: str,
    storage_account_name: str,
    container_name: str,
) -> str:
    """Encode Live Response parameters using a shell-safe, versioned envelope."""
    values = [sas_token, storage_account_name, container_name, *filepaths]
    encoded_values = [
        base64.urlsafe_b64encode(value.encode('utf-8')).decode('ascii').rstrip('=')
        for value in values
    ]
    return '.'.join([LIVE_RESPONSE_PAYLOAD_VERSION, *encoded_values])


class MicrosoftDefender:
    """ Class - wrapper to interact with MS Defender REST API """
    def __init__(self, log) -> None:
        self._headers = None
        self._config = Config
        self._log = log

        self._authenticate()

    def _authenticate(self):
        """
        Authenticates connector in MS Defender API
        """
        url = f'https://login.microsoftonline.com/{get_env_variable('AzureTenantID')}/oauth2/token'
        body = {
            'resource': self._config.DEFENDER_OAUTH_RESOURCE,
            'client_id': get_env_variable('AzureClientID'),
            'client_secret': get_env_variable('AzureClientSecret'),
            'grant_type': 'client_credentials',
        }
        response = self._make_request(method='POST', url=url, data=body)

        if response.status_code > 300:
            self._throw_error(
                f'Failed to authenticate at: {self._config.DEFENDER_OAUTH_RESOURCE}. Please, check your credentials.',
                response
            )

        self._headers = {
            'Authorization': f'Bearer {response.json().get('access_token')}',
            'Content-Type': 'application/json',
        }

    def _generate_sas_token(self) -> str:
        """
        Generates SAS token to interact with BlobStorage

        :return: SAS token
        """
        expiry_time = datetime.now(UTC) + timedelta(hours=2)

        try:
            sas_token = generate_container_sas(
                account_name=get_env_variable('AzureStorageAccountName'),
                container_name=get_env_variable('AzureBlobContainerName'),
                account_key=get_env_variable('AzureStorageAccountKey'),
                permission=ContainerSasPermissions(write=True),
                expiry=expiry_time,
            )
        except Exception:
            self._throw_error(
                f'Failed to generate SAS token. Please, check your credentials. Reason: {traceback.format_exc()}.'
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

        response = self._make_request(
            method='POST',
            url=url,
            data=MultipartEncoder(
                fields={
                    'HasParameters': 'true',
                    'OverrideIfExists': 'true',
                    'Description': 'description',
                    'file': (script_name, script_content, 'text/plain'),
                }
            )
        )

        if response.status_code >= 300:
            self._throw_error(f'Failed to load PowerShell script to the library.', response)

    def execute_ps_script_on_machine(
        self,
        machine_id: str,
        machine_os_platform: str,
        filepaths: list[str]
    ) -> None:
        """
        Remotely executes PowerShell or Bash script on the target machine

        :param machine_id: Machine ID
        :param machine_os_platform: OS platform type
        :param filepaths: Quarantine file paths
        """
        if machine_os_platform == 'windows':
            script_name = self._config.PS_SCRIPT_NAME
        elif machine_os_platform == 'linux':
            script_name = self._config.BASH_SCRIPT_NAME

        payload = encode_live_response_payload(
            filepaths=filepaths,
            sas_token=self._generate_sas_token(),
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

        self._run_live_response(machine_id, live_response_command)

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
            container_client.delete_blob(filename)
            return file_data
        except Exception:
            self._log.error(traceback.format_exc())

        return

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

    def _download_file_by_link(self, download_link) -> bytes:
        """
        Downloads file using download link

        :param download_link: File download link
        :return: File content
        """
        response = self._make_request('GET', url=download_link, stream=True)

        if response.status_code >= 300:
            self._log.warning(f'Failed to download file by url: {download_link}.', response)

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

    def _get_live_response_action_info(self, live_response_id: str) -> dict:
        """
        Retrieves live response job info

        :param live_response_id: Live response job ID
        :return: Live response job info
        """
        url = f'{self._config.DEFENDER_API_BASE_URL}/api/machineactions/{live_response_id}'

        response = self._make_request(method='GET', url=url)

        if response.status_code >= 300:
            self._throw_error(f'Failed to retrieve live response action info.', response)

        return response.json()

    def _run_live_response(self, machine_id: str, live_response_command: dict) -> str:
        """
        Remotely executes PowerShell or Bash script on the specified machine

        :param machine_id: Machine ID
        :param live_response_command: Command
        :return: Live response job ID
        """
        self._wait_run_other_machine_actions(machine_id)

        url = f'{self._config.DEFENDER_API_BASE_URL}/api/machines/{machine_id}/runliveresponse'

        self._log.info(f'Run live response job on machine: {machine_id}.')
        response = self._make_request(
            method='POST',
            url=url,
            data=json.dumps(live_response_command),
        )

        if response.status_code >= 300:
            self._throw_error('Failed to execute live response job.', response)

        time.sleep(self._config.ACTION_TIMEOUT)
        live_response_id = response.json().get('id')

        return live_response_id

    def _wait_run_other_machine_actions(self, machine_id: str) -> None:
        """
        Checks if other live response jobs are running on machine.
        Cancels pending AnyRun LogicAPP live response jobs

        :param machine_id: Machine ID
        """
        self._log.info('Check if other live response jobs are active.')
        waiting_counter = 0

        while True:
            machine_actions = self._get_machine_actions(machine_id)

            if not machine_actions:
                self._log.info(f'No active live response jobs found.')
                return

            for action in machine_actions:
                if (
                        action.get('type') == 'LiveResponse'
                        and action.get('requestor') == 'ANYRUN-LogicApp'
                        and action.get('status') == 'Pending'
                ):
                    action_id = action.get('id')
                    self._log.info(f'Cancelling ANYRUN-LogicApp live response job with status "Pending": {action_id}')
                    self._cancel_machine_action(action_id)

                    waiting_counter += 1
                    time.sleep(self._config.ACTION_TIMEOUT)
                    continue

                elif (
                        action.get('type') == 'LiveResponse'
                        and action.get('status') in ('Pending', 'InProgress')
                ):
                    self._log.info(f'Waiting for action: {action}')

                    waiting_counter += 1
                    time.sleep(self._config.ACTION_TIMEOUT)
                    continue

            if not waiting_counter:
                return

            waiting_counter = 0

    def _wait_run_script_live_response_job(self, live_response_id: str) -> dict | None:
        """
        Waiting for live response job to finish

        :param live_response_id: Live response ID
        :return: Live response job info
        """

        while True:
            machine_action = self._get_live_response_action_info(live_response_id)
            status = machine_action.get('status')

            if status == 'Succeeded':
                return machine_action
            elif status in ['Cancelled', 'TimeOut', 'Failed']:
                self._log.warning(f'Live response failed with error. Status: {status}. Detailed response: {machine_action}')
                return
            else:
                time.sleep(self._config.ACTION_TIMEOUT)

    def submit_indicators(self, indicators: list[dict], task_uuid: str) -> None:
        """
        Loads Malicious and Suspicious IOCs to the MS Defender

        :param indicators: List of indicators
        :param task_uuid: Analysis uuid
        """
        url = f'{self._config.DEFENDER_API_BASE_URL}/api/indicators/import'

        payload = {
            'Indicators': [
                {
                    'indicatorValue': indicator.get('ioc'),
                    'title': 'IoC from ANY.RUN Sandbox',
                    'description': f'https://app.any.run/tasks/{task_uuid}',
                    'action': 'Allowed',
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

        self._log.info(f'Successfully loaded {len(payload.get("Indicators"))} Malicious/Suspicious indicators.')

    def _make_request(
            self,
            method: str,
            url: str,
            data: dict | MultipartEncoder | str | None = None,
            stream: bool = False
        ) -> requests.Response:
        """
        Executes a request ti the specified API endpoint

        :param method: HTTP Request method
        :param url: Endpoint URL
        :param data: Request body
        :param stream: Enable/disable data streaming
        :return: Response object
        """
        try:
            response = requests.request(method, url, headers=self._setup_headers(data, stream), data=data, stream=stream)
        except (requests.RequestException, OSError) as error:
            self._throw_error(f'Network request failed: {error}.')
        return response

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
        self._log.error(error_message)

        if response is not None:
            raise RunTimeException(
                f'{error_message} Response: {response.text}',
                response.status_code
            )
        raise RunTimeException(error_message)
