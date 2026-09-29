from __future__ import annotations

import os
import time
import logging as log

from anyrun import RunTimeException
from anyrun.connectors import SandboxConnector
from anyrun.connectors.sandbox.operation_systems import WindowsConnector, LinuxConnector

from .defender import MicrosoftDefender
from .utils import get_env_variable, prepare_url_analysis_options, clear_indicators
from .config import Config


def process_alert(
    job_id: str,
    alert_id: str,
    alert_source: str,
    machine_os_platform: str,
    analysis_options: dict[str, str | int | bool],
    deadline_monotonic: float | None = None,
) -> None:
    """
    Retrieves analysis object from the specific machine according to the received parameters

    :param job_id: Asynchronous job identifier
    :param alert_id: XDR Alert ID
    :param alert_source: Alert source: EDR ot Antivirus
    :param machine_os_platform: Machine operating system
    :param analysis_options: ANY.RUN Sandbox analysis options
    :param deadline_monotonic: Overall worker deadline based on monotonic time
    """
    _check_deadline(deadline_monotonic)
    ms_defender = MicrosoftDefender(log, deadline_monotonic=deadline_monotonic)
    machine_id, evidences = ms_defender.get_evidences(alert_id, machine_os_platform)

    log.info(f'Found evidences: {evidences}\n')

    if alert_source == 'WindowsDefenderAtp':
        for filepath in evidences.get('filepaths'):
            log.info(f'Initialized evidence loading: {filepath}.')
            try:
                _check_deadline(deadline_monotonic)
                file = ms_defender.download_file_from_machine(machine_id, filepath)
            except RunTimeException as error:
                message = f'Requested file: {filepath} could not be collected: {error}'
                log.warning(message)
                ms_defender.add_comment(alert_id, message[:1500])
                continue

            if file:
                log.info(f'Evidence is successfully downloaded: {filepath}')
                setup_anyrun_connector(
                    'file', alert_id, machine_os_platform, analysis_options.copy(),
                    ms_defender, file, os.path.basename(filepath),
                    deadline_monotonic=deadline_monotonic,
                )
            else:
                message = f'Requested file: {filepath} was not found on the machine.'
                log.warning(message)
                ms_defender.add_comment(alert_id, message)

    elif alert_source == 'WindowsDefenderAv':
        ms_defender.upload_ps_script_to_library(machine_os_platform)
        blob_targets = ms_defender.execute_ps_script_on_machine(
            machine_id,
            machine_os_platform,
            list(zip(evidences.get('filepaths'), evidences.get('filenames'))),
            job_id,
        )

        for filename, blob_name in blob_targets:
            log.info(f'Initialized evidence loading: {filename}.')
            if file := ms_defender.download_file_from_storage(blob_name):
                setup_anyrun_connector(
                    'file', alert_id, machine_os_platform, analysis_options.copy(),
                    ms_defender, file, filename, deadline_monotonic=deadline_monotonic,
                )
            else:
                message = f'Requested file: {filename} was not found in the blob storage.'
                log.warning(message)
                ms_defender.add_comment(alert_id, message)

    for url in evidences.get('urls'):
        _check_deadline(deadline_monotonic)
        setup_anyrun_connector(
            'url', alert_id, machine_os_platform, analysis_options.copy(),
            ms_defender, url=url, deadline_monotonic=deadline_monotonic,
        )


def setup_anyrun_connector(
    analysis_type: str,
    alert_id: str,
    machine_os_platform: str,
    analysis_options: dict[str, str | int | bool],
    ms_defender: MicrosoftDefender,
    file: bytes | None = None,
    filename: str | None = None,
    url: str | None = None,
    deadline_monotonic: float | None = None,
) -> None:
    """
    Initializes specific analysis environment according to the received parameters

    :param analysis_type: File or URL analyse
    :param alert_id: XDR Alert ID
    :param machine_os_platform: Machine operating system
    :param analysis_options: ANY.RUN Sandbox analysis options
    :param ms_defender: The instance of the MSDefender utility class
    :param file: File content
    :param filename: File name
    :param url: Url object
    """
    if machine_os_platform == 'windows':
        log.info(f'Initialized ANY.RUN analysis using Windows VM')
        with SandboxConnector.windows(
            api_key=get_env_variable('ANYRUN_API_KEY'),
            integration=Config.VERSION
        ) as connector:
            process_analysis(
                analysis_type,
                alert_id,
                connector,
                analysis_options,
                ms_defender,
                file,
                filename,
                url,
                deadline_monotonic,
            )

    elif machine_os_platform == 'linux':
        log.info(f'Initialized ANY.RUN analysis using Linux VM')
        with SandboxConnector.linux(
            api_key=get_env_variable('ANYRUN_API_KEY'),
            integration=Config.VERSION
        ) as connector:
            process_analysis(
                analysis_type,
                alert_id,
                connector,
                analysis_options,
                ms_defender,
                file,
                filename,
                url,
                deadline_monotonic,
            )


def process_analysis(
    analysis_type: str,
    alert_id: str,
    connector: WindowsConnector | LinuxConnector,
    analysis_options: dict[str, str | int | bool],
    ms_defender: MicrosoftDefender,
    file: bytes | None = None,
    filename: str | None = None,
    url: str | None = None,
    deadline_monotonic: float | None = None,
) -> None:
    """
    Manages analysis results and updates the incident

    :param analysis_type: File or URL analyse
    :param alert_id: XDR Alert ID
    :param connector: ANY.RUN connector instance
    :param analysis_options: Analysis parameters
    :param ms_defender: The instance of the MSDefender utility class
    :param file: File content
    :param filename: File name
    :param url: Url object
    """
    _check_deadline(deadline_monotonic)
    log.info(f'Start analysis.')
    if analysis_type == 'file':
        analysis_options.pop('obj_ext_browser', None)
        task_uuid = connector.run_file_analysis(file_content=file, filename=filename, **analysis_options)
    else:
        analysis_options = prepare_url_analysis_options(analysis_options)
        task_uuid = connector.run_url_analysis(obj_url=url, **analysis_options)

    log.info(f'Analysis type: {analysis_type}. Task uuid: {task_uuid}')

    ms_defender.add_task_reference_comment(alert_id, filename or url, task_uuid=task_uuid)

    log.info(f'Added reference comment.')

    for status in connector.get_task_status(task_uuid):
        _check_deadline(deadline_monotonic)
        log.info(str(status))

    _check_deadline(deadline_monotonic)
    verdict = connector.get_analysis_verdict(task_uuid)
    indicators = connector.get_analysis_report(task_uuid, report_format='ioc')
    valid_indicators = clear_indicators(indicators)
    report = connector.get_analysis_report(task_uuid)

    if valid_indicators:
        log.info(f'Loading indicators: {valid_indicators}.')
        rejected_indicators = ms_defender.submit_indicators(valid_indicators, task_uuid)
        if rejected_indicators:
            ms_defender.add_comment(
                alert_id,
                f'Microsoft Defender rejected {len(rejected_indicators)} of '
                f'{len(valid_indicators)} indicators produced by ANY.RUN task {task_uuid}. '
                'See Function App logs for failure reasons.'
            )
        ms_defender.add_ioc_comment(alert_id, valid_indicators)
    else:
        log.warning('Malicious/Suspicious indicators not found.')

    ms_defender.add_summary_comment(alert_id, filename or url, verdict, report)


def _check_deadline(deadline_monotonic: float | None) -> None:
    """Fail before the Azure Functions hard timeout so the worker can report it."""
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        raise RunTimeException(
            'ANY.RUN analysis exceeded the 90-minute job time budget; '
            'remaining evidence was not submitted.'
        )
