from __future__ import annotations

import json
import logging
import time

import azure.functions as func
from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector

from anyrun_mde_core.config import Config
from anyrun_mde_core.defender import MicrosoftDefender
from anyrun_mde_core.processor import process_alert
from anyrun_mde_core.utils import get_env_variable


def main(job: func.QueueMessage) -> None:
    """Run the long-lived Defender and ANY.RUN workflow outside the HTTP call."""
    payload = json.loads(job.get_body().decode('utf-8'))
    job_id = payload['job_id']
    alert_id = payload['alert_id']

    logging.info('Starting ANY.RUN job %s for alert %s.', job_id, alert_id)

    try:
        deadline_monotonic = time.monotonic() + Config.JOB_TIME_BUDGET_SECONDS
        with BaseSandboxConnector(
            api_key=get_env_variable('ANYRUN_API_KEY'),
            integration=Config.VERSION,
        ) as connector:
            connector.check_authorization()

        process_alert(
            job_id=job_id,
            alert_id=alert_id,
            alert_source=payload['alert_source'],
            machine_os_platform=payload['machine_os_platform'],
            analysis_options=payload['analysis_options'],
            deadline_monotonic=deadline_monotonic,
        )
    except Exception as error:
        logging.exception('ANY.RUN job %s failed for alert %s.', job_id, alert_id)
        _add_failure_comment(alert_id, job_id, error)
        raise

    logging.info('Completed ANY.RUN job %s for alert %s.', job_id, alert_id)


def _add_failure_comment(alert_id: str, job_id: str, error: Exception) -> None:
    """Best-effort notification; preserve the original worker exception."""
    error_text = ' '.join(str(error).split())[:500]
    comment = (
        f'ANY.RUN analysis failed. Job ID: {job_id}. '
        f'Error: {type(error).__name__}: {error_text or "unspecified error"}. '
        'See Function App logs for details.'
    )
    try:
        MicrosoftDefender(logging).add_comment(alert_id, comment)
    except Exception:
        logging.exception(
            'Could not add the failure comment for ANY.RUN job %s and alert %s.',
            job_id,
            alert_id,
        )
