from __future__ import annotations

import json
import logging
import time
import traceback

import azure.functions as func
from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector

from anyrun_mde_core.config import Config
from anyrun_mde_core.defender import MicrosoftDefender
from anyrun_mde_core.job_status import JobStatusStore
from anyrun_mde_core.processor import process_alert
from anyrun_mde_core.utils import get_env_variable, sanitize_error_text


STATUS_WRITE_ATTEMPTS = 3
TERMINAL_STATUS_WRITE_ATTEMPTS = 5
STATUS_WRITE_BUDGET_SECONDS = 10
TERMINAL_STATUS_WRITE_BUDGET_SECONDS = 30


def main(job: func.QueueMessage) -> None:
    """Run the long-lived Defender and ANY.RUN workflow outside the HTTP call."""
    payload = json.loads(job.get_body().decode('utf-8'))
    job_id = payload['job_id']
    alert_id = payload['alert_id']
    attempt = max(1, int(getattr(job, 'dequeue_count', 1) or 1))

    logging.info(
        'Starting ANY.RUN job %s for alert %s (dequeue count %s).',
        job_id,
        alert_id,
        attempt,
    )

    status_store = None
    try:
        status_store = JobStatusStore.from_environment()
        _persist_status(
            status_store,
            job_id,
            state='processing',
            stage='worker_started',
            attempt=attempt,
        )

        def update_status(state: str, details: dict) -> None:
            # Progress telemetry must never abort a paid analysis. Terminal
            # states are persisted separately after the business work ends.
            _persist_status(
                status_store,
                job_id,
                state=state,
                stage=state,
                **details,
            )

        deadline_monotonic = time.monotonic() + Config.JOB_TIME_BUDGET_SECONDS
        with BaseSandboxConnector(
            api_key=get_env_variable('ANYRUN_API_KEY'),
            integration=Config.VERSION,
        ) as connector:
            connector.check_authorization()

        analyses = process_alert(
            job_id=job_id,
            alert_id=alert_id,
            alert_source=payload['alert_source'],
            machine_os_platform=payload['machine_os_platform'],
            analysis_options=payload['analysis_options'],
            deadline_monotonic=deadline_monotonic,
            status_callback=update_status,
        )
        if not analyses:
            raise RuntimeError('No alert evidence could be submitted to ANY.RUN.')
    except Exception as error:
        error_text = sanitize_error_text(error)
        logging.error(
            'ANY.RUN job %s failed for alert %s with %s: %s\nTraceback frames:\n%s',
            job_id,
            alert_id,
            type(error).__name__,
            error_text,
            ''.join(traceback.format_list(traceback.extract_tb(error.__traceback__))),
        )
        if status_store is not None:
            _persist_status(
                status_store,
                job_id,
                state='failed',
                stage='failed',
                attempt=attempt,
                error=error_text,
                error_type=type(error).__name__,
                attempts=TERMINAL_STATUS_WRITE_ATTEMPTS,
                budget_seconds=TERMINAL_STATUS_WRITE_BUDGET_SECONDS,
            )
        _add_failure_comment(alert_id, job_id, error)
        raise

    completed_persisted = _persist_status(
        status_store,
        job_id,
        state='completed',
        stage='completed',
        attempt=attempt,
        analysis_count=len(analyses),
        analyses=analyses,
        error=None,
        error_type=None,
        attempts=TERMINAL_STATUS_WRITE_ATTEMPTS,
        budget_seconds=TERMINAL_STATUS_WRITE_BUDGET_SECONDS,
    )
    if not completed_persisted:
        # Do not poison a successfully analysed message: replay could create a
        # duplicate paid task. Defender already contains the analysis output.
        logging.error(
            'ANY.RUN job %s completed, but its terminal status could not be persisted.',
            job_id,
        )
        _add_tracking_failure_comment(alert_id, job_id)
    logging.info('Completed ANY.RUN job %s for alert %s.', job_id, alert_id)


def _persist_status(
    status_store: JobStatusStore,
    job_id: str,
    *,
    attempts: int = STATUS_WRITE_ATTEMPTS,
    budget_seconds: int = STATUS_WRITE_BUDGET_SECONDS,
    **status: object,
) -> bool:
    """Persist observability data with bounded retries and no business abort."""
    deadline = time.monotonic() + budget_seconds
    for current_attempt in range(1, attempts + 1):
        if current_attempt > 1 and time.monotonic() >= deadline:
            break
        try:
            status_store.update(job_id, **status)
            return True
        except Exception as error:
            logging.warning(
                'Could not persist ANY.RUN job %s status %s (%s/%s): %s: %s',
                job_id,
                status.get('state', 'unknown'),
                current_attempt,
                attempts,
                type(error).__name__,
                sanitize_error_text(error),
            )
            if current_attempt < attempts:
                remaining = deadline - time.monotonic()
                delay = min(2 ** (current_attempt - 1), 4, max(0, remaining))
                if delay <= 0:
                    break
                time.sleep(delay)
    return False


def _add_failure_comment(alert_id: str, job_id: str, error: Exception) -> None:
    """Best-effort notification; preserve the original worker exception."""
    error_text = sanitize_error_text(error)
    comment = (
        f'ANY.RUN analysis failed. Job ID: {job_id}. '
        f'Error: {type(error).__name__}: {error_text or "unspecified error"}. '
        'See Function App logs for details.'
    )
    try:
        MicrosoftDefender(logging).add_comment(alert_id, comment)
    except Exception as comment_error:
        logging.error(
            'Could not add the failure comment for ANY.RUN job %s and alert %s: %s: %s',
            job_id,
            alert_id,
            type(comment_error).__name__,
            sanitize_error_text(comment_error),
        )


def _add_tracking_failure_comment(alert_id: str, job_id: str) -> None:
    comment = (
        f'ANY.RUN analysis completed for job {job_id}, but its final tracking '
        'status could not be saved. The analysis result and indicators were '
        'already added to this alert. See Function App logs for details.'
    )
    try:
        MicrosoftDefender(logging).add_comment(alert_id, comment)
    except Exception as error:
        logging.error(
            'Could not add the tracking warning for ANY.RUN job %s and alert %s: %s: %s',
            job_id,
            alert_id,
            type(error).__name__,
            sanitize_error_text(error),
        )
