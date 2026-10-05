from __future__ import annotations

import json
import math
import logging
import time
import traceback
import threading
from datetime import datetime, timezone

import azure.functions as func

from anyrun_mde_core.config import Config
from anyrun_mde_core.api_errors import SandboxAPIError, SubmissionRejected
from anyrun_mde_core.defender import MicrosoftDefender
from anyrun_mde_core.job_status import JobStatusStore
from anyrun_mde_core.processor import process_alert, RecoveryRequired
from anyrun_mde_core.sandbox_client import BoundedBaseConnector
from anyrun_mde_core.utils import get_env_variable, sanitize_error_text


STATUS_WRITE_ATTEMPTS = 3
TERMINAL_STATUS_WRITE_ATTEMPTS = 5
STATUS_WRITE_BUDGET_SECONDS = 10
TERMINAL_STATUS_WRITE_BUDGET_SECONDS = 30


def main(job: func.QueueMessage) -> None:
    payload = json.loads(job.get_body().decode('utf-8'))
    store = JobStatusStore.from_environment()
    # A renewed, expiring lease prevents overlapping queue deliveries for one
    # job. Do not mutate status if another worker already owns the job.
    with store.claim(payload['job_id']) as lease:
        stop = threading.Event()
        lease_lost = threading.Event()

        thread = threading.Thread(target=_keep_alive, args=(store, payload['job_id'], lease, stop, lease_lost),
                                  name='anyrun-job-heartbeat', daemon=True)
        thread.start()
        try:
            _run_job(job, store, lease_lost)
        finally:
            stop.set()
            thread.join(timeout=10)


def _keep_alive(store, job_id, lease, stop, lease_lost):
    """Independent of long Live Response calls and bounded Sandbox requests."""
    last_heartbeat = time.monotonic()
    last_renewed = last_heartbeat
    while not stop.wait(20):
        if time.monotonic() - last_renewed >= 50:
            # Ten-second safety margin for network/clock scheduling. Do not
            # assume ownership across an expired lease or try to regain it.
            lease_lost.set()
            logging.error('ANY.RUN job %s worker lease renewal deadline expired.', job_id)
            return
        try:
            lease.renew()
        except Exception as error:
            code = getattr(error, 'error_code', None)
            code = getattr(code, 'value', code)
            if code in {'LeaseIdMismatchWithLeaseOperation', 'LeaseLost', 'LeaseNotPresentWithLeaseOperation'} or time.monotonic() - last_renewed >= 50:
                lease_lost.set()
                logging.error('ANY.RUN job %s lost its worker lease.', job_id)
                return
            logging.warning('Lease renewal temporarily failed for job %s: %s.', job_id, type(error).__name__)
            continue
        last_renewed = time.monotonic()
        if time.monotonic() - last_heartbeat >= Config.HEARTBEAT_SECONDS:
            try:
                store.touch(job_id)
            except Exception as error:
                logging.warning('Heartbeat write failed for job %s: %s', job_id, type(error).__name__)
            last_heartbeat = time.monotonic()


def _run_job(job: func.QueueMessage, status_store: JobStatusStore, lease_lost: threading.Event) -> None:
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

    resume_state = status_store.get(job_id)
    if not isinstance(resume_state, dict):
        raise RuntimeError('Job checkpoint is missing; refusing unsafe submission.')
    if resume_state.get('state') == 'completed':
        return
    if resume_state.get('state') == 'failed':
        raise RuntimeError('Job already failed; inspect its checkpoint before recovery.')
    started_at = resume_state.get('work_started_at') or datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(started_at.replace('Z', '+00:00'))).total_seconds()
    deadline_monotonic = time.monotonic() + max(0, Config.JOB_TIME_BUDGET_SECONDS - elapsed)
    checkpoints = list(resume_state.get('analyses') or [])
    try:
        _persist_status(
            status_store,
            job_id,
            state='processing',
            stage='resumed' if attempt > 1 else 'worker_started',
            attempt=attempt,
            work_started_at=started_at,
            error=None,
            error_type=None,
        )

        def update_progress(state: str, details: dict) -> None:
            if lease_lost.is_set():
                raise RuntimeError('Worker lease was lost; stopping this delivery.')
            # Progress telemetry must never abort a paid analysis. Terminal
            # states and checkpoints retain retries. Only _keep_alive writes
            # periodic heartbeats; optional progress is attempted once.
            _persist_status(
                status_store,
                job_id,
                state=state,
                stage=state,
                attempts=1,
                **details,
            )

        def save_checkpoint(state: str, item: dict) -> None:
            if lease_lost.is_set():
                raise RuntimeError('Worker lease was lost; refusing further side effects.')
            identity = item.get('evidence_key') or item.get('task_uuid')
            for index, saved in enumerate(checkpoints):
                if (saved.get('evidence_key') or saved.get('task_uuid')) == identity:
                    checkpoints[index] = item
                    break
            else:
                checkpoints.append(item)
            if not _persist_status(status_store, job_id, state=state, stage=state,
                                   analyses=checkpoints, latest_analysis=item,
                                   work_started_at=started_at, attempt=attempt):
                raise RuntimeError('Durable analysis checkpoint could not be saved; automatic submission is stopped.')

        if checkpoints and all(item.get('enriched') for item in checkpoints) and len(checkpoints) >= resume_state.get('evidence_count', math.inf):
            # Tracking-only recovery should also work while Sandbox is down.
            analyses = checkpoints
        else:
            with BoundedBaseConnector(
                api_key=get_env_variable('ANYRUN_API_KEY'), integration=Config.VERSION,
                deadline_monotonic=deadline_monotonic,
            ) as connector:
                connector.check_authorization()

            analyses = process_alert(
                job_id=job_id, alert_id=alert_id, alert_source=payload['alert_source'],
                machine_os_platform=payload['machine_os_platform'], analysis_options=payload['analysis_options'],
                deadline_monotonic=deadline_monotonic, status_callback=update_progress,
                checkpoint_callback=save_checkpoint, resume_state=resume_state,
            )
        if not analyses:
            raise RuntimeError('No alert evidence could be submitted to ANY.RUN.')
    except Exception as error:
        if lease_lost.is_set():
            raise  # Another delivery may own this job; do not overwrite it.
        error_text = sanitize_error_text(error)
        logging.error(
            'ANY.RUN job %s failed for alert %s with %s: %s\nTraceback frames:\n%s',
            job_id,
            alert_id,
            type(error).__name__,
            error_text,
            ''.join(traceback.format_list(traceback.extract_tb(error.__traceback__))),
        )
        terminal = isinstance(error, (RecoveryRequired, SubmissionRejected)) or (
            isinstance(error, SandboxAPIError) and error.status_code in {400, 401, 403, 413, 422}
        ) or attempt >= Config.QUEUE_MAX_DEQUEUE_COUNT
        if status_store is not None:
            _persist_status(
                status_store,
                job_id,
                state='failed' if terminal else 'retrying',
                stage='failed' if terminal else 'retry_pending',
                attempt=attempt,
                error=error_text,
                error_type=type(error).__name__,
                attempts=TERMINAL_STATUS_WRITE_ATTEMPTS,
                budget_seconds=TERMINAL_STATUS_WRITE_BUDGET_SECONDS,
            )
        if terminal:
            _add_failure_comment(alert_id, job_id, error)
        raise
    except BaseException as error:
        if lease_lost.is_set():
            raise
        _persist_status(
            status_store, job_id, state='failed' if attempt >= Config.QUEUE_MAX_DEQUEUE_COUNT else 'retrying',
            stage='interrupted', attempt=attempt, error_type=type(error).__name__,
            error='Worker interrupted; the next queue delivery will resume saved tasks.',
            attempts=TERMINAL_STATUS_WRITE_ATTEMPTS, budget_seconds=TERMINAL_STATUS_WRITE_BUDGET_SECONDS,
        )
        raise

    if lease_lost.is_set():
        raise RuntimeError('Worker lease was lost before completion tracking.')
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
        # Business checkpoints contain enriched=True for all completed tasks.
        # A retry can safely restore tracking without another paid POST.
        logging.error(
            'ANY.RUN job %s completed, but its terminal status could not be persisted.',
            job_id,
        )
        _add_tracking_failure_comment(alert_id, job_id)
        # All business checkpoints are durable now, so a queue retry can safely
        # persist completed without creating another paid analysis.
        raise RuntimeError('Completed job could not persist its terminal status; safe recovery will retry.')
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
