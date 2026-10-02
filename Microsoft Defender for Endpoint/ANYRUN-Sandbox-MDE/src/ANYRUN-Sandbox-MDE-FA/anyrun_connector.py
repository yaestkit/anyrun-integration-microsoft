from __future__ import annotations

import logging
import time
from json import JSONDecodeError, dumps, loads
from uuid import uuid4

import azure.functions as func

from anyrun_mde_core.job_status import JobStatusStore
from anyrun_mde_core.utils import sanitize_error_text


REQUIRED_FIELDS = (
    'alert_id',
    'alert_source',
    'machine_os_platform',
    'analysis_options',
)
SUPPORTED_ALERT_SOURCES = {'WindowsDefenderAtp', 'WindowsDefenderAv'}
SUPPORTED_PLATFORMS = {'windows', 'linux'}
STATUS_CREATE_ATTEMPTS = 3


def main(req: func.HttpRequest, job: func.Out[str]) -> func.HttpResponse:
    """Validate a Logic App request, enqueue it, and return without waiting."""
    try:
        body = req.get_json()
    except (ValueError, JSONDecodeError):
        body = {}

    if not isinstance(body, dict):
        return _response(400, {'message': 'The request body must be a JSON object.'})

    values = {
        name: req.params.get(name) if req.params.get(name) is not None else body.get(name)
        for name in REQUIRED_FIELDS
    }
    missing = [name for name, value in values.items() if value is None or value == '']
    if missing:
        return _response(400, {'message': f"Missing required fields: {', '.join(missing)}."})

    if isinstance(values['analysis_options'], str):
        try:
            values['analysis_options'] = loads(values['analysis_options'])
        except (TypeError, ValueError, JSONDecodeError):
            return _response(400, {'message': 'analysis_options must be a JSON object.'})

    if not isinstance(values['analysis_options'], dict):
        return _response(400, {'message': 'analysis_options must be a JSON object.'})

    if not values['analysis_options']:
        return _response(400, {'message': 'analysis_options must not be empty.'})

    if values['alert_source'] not in SUPPORTED_ALERT_SOURCES:
        return _response(
            400,
            {'message': 'alert_source must be WindowsDefenderAtp or WindowsDefenderAv.'},
        )

    if values['machine_os_platform'] not in SUPPORTED_PLATFORMS:
        return _response(400, {'message': 'machine_os_platform must be windows or linux.'})

    job_id = str(uuid4())
    message = {'job_id': job_id, **values}

    try:
        status_store = JobStatusStore.from_environment()
        _create_status_with_retry(status_store, job_id, values['alert_id'])
    except Exception as error:
        logging.error(
            'Failed to initialize ANY.RUN job status %s: %s: %s',
            job_id,
            type(error).__name__,
            sanitize_error_text(error),
        )
        return _response(
            500,
            {'message': 'Failed to initialize asynchronous job tracking.'},
        )

    job.set(dumps(message))

    logging.info(
        'Queued ANY.RUN job %s for alert %s.',
        job_id,
        values['alert_id'],
    )
    return _response(
        202,
        {
            'job_id': job_id,
            'state': 'queued',
            'message': 'ANY.RUN analysis was accepted for asynchronous processing.',
        },
    )


def _create_status_with_retry(
    status_store: JobStatusStore,
    job_id: str,
    alert_id: str,
) -> None:
    """Retry the pre-enqueue status write without risking duplicate work."""
    for attempt in range(1, STATUS_CREATE_ATTEMPTS + 1):
        try:
            status_store.create(job_id, alert_id)
            return
        except Exception as error:
            if attempt == STATUS_CREATE_ATTEMPTS:
                raise
            logging.warning(
                'Could not initialize ANY.RUN job status %s (%s/%s): %s: %s',
                job_id,
                attempt,
                STATUS_CREATE_ATTEMPTS,
                type(error).__name__,
                sanitize_error_text(error),
            )
            time.sleep(2 ** (attempt - 1))


def _response(status_code: int, body: dict[str, str]) -> func.HttpResponse:
    return func.HttpResponse(
        dumps(body),
        status_code=status_code,
        mimetype='application/json',
    )
