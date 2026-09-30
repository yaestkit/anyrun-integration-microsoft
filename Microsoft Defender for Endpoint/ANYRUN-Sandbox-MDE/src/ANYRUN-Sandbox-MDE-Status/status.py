from __future__ import annotations

import logging
from json import JSONDecodeError, dumps

import azure.functions as func

from anyrun_mde_core.job_status import JobStatusStore
from anyrun_mde_core.utils import sanitize_error_text


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Return the current state of a queued Sandbox job without exposing secrets."""
    try:
        body = req.get_json()
    except (ValueError, JSONDecodeError):
        body = {}

    job_id = req.params.get('job_id') or (
        body.get('job_id') if isinstance(body, dict) else None
    )
    if not isinstance(job_id, str) or not job_id.strip():
        return _response(400, {'message': 'job_id is required.'})

    try:
        status = JobStatusStore.from_environment().get(job_id.strip())
    except ValueError as error:
        return _response(400, {'message': str(error)})
    except Exception as error:
        logging.error(
            'Failed to retrieve ANY.RUN job status %s: %s: %s',
            job_id,
            type(error).__name__,
            sanitize_error_text(error),
        )
        return _response(500, {'message': 'Failed to retrieve ANY.RUN job status.'})

    if status is None:
        return _response(404, {'message': 'ANY.RUN job status was not found.'})
    return _response(200, status)


def _response(status_code: int, body: dict) -> func.HttpResponse:
    return func.HttpResponse(
        dumps(body, ensure_ascii=False),
        status_code=status_code,
        mimetype='application/json',
    )
