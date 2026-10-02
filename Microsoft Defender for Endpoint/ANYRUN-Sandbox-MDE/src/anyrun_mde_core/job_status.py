from __future__ import annotations

import json
import os
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from azure.core.exceptions import ResourceNotFoundError
from azure.storage.blob import BlobServiceClient, ContentSettings


JOB_ID_PATTERN = re.compile(r'^[A-Za-z0-9-]{1,64}$')
DEFAULT_CONTAINER_NAME = 'anyrun-job-status'
STATUS_STORAGE_CONNECTION_TIMEOUT_SECONDS = 3
STATUS_STORAGE_READ_TIMEOUT_SECONDS = 5


class JobStatusStore:
    """Persist the safe, user-visible state of an asynchronous Sandbox job."""

    def __init__(self, connection_string: str, container_name: str) -> None:
        self._mutex = threading.RLock()
        self._container = BlobServiceClient.from_connection_string(
            connection_string,
            # Application-level retries in the worker have explicit budgets.
            # Disable the SDK retry layer so attempts cannot multiply into
            # minutes for this non-critical observability side channel.
            retry_total=0,
            retry_connect=0,
            retry_read=0,
            retry_status=0,
            connection_timeout=STATUS_STORAGE_CONNECTION_TIMEOUT_SECONDS,
            read_timeout=STATUS_STORAGE_READ_TIMEOUT_SECONDS,
        ).get_container_client(container_name)

    @classmethod
    def from_environment(cls) -> 'JobStatusStore':
        connection_string = os.environ.get('AzureStorageConnectionString', '').strip()
        if not connection_string:
            raise RuntimeError('AzureStorageConnectionString is not configured.')
        container_name = (
            os.environ.get('AnyRunJobStatusContainerName', DEFAULT_CONTAINER_NAME).strip()
            or DEFAULT_CONTAINER_NAME
        )
        return cls(connection_string, container_name)

    def create(self, job_id: str, alert_id: str) -> dict[str, Any]:
        timestamp = _utc_now()
        status = {
            'job_id': _validate_job_id(job_id),
            'alert_id': str(alert_id)[:256],
            'state': 'queued',
            'stage': 'queued',
            'created_at': timestamp,
            'updated_at': timestamp,
            'history': [
                {
                    'state': 'queued',
                    'stage': 'queued',
                    'timestamp': timestamp,
                }
            ],
        }
        self._write(status)
        return status

    def get(self, job_id: str) -> dict[str, Any] | None:
        blob = self._container.get_blob_client(f'{_validate_job_id(job_id)}.json')
        try:
            payload = blob.download_blob().readall()
        except ResourceNotFoundError:
            return None
        status = json.loads(payload)
        if not isinstance(status, dict):
            raise RuntimeError('Stored ANY.RUN job status is not a JSON object.')
        return status

    def update(
        self,
        job_id: str,
        *,
        state: str,
        stage: str | None = None,
        **details: Any,
    ) -> dict[str, Any]:
        # Heartbeat and checkpoints share this client in the worker. Serialize
        # their read/modify/write cycles so a heartbeat cannot erase a UUID.
        with self._mutex:
            return self._update(job_id, state=state, stage=stage, **details)

    def _update(self, job_id: str, *, state: str, stage: str | None = None, **details: Any) -> dict[str, Any]:
        status = self.get(job_id)
        if status is None:
            raise RuntimeError(f'ANY.RUN job status {job_id} does not exist.')

        timestamp = _utc_now()
        safe_state = str(state)[:64]
        safe_stage = str(stage or state)[:96]
        status.update(_json_safe(details))
        status.update({
            'state': safe_state,
            'stage': safe_stage,
            'updated_at': timestamp,
        })
        if safe_state in {'completed', 'failed'}:
            status['completed_at'] = timestamp
        history = status.setdefault('history', [])
        if not isinstance(history, list):
            history = []
            status['history'] = history
        history.append({
            'state': safe_state,
            'stage': safe_stage,
            'timestamp': timestamp,
        })
        status['history'] = history[-50:]
        self._write(status)
        return status

    def touch(self, job_id: str, **details: Any) -> None:
        """Refresh liveness without growing history or reviving terminal jobs."""
        with self._mutex:
            status = self.get(job_id)
            if status is None or status.get('state') in {'completed', 'failed'}:
                return
            status.update(_json_safe(details))
            status['updated_at'] = status['heartbeat_at'] = _utc_now()
            self._write(status)

    @contextmanager
    def claim(self, job_id: str):
        """One worker per job; the 60-second lease expires after process death."""
        from azure.core.exceptions import ResourceExistsError
        blob = self._container.get_blob_client(f'{_validate_job_id(job_id)}.lock')
        try:
            blob.upload_blob(b'', overwrite=False)
        except ResourceExistsError:
            pass
        lease = blob.acquire_lease(lease_duration=60)
        try:
            yield lease
        finally:
            try:
                lease.release()
            except Exception:
                # A lost lease must not replace the business exception.
                pass

    def _write(self, status: dict[str, Any]) -> None:
        job_id = _validate_job_id(str(status['job_id']))
        payload = json.dumps(
            _json_safe(status),
            ensure_ascii=False,
            separators=(',', ':'),
        ).encode('utf-8')
        self._container.get_blob_client(f'{job_id}.json').upload_blob(
            payload,
            overwrite=True,
            content_settings=ContentSettings(content_type='application/json'),
        )


def _validate_job_id(job_id: str) -> str:
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise ValueError('Invalid ANY.RUN job ID.')
    return job_id


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)
