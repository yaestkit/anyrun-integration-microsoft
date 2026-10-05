#!/usr/bin/env python3
"""Offline compatibility checks against installed SDK; no real API requests.

Run in a Python 3.12 environment with the Sandbox requirements installed.
Unit tests intentionally use stubs; run this script in a separate process.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import aiohttp
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ANYRUN-Sandbox-MDE' / 'src'))

from anyrun_mde_core.sandbox_client import BoundedWindowsConnector, BoundedLinuxConnector, BoundedBaseConnector
from anyrun_mde_core.config import Config
from anyrun_mde_core.job_status import JobStatusStore
from azure.core.exceptions import ResourceExistsError
from anyrun_mde_core import processor
from anyrun_mde_core.api_errors import SandboxAPIError, SandboxTransportError


async def verify():
    for client_type in (BoundedWindowsConnector, BoundedLinuxConnector, BoundedBaseConnector):
        client = client_type(api_key='offline-placeholder', deadline_monotonic=time.monotonic() + 5400)
        response = Mock(status=200, headers={})
        response.json = AsyncMock(return_value={'data': {'status': 'done'}})
        client._session = Mock(request=AsyncMock(return_value=response))
        await client.get_analysis_report_async('offline-task')
        timeout = client._session.request.call_args.kwargs['timeout']
        assert timeout == Config.ANYRUN_REQUEST_TIMEOUT_SECONDS, timeout
        client.request_deadline = time.monotonic() + 2
        await client.get_analysis_report_async('offline-task')
        timeout = client._session.request.call_args.kwargs['timeout']
        assert 0 < timeout <= 2, timeout
        client.request_deadline = None
        await client._make_request_async('POST', f'{client.ANY_RUN_API_URL}/analysis', json={})
        assert client._session.request.call_args.kwargs['timeout'] == Config.ANYRUN_SUBMIT_TIMEOUT_SECONDS
        client.deadline_monotonic = time.monotonic() + 3
        await client._make_request_async('POST', f'{client.ANY_RUN_API_URL}/analysis', json={})
        assert 0 < client._session.request.call_args.kwargs['timeout'] <= 3
        client.deadline_monotonic = time.monotonic() + 5400
        for status in (400, 401, 403, 404, 429, 503):
            response.status = status
            response.json.return_value = {'message': 'offline rejection'}
            try:
                await client.get_analysis_report_async('offline-task')
            except SandboxAPIError as error:
                assert error.status_code == status
            else:
                raise AssertionError('HTTP status was lost')
        for status in (401, 403, 413, 429, 502, 503):
            response.status = status
            response.json.side_effect = aiohttp.ContentTypeError(
                request_info=Mock(real_url='https://api.any.run/offline'), history=(),
                status=status, message='Unexpected mimetype: text/html',
            )
            try:
                await client.get_analysis_report_async('offline-task')
            except SandboxAPIError as error:
                assert error.status_code == status
            else:
                raise AssertionError('Non-JSON HTTP failure lost status')
        response.json.side_effect = None
        response.status = 200
        client._session.request.side_effect = TimeoutError('offline timeout')
        try:
            await client.get_analysis_report_async('offline-task')
        except SandboxTransportError:
            pass
        else:
            raise AssertionError('SDK-wrapped timeout was not classified')
        client._session.request.side_effect = None
        client.request_deadline = time.monotonic() - 1
        previous_calls = client._session.request.call_count
        try:
            await client.get_analysis_report_async('offline-task')
        except TimeoutError:
            pass
        else:
            raise AssertionError('Expired deadline did not stop a request')
        assert client._session.request.call_count == previous_calls
        client._session = None
        client.deadline_monotonic = None
        client.request_deadline = None
        client._enable_requests = True
        response = Mock(status_code=200, headers={})
        response.json.return_value = {'data': {'status': 'done'}}
        with patch('requests.request', return_value=response) as request:
            await client.get_analysis_report_async('offline-task')
        assert request.call_args.kwargs['timeout'] == Config.ANYRUN_REQUEST_TIMEOUT_SECONDS
        response.status_code = 429
        with patch('requests.request', return_value=response):
            try:
                await client.get_analysis_report_async('offline-task')
            except SandboxAPIError as error:
                assert error.status_code == 429
            else:
                raise AssertionError('Requests path lost HTTP status')
        response.status_code = 413
        response.json.side_effect = requests.exceptions.JSONDecodeError('Not JSON', '<html>', 0)
        with patch('requests.request', return_value=response):
            try:
                await client.get_analysis_report_async('offline-task')
            except SandboxAPIError as error:
                assert error.status_code == 413
            else:
                raise AssertionError('Requests non-JSON failure lost HTTP status')
    store = JobStatusStore('UseDevelopmentStorage=true', 'status')
    blob = Mock()
    blob.upload_blob.side_effect = ResourceExistsError('lock blob already exists')
    store._container = Mock()
    store._container.get_blob_client.return_value = blob
    with store.claim('job-1') as lease:
        self_check = lease is blob.acquire_lease.return_value
        assert self_check
    blob.acquire_lease.assert_called_once_with(lease_duration=60)
    lease.release.assert_called_once()
    print('SDK compatibility: Windows/Linux/Base, aiohttp/requests deadlines and Azure lease API OK (offline).')


def verify_recovery_pipeline():
    """Real worker/processor/status code; replace only external API/storage IO."""
    source = Path(__file__).resolve().parents[1] / 'ANYRUN-Sandbox-MDE' / 'src'
    spec = importlib.util.spec_from_file_location('offline_worker', source / 'ANYRUN-Sandbox-MDE-Worker' / 'worker.py')
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    store = JobStatusStore('UseDevelopmentStorage=true', 'status')
    blobs = {}

    class MemoryBlob:
        def __init__(self, name):
            self.name = name

        def upload_blob(self, payload, **_kwargs):
            blobs[self.name] = payload

        def download_blob(self):
            return Mock(readall=Mock(return_value=blobs[self.name]))

    store._container = Mock(get_blob_client=Mock(side_effect=MemoryBlob))
    store.create('offline-job', 'offline-alert')
    payload = {'job_id': 'offline-job', 'alert_id': 'offline-alert', 'alert_source': 'WindowsDefenderAtp',
               'machine_os_platform': 'windows', 'analysis_options': {'opt_timeout': 240}}
    message = Mock(dequeue_count=1, get_body=Mock(return_value=json.dumps(payload).encode()))
    defender = Mock()
    defender.get_evidences.return_value = ('machine', {
        'filepaths': ['C:/sample.exe'], 'filenames': ['sample.exe'], 'urls': [],
    })
    defender.download_file_from_machine.return_value = b'offline-file'
    connector = Mock()
    connector.run_file_analysis.return_value = 'same-paid-task'
    report = {'data': {'status': 'done', 'analysis': {
        'permanentUrl': 'https://app.any.run/tasks/same-paid-task',
        'scores': {'verdict': {'threatLevelText': 'Malicious activity', 'score': 100}},
    }}}

    class ProcessStopped(BaseException):
        pass

    connector.get_analysis_report.side_effect = [ProcessStopped(), report, []]
    connector_context = Mock()
    connector_context.__enter__ = Mock(return_value=connector)
    connector_context.__exit__ = Mock(return_value=False)
    auth_context = Mock()
    auth_context.__enter__ = Mock(return_value=Mock())
    auth_context.__exit__ = Mock(return_value=False)
    persist = worker._persist_status

    def without_shutdown_cleanup(*args, **kwargs):
        # Model abrupt process death: no interrupted-state write survives.
        if kwargs.get('stage') == 'interrupted':
            return False
        return persist(*args, **kwargs)

    with patch.object(processor, 'MicrosoftDefender', return_value=defender), \
            patch.object(processor, 'BoundedWindowsConnector', return_value=connector_context), \
            patch.object(worker, 'BoundedBaseConnector', return_value=auth_context), \
            patch.object(worker, 'get_env_variable', return_value='offline-placeholder'), \
            patch.object(processor, 'get_env_variable', return_value='offline-placeholder'), \
            patch.object(worker, '_persist_status', side_effect=without_shutdown_cleanup):
        try:
            worker._run_job(message, store, threading.Event())
        except ProcessStopped:
            pass
        else:
            raise AssertionError('Interruption was not simulated')
        assert store.get('offline-job')['state'] == 'waiting_for_verdict'
        message.dequeue_count = 2
        worker._run_job(message, store, threading.Event())
        status = store.get('offline-job')
        assert status['state'] == 'completed'
        assert status['attempt'] == 2
        assert status['analyses'][0]['task_uuid'] == 'same-paid-task'
        connector.run_file_analysis.assert_called_once()
        defender.download_file_from_machine.assert_called_once()
        defender.add_task_reference_comment.assert_called_once()
        defender.add_summary_comment.assert_called_once()
        # A third delivery acknowledges the completed job without more IO.
        message.dequeue_count = 3
        worker._run_job(message, store, threading.Event())
        connector.run_file_analysis.assert_called_once()
    print('Recovery pipeline: interrupted -> same UUID -> completed; one submission, one Live Response (offline).')


if __name__ == '__main__':
    asyncio.run(verify())
    verify_recovery_pipeline()
