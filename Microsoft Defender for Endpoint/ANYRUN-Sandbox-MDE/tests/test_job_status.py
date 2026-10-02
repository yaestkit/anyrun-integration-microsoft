import importlib.util
import json
import os
import sys
import types
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


SOURCE = Path(__file__).parents[1] / 'src' / 'anyrun_mde_core' / 'job_status.py'


class ResourceNotFoundError(Exception):
    pass


class FakeDownload:
    def __init__(self, value):
        self._value = value

    def readall(self):
        return self._value


class FakeBlob:
    def __init__(self, blobs, name):
        self._blobs = blobs
        self._name = name

    def upload_blob(self, payload, **_kwargs):
        self._blobs[self._name] = payload

    def download_blob(self):
        if self._name not in self._blobs:
            raise ResourceNotFoundError()
        return FakeDownload(self._blobs[self._name])


class FakeContainer:
    def __init__(self):
        self.blobs = {}

    def get_blob_client(self, name):
        return FakeBlob(self.blobs, name)


def load_module():
    azure = types.ModuleType('azure')
    core = types.ModuleType('azure.core')
    exceptions = types.ModuleType('azure.core.exceptions')
    exceptions.ResourceNotFoundError = ResourceNotFoundError
    storage = types.ModuleType('azure.storage')
    blob = types.ModuleType('azure.storage.blob')
    blob.BlobServiceClient = Mock()
    blob.ContentSettings = lambda **kwargs: kwargs
    sys.modules.update({
        'azure': azure,
        'azure.core': core,
        'azure.core.exceptions': exceptions,
        'azure.storage': storage,
        'azure.storage.blob': blob,
    })
    spec = importlib.util.spec_from_file_location('job_status_under_test', SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class JobStatusStoreTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.store = object.__new__(self.module.JobStatusStore)
        self.store._container = FakeContainer()
        self.store._mutex = threading.RLock()

    def test_heartbeat_preserves_history_uuid_and_terminal_state(self):
        self.store.create('job-1', 'alert')
        self.store.update('job-1', state='waiting_for_verdict', latest_analysis={'task_uuid': 'paid-task'})
        before = self.store.get('job-1')
        for _ in range(100):
            self.store.touch('job-1')
        status = self.store.get('job-1')
        self.assertEqual(status['history'], before['history'])
        self.assertEqual(status['latest_analysis']['task_uuid'], 'paid-task')
        self.assertIn('heartbeat_at', status)
        self.store.update('job-1', state='completed')
        completed = self.store.get('job-1')
        self.store.touch('job-1', state='processing')
        self.assertEqual(self.store.get('job-1'), completed)

    def test_create_update_and_read_terminal_status(self):
        self.store.create('job-1', 'alert-1')
        self.store.update(
            'job-1',
            state='submitted_to_anyrun',
            latest_analysis={'task_uuid': 'task-1'},
        )
        self.store.update(
            'job-1',
            state='completed',
            analyses=[{'task_uuid': 'task-1', 'verdict': 'malicious'}],
        )

        status = self.store.get('job-1')

        self.assertEqual(status['state'], 'completed')
        self.assertEqual(status['analyses'][0]['verdict'], 'malicious')
        self.assertIn('completed_at', status)
        self.assertEqual([entry['state'] for entry in status['history']], [
            'queued',
            'submitted_to_anyrun',
            'completed',
        ])
        stored = json.loads(self.store._container.blobs['job-1.json'])
        self.assertNotIn('api_key', stored)

    def test_missing_status_returns_none(self):
        self.assertIsNone(self.store.get('missing-job'))

    def test_invalid_job_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Invalid ANY.RUN job ID'):
            self.store.get('../secret')

    def test_environment_client_has_bounded_transport_and_no_sdk_retries(self):
        service_client = Mock()
        self.module.BlobServiceClient.from_connection_string.return_value = service_client
        with patch.dict(os.environ, {
            'AzureStorageConnectionString': 'UseDevelopmentStorage=true',
            'AnyRunJobStatusContainerName': 'status-container',
        }, clear=False):
            self.module.JobStatusStore.from_environment()

        _, kwargs = self.module.BlobServiceClient.from_connection_string.call_args
        self.assertEqual(kwargs['retry_total'], 0)
        self.assertEqual(kwargs['retry_connect'], 0)
        self.assertEqual(kwargs['retry_read'], 0)
        self.assertEqual(kwargs['retry_status'], 0)
        self.assertEqual(kwargs['connection_timeout'], 3)
        self.assertEqual(kwargs['read_timeout'], 5)
        service_client.get_container_client.assert_called_once_with('status-container')


if __name__ == '__main__':
    unittest.main()
