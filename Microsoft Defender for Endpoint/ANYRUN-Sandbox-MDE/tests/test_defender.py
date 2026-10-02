import base64
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


SOURCE_DIR = Path(__file__).parents[1] / 'src' / 'anyrun_mde_core'


class FakeResponse:
    def __init__(self, status_code, payload=None, text='', headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text
        self.headers = headers or {}
        self.content = b''

    def json(self):
        return self._payload

    def __bool__(self):
        return self.status_code < 400


class RunTimeException(Exception):
    def __init__(self, description, code=None):
        self.description = description
        self.status_code = code

    def __str__(self):
        code = int(self.status_code) if self.status_code else 'unspecified'
        return f'[AnyRun Exception] Status code: {code}. Description: {self.description}'


def load_defender_module():
    requests = types.ModuleType('requests')
    requests.Response = FakeResponse
    requests.RequestException = Exception
    requests.request = Mock()

    encoder = types.ModuleType('requests_toolbelt.multipart.encoder')

    class MultipartEncoder:
        def __init__(self, fields):
            self.fields = fields
            self.content_type = 'multipart/form-data; boundary=test'

    encoder.MultipartEncoder = MultipartEncoder

    blob = types.ModuleType('azure.storage.blob')
    blob.BlobServiceClient = Mock()
    blob.BlobSasPermissions = Mock()
    blob.generate_blob_sas = Mock()

    anyrun = types.ModuleType('anyrun')
    anyrun.RunTimeException = RunTimeException

    modules = {
        'requests': requests,
        'requests_toolbelt': types.ModuleType('requests_toolbelt'),
        'requests_toolbelt.multipart': types.ModuleType('requests_toolbelt.multipart'),
        'requests_toolbelt.multipart.encoder': encoder,
        'azure': types.ModuleType('azure'),
        'azure.storage': types.ModuleType('azure.storage'),
        'azure.storage.blob': blob,
        'anyrun': anyrun,
    }
    sys.modules.update(modules)

    package = types.ModuleType('connector_under_test')
    package.__path__ = [str(SOURCE_DIR)]
    sys.modules[package.__name__] = package

    spec = importlib.util.spec_from_file_location(
        'connector_under_test.defender',
        SOURCE_DIR / 'defender.py',
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_defender(module):
    defender = module.MicrosoftDefender.__new__(module.MicrosoftDefender)
    defender._config = module.Config
    defender._headers = None
    defender._token_expires_at = 0.0
    defender._deadline_monotonic = None
    defender._log = Mock()
    return defender


class MicrosoftDefenderTests(unittest.TestCase):
    def test_replayed_comment_is_not_added_when_already_present(self):
        defender = make_defender(self.module)
        defender.deduplicate_comments = True
        defender._make_request = Mock(return_value=FakeResponse(200, {'comments': [{'comment': 'same summary'}]}))
        defender.add_comment('alert', 'same summary')
        defender._make_request.assert_called_once()
        self.assertEqual(defender._make_request.call_args.args[0], 'GET')

    @classmethod
    def setUpClass(cls):
        cls.module = load_defender_module()

    def test_oauth_uses_legacy_resource(self):
        defender = make_defender(self.module)
        defender._make_request = Mock(
            return_value=FakeResponse(200, {'access_token': 'test-token'})
        )
        environment = {
            'AzureTenantID': 'tenant-id',
            'AzureClientID': 'client-id',
            'AzureClientSecret': 'client-secret',
        }

        with patch.object(self.module, 'get_env_variable', side_effect=environment.__getitem__):
            defender._authenticate()

        request = defender._make_request.call_args
        self.assertEqual(
            request.kwargs['data']['resource'],
            'https://api.securitycenter.microsoft.com',
        )
        self.assertEqual(
            request.kwargs['url'],
            'https://login.microsoftonline.com/tenant-id/oauth2/token',
        )
        self.assertFalse(request.kwargs['authenticated'])
        self.assertEqual(defender._headers['Authorization'], 'Bearer test-token')

    def test_error_boundary_redacts_sas_connection_keys_and_bearer_tokens(self):
        defender = make_defender(self.module)
        message = (
            'Network request failed for '
            'https://account.blob.core.windows.net/c/file?sv=1&sig=sas-secret '
            'AccountKey=storage-secret Bearer token-secret'
        )

        with self.assertRaises(RunTimeException) as raised:
            defender._throw_error(message)

        safe = str(raised.exception)
        self.assertNotIn('sas-secret', safe)
        self.assertNotIn('storage-secret', safe)
        self.assertNotIn('token-secret', safe)
        defender._log.error.assert_called_once()

    def test_oauth_request_does_not_reuse_defender_headers(self):
        defender = make_defender(self.module)
        defender._headers = {'Authorization': 'Bearer expired'}
        self.module.requests.request.return_value = FakeResponse(
            200,
            {'access_token': 'fresh-token', 'expires_in': 3600},
        )
        environment = {
            'AzureTenantID': 'tenant-id',
            'AzureClientID': 'client-id',
            'AzureClientSecret': 'client-secret',
        }

        with patch.object(self.module, 'get_env_variable', side_effect=environment.__getitem__):
            defender._authenticate()

        self.assertIsNone(self.module.requests.request.call_args.kwargs['headers'])
        self.assertEqual(defender._headers['Authorization'], 'Bearer fresh-token')
        self.module.requests.request.reset_mock()

    def test_live_response_200_and_201_use_modern_api_base(self):
        for status_code in (200, 201):
            with self.subTest(status_code=status_code):
                defender = make_defender(self.module)
                defender._wait_run_other_machine_actions = Mock()
                defender._make_request = Mock(
                    return_value=FakeResponse(status_code, {'id': 'action-id'})
                )

                with patch.object(self.module.time, 'sleep') as sleep:
                    result = defender._run_live_response('machine-id', {'Commands': []})

                self.assertEqual(result, 'action-id')
                sleep.assert_called_once_with(10)
                self.assertEqual(
                    defender._make_request.call_args.kwargs['url'],
                    'https://api.security.microsoft.com/api/machines/'
                    'machine-id/runliveresponse',
                )

    def test_live_response_initial_delay_occurs_only_after_acceptance(self):
        defender = make_defender(self.module)
        defender._wait_run_other_machine_actions = Mock()
        defender._make_request = Mock(side_effect=[
            FakeResponse(400, text='ActiveRequestAlreadyExists'),
            FakeResponse(201, {'id': 'action-id'}),
        ])
        events = Mock()
        events.attach_mock(defender._make_request, 'request')

        with patch.object(self.module.time, 'sleep') as sleep:
            events.attach_mock(sleep, 'sleep')
            result = defender._run_live_response('machine-id', {'Commands': []})

        self.assertEqual(result, 'action-id')
        self.assertEqual(
            [call[0] for call in events.mock_calls],
            ['request', 'sleep', 'request', 'sleep'],
        )
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [30, 10])

    def test_live_response_missing_action_id_does_not_add_initial_delay(self):
        defender = make_defender(self.module)
        defender._wait_run_other_machine_actions = Mock()
        defender._make_request = Mock(return_value=FakeResponse(201))

        with patch.object(self.module.time, 'sleep') as sleep:
            with self.assertRaises(RunTimeException):
                defender._run_live_response('machine-id', {'Commands': []})

        sleep.assert_not_called()

    def test_library_upload_builds_replayable_multipart_without_machine_context(self):
        defender = make_defender(self.module)
        defender._make_request = Mock(return_value=FakeResponse(200))

        defender.upload_ps_script_to_library('windows')

        request = defender._make_request.call_args
        self.assertIsInstance(request.kwargs['data'], self.module.MultipartEncoder)
        retry_body = request.kwargs['retry_data_factory']()
        self.assertIsInstance(retry_body, self.module.MultipartEncoder)
        self.assertIsNot(retry_body, request.kwargs['data'])

    def test_live_response_http_errors_keep_status_and_body(self):
        for status_code in (400, 403, 500):
            with self.subTest(status_code=status_code):
                body = f'{{"error":{{"code":"error-{status_code}"}}}}'
                defender = make_defender(self.module)
                defender._wait_run_other_machine_actions = Mock()
                defender._make_request = Mock(
                    return_value=FakeResponse(
                        status_code,
                        {'error': {'code': f'error-{status_code}'}},
                        body,
                    )
                )

                with patch.object(self.module.time, 'sleep') as sleep:
                    with self.assertRaises(RunTimeException) as raised:
                        defender._run_live_response('machine-id', {'Commands': []})

                sleep.assert_not_called()
                self.assertEqual(raised.exception.status_code, status_code)
                self.assertIn('Failed to execute live response job.', str(raised.exception))
                self.assertIn(f'Status code: {status_code}', str(raised.exception))
                self.assertIn(f'Response: {body}', str(raised.exception))

    def test_network_errors_are_reported_without_an_unbound_response(self):
        defender = make_defender(self.module)
        defender._headers = {}
        self.module.requests.request.side_effect = OSError('connection reset')

        with self.assertRaises(RunTimeException) as raised:
            defender._make_request('GET', 'https://example.invalid')

        self.assertIsNone(raised.exception.status_code)
        self.assertIn('Network request failed: connection reset.', str(raised.exception))

        self.module.requests.request.reset_mock(side_effect=True)

    def test_live_response_uses_one_safe_round_trip_payload_on_all_platforms(self):
        sas_token = (
            'sp=w&st=2026-09-10T10%3A00%3A00Z&se=2026-09-10T11%3A00%3A00Z'
            '&sig=abc%2F123%3D'
        )
        files = [
            (r'C:\Users\Test User\sample.exe', 'sample.exe'),
            (r'C:\Temp\a&b.exe', 'a&b.exe'),
            (r'C:\Temp\a$b!.bin', 'a$b!.bin'),
            (r'C:\Temp\semi;colon.txt', 'semi;colon.txt'),
            (r'C:\Temp\pipe|name.dat', 'pipe|name.dat'),
            ('/tmp/name with spaces/(sample)!$&;|.bin', '(sample)!$&;|.bin'),
        ]

        for platform in ('windows', 'linux'):
            with self.subTest(platform=platform):
                defender = make_defender(self.module)
                defender._wait_run_other_machine_actions = Mock()
                defender._generate_sas_token = Mock(return_value=sas_token)
                defender._run_live_response = Mock(return_value='action-id')
                defender._wait_run_script_live_response_job = Mock()
                environment = {
                    'AzureStorageAccountName': 'storageaccount',
                    'AzureBlobContainerName': 'container',
                }

                with patch.object(
                    self.module,
                    'get_env_variable',
                    side_effect=environment.__getitem__,
                ):
                    defender.execute_ps_script_on_machine(
                        'machine-id',
                        platform,
                        files,
                        'job-1',
                    )

                command = defender._run_live_response.call_args.args[1]
                args_value = command['Commands'][0]['params'][1]['value']
                prefix, encoded_payload = args_value.split(' ', 1)
                payload_parts = encoded_payload.split('.')

                self.assertEqual(prefix, '-payload')
                self.assertEqual(payload_parts[0], 'v2')
                self.assertTrue(set(encoded_payload) <= set(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.')
                )
                self.assertFalse(set(';&|!$()') & set(args_value))

                decoded_values = []
                for encoded_value in payload_parts[1:]:
                    padding = '=' * (-len(encoded_value) % 4)
                    decoded_values.append(
                        base64.urlsafe_b64decode(encoded_value + padding).decode('utf-8')
                    )

                self.assertEqual(decoded_values[:2], ['storageaccount', 'container'])
                triples = [decoded_values[index:index + 3] for index in range(2, len(decoded_values), 3)]
                self.assertEqual([item[0] for item in triples], [item[0] for item in files])
                self.assertEqual([item[2] for item in triples], [sas_token] * len(files))
                blob_names = [item[1] for item in triples]
                self.assertEqual(len(blob_names), len(set(blob_names)))
                self.assertTrue(all(name.startswith('job-1-') for name in blob_names))
                defender._wait_run_script_live_response_job.assert_called_once_with('action-id')

    def test_sandbox_indicators_are_never_allowed(self):
        defender = make_defender(self.module)
        defender._make_request = Mock(return_value=FakeResponse(200, {
            'value': [{'indicator': 'example.test', 'isFailed': False}],
        }))
        with patch.object(
            self.module,
            'get_env_variable',
            side_effect=lambda name, default=None: {
                'DefenderIndicatorAction': 'Audit',
                'DefenderIndicatorGenerateAlert': 'false',
            }.get(name, default),
        ):
            failures = defender.submit_indicators(
                [{'ioc': 'example.test', 'type': 'domain', 'reputation': 2}],
                'task-id',
            )

        request_payload = defender._make_request.call_args.kwargs['data']
        self.assertIn('"action": "Audit"', request_payload)
        self.assertIn('"generateAlert": false', request_payload)
        self.assertNotIn('Allowed', request_payload)
        self.assertEqual(failures, [])

    def test_sandbox_indicator_rejections_are_returned(self):
        defender = make_defender(self.module)
        defender._make_request = Mock(return_value=FakeResponse(200, {
            'value': [{
                'indicator': 'example.test',
                'isFailed': True,
                'failureReason': 'unsupported action',
            }],
        }))
        with patch.object(
            self.module,
            'get_env_variable',
            side_effect=lambda name, default=None: {
                'DefenderIndicatorAction': 'Audit',
                'DefenderIndicatorGenerateAlert': 'true',
            }.get(name, default),
        ):
            failures = defender.submit_indicators(
                [{'ioc': 'example.test', 'type': 'domain', 'reputation': 2}],
                'task-id',
            )

        self.assertEqual(len(failures), 1)
        defender._log.error.assert_called_once()

    def test_401_refreshes_token_and_retries_once(self):
        defender = make_defender(self.module)
        defender._headers = {'Authorization': 'Bearer old'}
        defender._token_expires_at = self.module.time.monotonic() + 3600
        defender._authenticate = Mock(side_effect=lambda: setattr(
            defender,
            '_headers',
            {'Authorization': 'Bearer new'},
        ))
        self.module.requests.request.side_effect = [
            FakeResponse(401),
            FakeResponse(200),
        ]

        response = defender._make_request('GET', 'https://api.security.microsoft.com/api/alerts/a')

        self.assertEqual(response.status_code, 200)
        defender._authenticate.assert_called_once_with()
        self.assertEqual(self.module.requests.request.call_count, 2)
        self.module.requests.request.reset_mock(side_effect=True)

    def test_401_recreates_one_shot_request_body(self):
        defender = make_defender(self.module)
        defender._headers = {'Authorization': 'Bearer old'}
        defender._token_expires_at = self.module.time.monotonic() + 3600
        defender._authenticate = Mock(side_effect=lambda: setattr(
            defender,
            '_headers',
            {'Authorization': 'Bearer new'},
        ))
        initial_body = object()
        retry_body = object()
        body_factory = Mock(return_value=retry_body)
        self.module.requests.request.side_effect = [FakeResponse(401), FakeResponse(200)]

        response = defender._make_request(
            'POST',
            'https://api.security.microsoft.com/api/libraryfiles',
            data=initial_body,
            retry_data_factory=body_factory,
        )

        self.assertEqual(response.status_code, 200)
        body_factory.assert_called_once_with()
        self.assertIs(self.module.requests.request.call_args_list[1].kwargs['data'], retry_body)
        self.module.requests.request.reset_mock(side_effect=True)

    def test_failed_av_run_cleans_up_all_planned_blobs(self):
        defender = make_defender(self.module)
        defender._wait_run_other_machine_actions = Mock()
        defender._generate_sas_token = Mock(return_value='sas')
        defender._run_live_response = Mock(return_value='action-id')
        defender._wait_run_script_live_response_job = Mock(
            side_effect=RunTimeException('run failed'),
        )
        defender.delete_files_from_storage = Mock()
        environment = {
            'AzureStorageAccountName': 'storageaccount',
            'AzureBlobContainerName': 'container',
        }

        with patch.object(self.module, 'get_env_variable', side_effect=environment.__getitem__):
            with self.assertRaises(RunTimeException):
                defender.execute_ps_script_on_machine(
                    'machine-id',
                    'windows',
                    [('C:/one.exe', 'one.exe'), ('C:/two.exe', 'two.exe')],
                    'job-1',
                )

        cleaned = defender.delete_files_from_storage.call_args.args[0]
        self.assertEqual(len(cleaned), 2)
        self.assertEqual(len(cleaned), len(set(cleaned)))

    def test_live_response_timeout_cancels_only_its_own_action(self):
        defender = make_defender(self.module)
        defender._get_live_response_action_info = Mock(
            return_value={'id': 'own-action', 'status': 'InProgress'},
        )
        defender._cancel_machine_action = Mock()

        with patch.object(defender._config, 'LIVE_RESPONSE_WAIT_SECONDS', 10):
            with patch.object(self.module.time, 'monotonic', side_effect=[0, 10]):
                with self.assertRaises(RunTimeException) as raised:
                    defender._wait_run_script_live_response_job('own-action')

        self.assertIn('exceeded 10 seconds', str(raised.exception))
        defender._cancel_machine_action.assert_called_once_with('own-action')

    def test_new_live_response_resource_not_found_is_temporarily_not_visible(self):
        defender = make_defender(self.module)
        defender._make_request = Mock(return_value=FakeResponse(
            404,
            {'error': {'code': 'ResourceNotFound'}},
            text='{"error":{"code":"ResourceNotFound"}}',
        ))

        result = defender._get_live_response_action_info('new-action')

        self.assertIsNone(result)

    def test_live_response_wait_retries_initial_resource_not_found(self):
        defender = make_defender(self.module)
        defender._get_live_response_action_info = Mock(side_effect=[
            None,
            None,
            {'id': 'new-action', 'status': 'Succeeded'},
        ])

        with patch.object(self.module.time, 'monotonic', side_effect=[0, 0, 10]):
            with patch.object(self.module.time, 'sleep') as sleep:
                result = defender._wait_run_script_live_response_job('new-action')

        self.assertEqual(result['status'], 'Succeeded')
        self.assertEqual(defender._get_live_response_action_info.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        sleep.assert_called_with(defender._config.LIVE_RESPONSE_VISIBILITY_POLL_SECONDS)

    def test_live_response_wait_bounds_resource_visibility_retries(self):
        defender = make_defender(self.module)
        defender._get_live_response_action_info = Mock(return_value=None)

        with patch.object(defender._config, 'LIVE_RESPONSE_VISIBILITY_WAIT_SECONDS', 20):
            with patch.object(self.module.time, 'monotonic', side_effect=[0, 0, 20]):
                with patch.object(self.module.time, 'sleep'):
                    with self.assertRaises(RunTimeException) as raised:
                        defender._wait_run_script_live_response_job('missing-action')

        self.assertIn('did not become visible', str(raised.exception))
        self.assertIn('Action ID: missing-action', str(raised.exception))

    def test_other_live_response_404_is_not_retried(self):
        defender = make_defender(self.module)
        defender._make_request = Mock(return_value=FakeResponse(
            404,
            {'error': {'code': 'DifferentNotFound'}},
            text='{"error":{"code":"DifferentNotFound"}}',
        ))

        with self.assertRaises(RunTimeException) as raised:
            defender._get_live_response_action_info('action-id')

        self.assertEqual(raised.exception.status_code, 404)

    def test_failed_download_is_not_returned_as_evidence(self):
        defender = make_defender(self.module)
        defender._make_request = Mock(return_value=FakeResponse(403, text='expired SAS'))

        self.assertIsNone(defender._download_file_by_link('https://storage.invalid/private'))
        defender._log.warning.assert_called_once()


if __name__ == '__main__':
    unittest.main()
