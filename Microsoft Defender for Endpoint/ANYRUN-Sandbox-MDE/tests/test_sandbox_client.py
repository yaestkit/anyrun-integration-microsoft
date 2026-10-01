import asyncio
import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

SOURCE = Path(__file__).parents[1] / 'src' / 'anyrun_mde_core'


def load_client():
    class FakeSDK:
        def __init__(self, **kwargs):
            self._enable_requests = False
            self.request = AsyncMock()

        async def _make_request_async(self, *args, **kwargs):
            try:
                return await self.request(*args, **kwargs)
            except Exception as error:
                raise RuntimeError('SDK wrapped transport error') from error

    package = types.ModuleType('bounded_client_tests')
    package.__path__ = [str(SOURCE)]
    systems = types.ModuleType('anyrun.connectors.sandbox.operation_systems')
    systems.WindowsConnector = systems.LinuxConnector = FakeSDK
    base = types.ModuleType('anyrun.connectors.sandbox.base_connector')
    base.BaseSandboxConnector = FakeSDK
    # Unit tests run without installing the SDK or network dependencies.
    aiohttp = types.ModuleType('aiohttp')
    aiohttp.ClientError = type('ClientError', (Exception,), {})
    aiohttp.ContentTypeError = type('ContentTypeError', (aiohttp.ClientError,), {})
    requests = types.ModuleType('requests')
    requests.RequestException = type('RequestException', (Exception,), {})
    spec = importlib.util.spec_from_file_location('bounded_client_tests.sandbox_client', SOURCE / 'sandbox_client.py')
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {
        package.__name__: package, systems.__name__: systems, base.__name__: base,
        'aiohttp': aiohttp, 'requests': requests,
    }):
        spec.loader.exec_module(module)
    return module


class SandboxClientTests(unittest.TestCase):
    def test_submission_uses_extended_timeout_bounded_by_budget(self):
        module = load_client()
        client = module.BoundedWindowsConnector()
        response = Mock(status=200, json=AsyncMock(return_value={'data': {}}))
        client.request.return_value = response
        asyncio.run(client._make_request_async('POST', 'https://api.any.run/v1/analysis'))
        self.assertEqual(client.request.call_args.kwargs['request_timeout'], 300)
        asyncio.run(client._make_request_async('GET', 'https://api.any.run/v1/analysis/uuid'))
        self.assertEqual(client.request.call_args.kwargs['request_timeout'], 60)
        client.deadline_monotonic = 12
        with patch.object(module.time, 'monotonic', return_value=0):
            asyncio.run(client._make_request_async('POST', 'https://api.any.run/v1/analysis'))
        self.assertEqual(client.request.call_args.kwargs['request_timeout'], 12)

    def test_http_errors_keep_structured_codes_including_non_json(self):
        module = load_client()
        for code in (400, 401, 403, 404, 409, 413, 422, 425, 429, 503):
            client = module.BoundedWindowsConnector()
            client.request.return_value = Mock(status=code, json=AsyncMock(return_value={'message': 'rejected'}))
            with self.assertRaises(module.SandboxAPIError) as error:
                asyncio.run(client._make_request_async('GET', 'https://api.any.run/v1/analysis/uuid'))
            self.assertEqual(error.exception.status_code, code)
        client.request.return_value.json.side_effect = ValueError('HTML response')
        with self.assertRaises(module.SandboxAPIError) as error:
            asyncio.run(client._make_request_async('GET', 'https://api.any.run/v1/analysis/uuid'))
        self.assertEqual(error.exception.status_code, 503)

    def test_wrapped_transport_error_keeps_unknown_outcome_type(self):
        module = load_client()
        client = module.BoundedWindowsConnector()
        client.request.side_effect = TimeoutError('network timeout')
        with self.assertRaises(module.SandboxTransportError):
            asyncio.run(client._make_request_async('POST', 'https://api.any.run/v1/analysis'))

    def test_requests_path_preserves_codes(self):
        module = load_client()
        client = module.BoundedWindowsConnector()
        client._enable_requests = True
        client.request.return_value = Mock(status_code=429, json=Mock(return_value={'message': 'rate limit'}))
        with self.assertRaises(module.SandboxAPIError) as error:
            asyncio.run(client._make_request_async('GET', 'https://api.any.run/v1/analysis/uuid'))
        self.assertEqual(error.exception.status_code, 429)

    def test_expired_deadline_prevents_any_request(self):
        module = load_client()
        client = module.BoundedWindowsConnector(deadline_monotonic=-1)
        with self.assertRaises(TimeoutError):
            asyncio.run(client._make_request_async('POST', 'https://api.any.run/v1/analysis'))
        client.request.assert_not_called()

    def test_capture_only_exposes_completion_metadata_not_sample_or_credentials(self):
        script = SOURCE.parents[2] / 'Scripts' / 'capture_sandbox_report.py'
        spec = importlib.util.spec_from_file_location('capture_metadata_test', script)
        capture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(capture)
        payload = {'data': {'status': 'RUNNING', 'remaining': 30, 'api_key': 'secret-key',
                            'analysis': {'sample': 'private.exe', 'url': 'https://example.test/?sig=SECRET',
                                         'scores': {'verdict': {'threatLevelText': 'No threats detected', 'score': 0}}}}}
        result = capture.metadata(payload)
        self.assertEqual(result['data.status'], 'RUNNING')
        self.assertEqual(result['data.remaining'], 30)
        for secret in ('private.exe', 'sig=SECRET', 'secret-key'):
            self.assertNotIn(secret, json.dumps(result))

    def test_capture_missing_fields_do_not_invent_completion(self):
        script = SOURCE.parents[2] / 'Scripts' / 'capture_sandbox_report.py'
        spec = importlib.util.spec_from_file_location('capture_missing_metadata_test', script)
        capture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(capture)
        self.assertTrue(all(value is None for value in capture.metadata({'data': None}).values()))
