import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import ANY, Mock


COMPONENT_DIR = Path(__file__).parents[1]
SOURCE_DIR = COMPONENT_DIR / 'src'
HTTP_DIR = SOURCE_DIR / 'ANYRUN-Sandbox-MDE-FA'
WORKER_DIR = SOURCE_DIR / 'ANYRUN-Sandbox-MDE-Worker'
LOGIC_TEMPLATE = COMPONENT_DIR / 'Logic App' / 'ANYRUN-Sandbox-MDE-LA.json'


class FakeHttpResponse:
    def __init__(self, body, status_code, mimetype=None):
        self.body = body
        self.status_code = status_code
        self.mimetype = mimetype


class FakeRequest:
    def __init__(self, body, params=None):
        self._body = body
        self.params = params or {}

    def get_json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeOutput:
    def __init__(self):
        self.value = None

    def set(self, value):
        self.value = value


class FakeQueueMessage:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode('utf-8')

    def get_body(self):
        return self._body


def install_azure_functions_stub():
    azure = types.ModuleType('azure')
    functions = types.ModuleType('azure.functions')
    functions.HttpResponse = FakeHttpResponse
    functions.HttpRequest = object
    functions.Out = object
    functions.QueueMessage = object
    azure.functions = functions
    sys.modules['azure'] = azure
    sys.modules['azure.functions'] = functions


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AsyncContractTests(unittest.TestCase):
    def setUp(self):
        install_azure_functions_stub()

    def test_http_function_enqueues_and_returns_202(self):
        module = load_module('http_function_under_test', HTTP_DIR / 'anyrun_connector.py')
        output = FakeOutput()
        request = FakeRequest({
            'alert_id': 'alert-1',
            'alert_source': 'WindowsDefenderAtp',
            'machine_os_platform': 'windows',
            'analysis_options': {'opt_timeout': 240},
        })

        response = module.main(request, output)

        self.assertEqual(response.status_code, 202)
        queued = json.loads(output.value)
        self.assertEqual(queued['alert_id'], 'alert-1')
        self.assertEqual(queued['analysis_options']['opt_timeout'], 240)
        self.assertTrue(queued['job_id'])
        self.assertEqual(json.loads(response.body)['job_id'], queued['job_id'])

    def test_http_function_rejects_incomplete_request_without_enqueuing(self):
        module = load_module('invalid_http_function_under_test', HTTP_DIR / 'anyrun_connector.py')
        output = FakeOutput()

        response = module.main(FakeRequest({'alert_id': 'alert-1'}), output)

        self.assertEqual(response.status_code, 400)
        self.assertIsNone(output.value)

    def test_http_function_rejects_unsupported_alert_source(self):
        module = load_module('unsupported_http_function_under_test', HTTP_DIR / 'anyrun_connector.py')
        output = FakeOutput()
        response = module.main(FakeRequest({
            'alert_id': 'alert-1',
            'alert_source': 'UnsupportedSource',
            'machine_os_platform': 'windows',
            'analysis_options': {'opt_timeout': 240},
        }), output)

        self.assertEqual(response.status_code, 400)
        self.assertIsNone(output.value)

    def test_http_function_accepts_query_only_request(self):
        module = load_module('query_http_function_under_test', HTTP_DIR / 'anyrun_connector.py')
        output = FakeOutput()
        response = module.main(FakeRequest(ValueError('no body'), params={
            'alert_id': 'alert-1',
            'alert_source': 'WindowsDefenderAtp',
            'machine_os_platform': 'windows',
            'analysis_options': '{"opt_timeout": 240}',
        }), output)

        self.assertEqual(response.status_code, 202)
        self.assertEqual(json.loads(output.value)['analysis_options']['opt_timeout'], 240)

    def test_worker_authenticates_and_processes_queued_job(self):
        process_alert = Mock()
        get_env_variable = Mock(return_value='api-key')

        class FakeConnector:
            checked = False

            def __init__(self, api_key, integration):
                self.api_key = api_key
                self.integration = integration

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def check_authorization(self):
                type(self).checked = True

        anyrun = types.ModuleType('anyrun')
        connectors = types.ModuleType('anyrun.connectors')
        sandbox = types.ModuleType('anyrun.connectors.sandbox')
        base = types.ModuleType('anyrun.connectors.sandbox.base_connector')
        base.BaseSandboxConnector = FakeConnector
        sys.modules.update({
            'anyrun': anyrun,
            'anyrun.connectors': connectors,
            'anyrun.connectors.sandbox': sandbox,
            'anyrun.connectors.sandbox.base_connector': base,
        })

        core = types.ModuleType('anyrun_mde_core')
        config = types.ModuleType('anyrun_mde_core.config')
        config.Config = type('Config', (), {
            'VERSION': 'test',
            'JOB_TIME_BUDGET_SECONDS': 5400,
        })
        processor = types.ModuleType('anyrun_mde_core.processor')
        processor.process_alert = process_alert
        defender = types.ModuleType('anyrun_mde_core.defender')
        defender.MicrosoftDefender = Mock()
        utils = types.ModuleType('anyrun_mde_core.utils')
        utils.get_env_variable = get_env_variable
        sys.modules.update({
            'anyrun_mde_core': core,
            'anyrun_mde_core.config': config,
            'anyrun_mde_core.defender': defender,
            'anyrun_mde_core.processor': processor,
            'anyrun_mde_core.utils': utils,
        })

        module = load_module('queue_worker_under_test', WORKER_DIR / 'worker.py')
        payload = {
            'job_id': 'job-1',
            'alert_id': 'alert-1',
            'alert_source': 'WindowsDefenderAtp',
            'machine_os_platform': 'windows',
            'analysis_options': {'opt_timeout': 240},
        }

        module.main(FakeQueueMessage(payload))

        self.assertTrue(FakeConnector.checked)
        process_alert.assert_called_once_with(
            job_id='job-1',
            alert_id='alert-1',
            alert_source='WindowsDefenderAtp',
            machine_os_platform='windows',
            analysis_options={'opt_timeout': 240},
            deadline_monotonic=ANY,
        )

    def test_worker_comments_on_alert_and_reraises_failure(self):
        process_alert = Mock(side_effect=RuntimeError('sample submission failed'))
        defender_client = Mock()

        class FakeConnector:
            def __init__(self, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def check_authorization(self):
                pass

        anyrun = types.ModuleType('anyrun')
        connectors = types.ModuleType('anyrun.connectors')
        sandbox = types.ModuleType('anyrun.connectors.sandbox')
        base = types.ModuleType('anyrun.connectors.sandbox.base_connector')
        base.BaseSandboxConnector = FakeConnector
        core = types.ModuleType('anyrun_mde_core')
        config = types.ModuleType('anyrun_mde_core.config')
        config.Config = type('Config', (), {
            'VERSION': 'test',
            'JOB_TIME_BUDGET_SECONDS': 5400,
        })
        processor = types.ModuleType('anyrun_mde_core.processor')
        processor.process_alert = process_alert
        defender = types.ModuleType('anyrun_mde_core.defender')
        defender.MicrosoftDefender = Mock(return_value=defender_client)
        utils = types.ModuleType('anyrun_mde_core.utils')
        utils.get_env_variable = Mock(return_value='api-key')
        sys.modules.update({
            'anyrun': anyrun,
            'anyrun.connectors': connectors,
            'anyrun.connectors.sandbox': sandbox,
            'anyrun.connectors.sandbox.base_connector': base,
            'anyrun_mde_core': core,
            'anyrun_mde_core.config': config,
            'anyrun_mde_core.defender': defender,
            'anyrun_mde_core.processor': processor,
            'anyrun_mde_core.utils': utils,
        })
        module = load_module('failed_queue_worker_under_test', WORKER_DIR / 'worker.py')
        payload = {
            'job_id': 'job-failed',
            'alert_id': 'alert-failed',
            'alert_source': 'WindowsDefenderAtp',
            'machine_os_platform': 'windows',
            'analysis_options': {'opt_timeout': 240},
        }

        with self.assertRaisesRegex(RuntimeError, 'sample submission failed'):
            module.main(FakeQueueMessage(payload))

        defender_client.add_comment.assert_called_once()
        alert_id, comment = defender_client.add_comment.call_args.args
        self.assertEqual(alert_id, 'alert-failed')
        self.assertIn('job-failed', comment)
        self.assertIn('sample submission failed', comment)

    def test_http_and_worker_bindings_use_the_same_queue(self):
        http = json.loads((HTTP_DIR / 'function.json').read_text())
        worker = json.loads((WORKER_DIR / 'function.json').read_text())
        output = next(binding for binding in http['bindings'] if binding['type'] == 'queue')
        trigger = next(binding for binding in worker['bindings'] if binding['type'] == 'queueTrigger')

        self.assertEqual(output['queueName'], 'anyrun-mde-jobs')
        self.assertEqual(output['queueName'], trigger['queueName'])
        self.assertEqual(output['connection'], trigger['connection'])

    def test_logic_app_disables_polling_for_fire_and_forget_202(self):
        self.assertEqual(LOGIC_TEMPLATE.read_text().count('DisableAsyncPattern'), 2)


if __name__ == '__main__':
    unittest.main()
