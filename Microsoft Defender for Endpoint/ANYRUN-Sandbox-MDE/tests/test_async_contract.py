import importlib.util
import json
import sys
import types
import unittest
import asyncio
from datetime import datetime, timedelta, timezone
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import ANY, Mock, patch


COMPONENT_DIR = Path(__file__).parents[1]
SOURCE_DIR = COMPONENT_DIR / 'src'
HTTP_DIR = SOURCE_DIR / 'ANYRUN-Sandbox-MDE-FA'
WORKER_DIR = SOURCE_DIR / 'ANYRUN-Sandbox-MDE-Worker'
STATUS_DIR = SOURCE_DIR / 'ANYRUN-Sandbox-MDE-Status'
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
    def __init__(self, payload, dequeue_count=1):
        self._body = json.dumps(payload).encode('utf-8')
        self.dequeue_count = dequeue_count

    def get_body(self):
        return self._body


class RecoveryRequired(RuntimeError):
    pass


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
    def payload(self):
        return {'job_id': 'job-recovery', 'alert_id': 'alert', 'alert_source': 'WindowsDefenderAtp',
                'machine_os_platform': 'windows', 'analysis_options': {'opt_timeout': 240}}

    def test_stale_projection_is_read_only_and_keeps_fresh_and_terminal_jobs(self):
        module = load_module('stale_status_under_test', STATUS_DIR / 'status.py')
        now = datetime.now(timezone.utc)
        status = {'state': 'waiting_for_verdict', 'updated_at': (now - timedelta(minutes=16)).isoformat(),
                  'latest_analysis': {'task_uuid': 'paid-task'}}
        stale = module._mark_stale(status, now)
        self.assertEqual(stale['stage'], 'stale')
        self.assertEqual(stale['error_type'], 'StaleJob')
        self.assertEqual(status['state'], 'waiting_for_verdict')
        self.assertEqual(stale['latest_analysis']['task_uuid'], 'paid-task')
        fresh = {**status, 'updated_at': (now - timedelta(minutes=11)).isoformat()}
        self.assertEqual(module._mark_stale(fresh, now), fresh)  # Survives Azure's 10-minute crash lock.
        completed = {**status, 'state': 'completed'}
        self.assertEqual(module._mark_stale(completed, now), completed)

    def test_base_exception_remains_recoverable_until_final_attempt(self):
        process = Mock(side_effect=asyncio.CancelledError())
        module, defender = self._load_worker_for_test('interrupted_worker', process)
        with self.assertRaises(asyncio.CancelledError):
            module.main(FakeQueueMessage(self.payload(), dequeue_count=1))
        self.assertEqual(self.status_store.update.call_args.kwargs['state'], 'retrying')
        self.assertEqual(self.status_store.update.call_args.kwargs['stage'], 'interrupted')
        defender.add_comment.assert_not_called()
        with self.assertRaises(asyncio.CancelledError):
            module.main(FakeQueueMessage(self.payload(), dequeue_count=3))
        self.assertEqual(self.status_store.update.call_args.kwargs['state'], 'failed')

    def test_transient_failure_is_retrying_and_same_state_is_passed_on_resume(self):
        process = Mock(side_effect=RuntimeError('temporary API failure'))
        module, defender = self._load_worker_for_test('retry_worker', process)
        state = {'state': 'waiting_for_verdict', 'analyses': [{'task_uuid': 'paid-task'}]}
        self.status_store.get.return_value = state
        with self.assertRaisesRegex(RuntimeError, 'temporary API'):
            module.main(FakeQueueMessage(self.payload(), dequeue_count=2))
        self.assertEqual(process.call_args.kwargs['resume_state'], state)
        self.assertEqual(self.status_store.update.call_args.kwargs['state'], 'retrying')
        self.assertEqual(self.status_store.update.call_args_list[0].kwargs['stage'], 'resumed')
        defender.add_comment.assert_not_called()

    def test_completed_queue_redelivery_does_not_start_business_work(self):
        process = Mock()
        module, _ = self._load_worker_for_test('completed_redelivery_worker', process)
        self.status_store.get.return_value = {'state': 'completed'}
        module.main(FakeQueueMessage(self.payload(), dequeue_count=2))
        process.assert_not_called()

    def test_fully_enriched_checkpoints_restore_completed_without_sandbox_calls(self):
        process = Mock()
        module, _ = self._load_worker_for_test('tracking_only_worker', process)
        self.status_store.get.return_value = {
            'state': 'analysis_completed', 'evidence_count': 1,
            'analyses': [{'task_uuid': 'paid-task', 'enriched': True}],
        }
        module.main(FakeQueueMessage(self.payload(), dequeue_count=2))
        process.assert_not_called()
        module.get_env_variable.assert_not_called()
        self.assertEqual(self.status_store.update.call_args.kwargs['state'], 'completed')

    def test_durable_checkpoint_failure_aborts_before_paid_submission(self):
        submitted = Mock()

        def process(**kwargs):
            kwargs['checkpoint_callback']('submitting_to_anyrun', {'evidence_key': 'key', 'submission_intent': True})
            submitted()

        module, _ = self._load_worker_for_test('checkpoint_failure_worker', process)
        module.time.sleep = Mock()
        self.status_store.update.side_effect = RuntimeError('Storage down')
        with self.assertRaisesRegex(RuntimeError, 'Durable analysis checkpoint'):
            module.main(FakeQueueMessage(self.payload()))
        submitted.assert_not_called()

    def test_heartbeat_failure_does_not_stop_lease_renewal_or_business(self):
        module, _ = self._load_worker_for_test('heartbeat_worker', Mock())
        stop, lease, lost = Mock(), Mock(), Mock()
        stop.wait.side_effect = [False, False, True]
        self.status_store.touch.side_effect = RuntimeError('temporary heartbeat failure')
        with patch.object(module.time, 'monotonic', side_effect=[0, 20, 20, 60, 60, 40, 40, 120, 120]):
            module._keep_alive(self.status_store, 'job', lease, stop, lost)
        self.assertEqual(lease.renew.call_count, 2)
        self.assertEqual(self.status_store.touch.call_count, 2)
        lost.set.assert_not_called()

    def test_lost_lease_stops_heartbeats(self):
        module, _ = self._load_worker_for_test('lease_lost_worker', Mock())
        stop, lease, lost = Mock(), Mock(), Mock()
        stop.wait.return_value = False
        lease.renew.side_effect = RuntimeError('lease expired')
        lease.renew.side_effect.error_code = 'LeaseLost'
        module._keep_alive(self.status_store, 'job', lease, stop, lost)
        lost.set.assert_called_once()
        self.status_store.touch.assert_not_called()

    def test_transient_lease_renewal_failure_recovers_within_lease_lifetime(self):
        module, _ = self._load_worker_for_test('temporary_lease_failure_worker', Mock())
        stop, lease, lost = Mock(), Mock(), Mock()
        stop.wait.side_effect = [False, False, True]
        lease.renew.side_effect = [RuntimeError('Storage temporarily unavailable'), None]
        with patch.object(module.time, 'monotonic', side_effect=[0, 20, 20, 40, 40, 40]):
            module._keep_alive(self.status_store, 'job', lease, stop, lost)
        self.assertEqual(lease.renew.call_count, 2)
        lost.set.assert_not_called()

    def test_lease_expiry_deadline_stops_worker_without_reacquiring(self):
        module, _ = self._load_worker_for_test('lease_deadline_worker', Mock())
        stop, lease, lost = Mock(), Mock(), Mock()
        stop.wait.side_effect = [False, False, False]
        lease.renew.side_effect = RuntimeError('temporary network failure')
        with patch.object(module.time, 'monotonic', side_effect=[0, 20, 20, 40, 40, 60]):
            module._keep_alive(self.status_store, 'job', lease, stop, lost)
        self.assertEqual(lease.renew.call_count, 2)
        lost.set.assert_called_once()

    def test_lease_contention_does_not_acknowledge_or_mutate_the_job(self):
        module, _ = self._load_worker_for_test('lease_contention_worker', Mock())
        self.status_store.claim.side_effect = RuntimeError('LeaseAlreadyPresent')
        with self.assertRaisesRegex(RuntimeError, 'LeaseAlreadyPresent'):
            module.main(FakeQueueMessage(self.payload()))
        self.status_store.update.assert_not_called()

    def test_permanent_submission_rejection_is_terminal_on_first_attempt(self):
        from anyrun_mde_core.api_errors import SubmissionRejected
        module, defender = self._load_worker_for_test('rejected_submission_worker', Mock(side_effect=SubmissionRejected('HTTP 400')))
        with self.assertRaises(SubmissionRejected):
            module.main(FakeQueueMessage(self.payload()))
        self.assertEqual(self.status_store.update.call_args.kwargs['state'], 'failed')
        defender.add_comment.assert_called_once()

    def setUp(self):
        install_azure_functions_stub()
        load_module('anyrun_mde_core.api_errors', SOURCE_DIR / 'anyrun_mde_core' / 'api_errors.py')
        self.status_store = Mock()
        self.status_store.get.return_value = {'state': 'queued', 'analyses': []}
        self.status_store.claim.side_effect = lambda _job_id: nullcontext(Mock())
        config = load_module('anyrun_mde_core.config', SOURCE_DIR / 'anyrun_mde_core' / 'config.py')
        job_status = types.ModuleType('anyrun_mde_core.job_status')
        job_status.JobStatusStore = Mock()
        job_status.JobStatusStore.from_environment.return_value = self.status_store
        sys.modules['anyrun_mde_core.job_status'] = job_status
        utils = types.ModuleType('anyrun_mde_core.utils')
        utils.sanitize_error_text = lambda value, limit=500: str(value)[:limit]
        sys.modules['anyrun_mde_core.utils'] = utils

    def _load_worker_for_test(self, name, process_alert, defender_client=None):
        defender_client = defender_client or Mock()

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
        bounded = types.ModuleType('anyrun_mde_core.sandbox_client')
        bounded.BoundedBaseConnector = FakeConnector
        sys.modules[bounded.__name__] = bounded
        core = types.ModuleType('anyrun_mde_core')
        config = types.ModuleType('anyrun_mde_core.config')
        config.Config = type('Config', (), {
            'VERSION': 'test',
            'JOB_TIME_BUDGET_SECONDS': 5400,
            'HEARTBEAT_SECONDS': 60, 'QUEUE_MAX_DEQUEUE_COUNT': 3,
        })
        processor = types.ModuleType('anyrun_mde_core.processor')
        processor.process_alert = process_alert
        processor.RecoveryRequired = RecoveryRequired
        defender = types.ModuleType('anyrun_mde_core.defender')
        defender.MicrosoftDefender = Mock(return_value=defender_client)
        job_status = types.ModuleType('anyrun_mde_core.job_status')
        job_status.JobStatusStore = Mock()
        job_status.JobStatusStore.from_environment.return_value = self.status_store
        utils = types.ModuleType('anyrun_mde_core.utils')
        utils.get_env_variable = Mock(return_value='api-key')
        utils.sanitize_error_text = lambda value, limit=500: str(value)[:limit]
        sys.modules.update({
            'anyrun': anyrun,
            'anyrun.connectors': connectors,
            'anyrun.connectors.sandbox': sandbox,
            'anyrun.connectors.sandbox.base_connector': base,
            'anyrun_mde_core': core,
            'anyrun_mde_core.config': config,
            'anyrun_mde_core.defender': defender,
            'anyrun_mde_core.job_status': job_status,
            'anyrun_mde_core.processor': processor,
            'anyrun_mde_core.utils': utils,
        })
        return load_module(name, WORKER_DIR / 'worker.py'), defender_client

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
        self.status_store.create.assert_called_once_with(queued['job_id'], 'alert-1')

    def test_http_function_rejects_incomplete_request_without_enqueuing(self):
        module = load_module('invalid_http_function_under_test', HTTP_DIR / 'anyrun_connector.py')
        output = FakeOutput()

        response = module.main(FakeRequest({'alert_id': 'alert-1'}), output)

        self.assertEqual(response.status_code, 400)
        self.assertIsNone(output.value)

    def test_http_function_does_not_enqueue_when_status_creation_fails(self):
        self.status_store.create.side_effect = RuntimeError('storage unavailable')
        module = load_module('failed_status_http_function_under_test', HTTP_DIR / 'anyrun_connector.py')
        output = FakeOutput()
        request = FakeRequest({
            'alert_id': 'alert-1',
            'alert_source': 'WindowsDefenderAtp',
            'machine_os_platform': 'windows',
            'analysis_options': {'opt_timeout': 240},
        })

        with patch.object(module.time, 'sleep'):
            response = module.main(request, output)

        self.assertEqual(response.status_code, 500)
        self.assertIsNone(output.value)
        self.assertEqual(self.status_store.create.call_count, 3)

    def test_http_function_retries_transient_status_creation_before_enqueuing(self):
        self.status_store.create.side_effect = [
            RuntimeError('temporary storage failure'),
            None,
        ]
        module = load_module('retry_status_http_function_under_test', HTTP_DIR / 'anyrun_connector.py')
        output = FakeOutput()
        request = FakeRequest({
            'alert_id': 'alert-1',
            'alert_source': 'WindowsDefenderAtp',
            'machine_os_platform': 'windows',
            'analysis_options': {'opt_timeout': 240},
        })

        with patch.object(module.time, 'sleep') as sleep:
            response = module.main(request, output)

        self.assertEqual(response.status_code, 202)
        queued = json.loads(output.value)
        self.assertEqual(self.status_store.create.call_count, 2)
        self.assertEqual(
            self.status_store.create.call_args_list[0].args,
            self.status_store.create.call_args_list[1].args,
        )
        self.assertEqual(self.status_store.create.call_args.args[0], queued['job_id'])
        sleep.assert_called_once_with(1)

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
        process_alert = Mock(return_value=[{'task_uuid': 'task-1'}])
        get_env_variable = Mock(return_value='api-key')

        class FakeConnector:
            checked = False

            def __init__(self, api_key, integration, **_kwargs):
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
        bounded = types.ModuleType('anyrun_mde_core.sandbox_client')
        bounded.BoundedBaseConnector = FakeConnector
        sys.modules[bounded.__name__] = bounded
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
            'HEARTBEAT_SECONDS': 60, 'QUEUE_MAX_DEQUEUE_COUNT': 3,
        })
        processor = types.ModuleType('anyrun_mde_core.processor')
        processor.process_alert = process_alert
        processor.RecoveryRequired = RecoveryRequired
        defender = types.ModuleType('anyrun_mde_core.defender')
        defender.MicrosoftDefender = Mock()
        job_status = types.ModuleType('anyrun_mde_core.job_status')
        job_status.JobStatusStore = Mock()
        job_status.JobStatusStore.from_environment.return_value = self.status_store
        utils = types.ModuleType('anyrun_mde_core.utils')
        utils.get_env_variable = get_env_variable
        utils.sanitize_error_text = lambda value, limit=500: str(value)[:limit]
        sys.modules.update({
            'anyrun_mde_core': core,
            'anyrun_mde_core.config': config,
            'anyrun_mde_core.defender': defender,
            'anyrun_mde_core.job_status': job_status,
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
            status_callback=ANY,
            checkpoint_callback=ANY,
            resume_state={'state': 'queued', 'analyses': []},
        )
        completed = [
            call for call in self.status_store.update.call_args_list
            if call.kwargs.get('state') == 'completed'
        ]
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].kwargs['analyses'], [{'task_uuid': 'task-1'}])

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
        bounded = types.ModuleType('anyrun_mde_core.sandbox_client')
        bounded.BoundedBaseConnector = FakeConnector
        sys.modules[bounded.__name__] = bounded
        core = types.ModuleType('anyrun_mde_core')
        config = types.ModuleType('anyrun_mde_core.config')
        config.Config = type('Config', (), {
            'VERSION': 'test',
            'JOB_TIME_BUDGET_SECONDS': 5400,
            'HEARTBEAT_SECONDS': 60, 'QUEUE_MAX_DEQUEUE_COUNT': 3,
        })
        processor = types.ModuleType('anyrun_mde_core.processor')
        processor.process_alert = process_alert
        processor.RecoveryRequired = RecoveryRequired
        defender = types.ModuleType('anyrun_mde_core.defender')
        defender.MicrosoftDefender = Mock(return_value=defender_client)
        job_status = types.ModuleType('anyrun_mde_core.job_status')
        job_status.JobStatusStore = Mock()
        job_status.JobStatusStore.from_environment.return_value = self.status_store
        utils = types.ModuleType('anyrun_mde_core.utils')
        utils.get_env_variable = Mock(return_value='api-key')
        utils.sanitize_error_text = lambda value, limit=500: str(value)[:limit]
        sys.modules.update({
            'anyrun': anyrun,
            'anyrun.connectors': connectors,
            'anyrun.connectors.sandbox': sandbox,
            'anyrun.connectors.sandbox.base_connector': base,
            'anyrun_mde_core': core,
            'anyrun_mde_core.config': config,
            'anyrun_mde_core.defender': defender,
            'anyrun_mde_core.job_status': job_status,
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
            module.main(FakeQueueMessage(payload, dequeue_count=3))

        defender_client.add_comment.assert_called_once()
        alert_id, comment = defender_client.add_comment.call_args.args
        self.assertEqual(alert_id, 'alert-failed')
        self.assertIn('job-failed', comment)
        self.assertIn('sample submission failed', comment)
        failed = [
            call for call in self.status_store.update.call_args_list
            if call.kwargs.get('state') == 'failed'
        ]
        self.assertEqual(len(failed), 1)

    def test_worker_fails_when_no_evidence_was_submitted(self):
        module, defender_client = self._load_worker_for_test(
            'empty_queue_worker_under_test',
            Mock(return_value=[]),
        )
        payload = {
            'job_id': 'job-empty',
            'alert_id': 'alert-empty',
            'alert_source': 'WindowsDefenderAtp',
            'machine_os_platform': 'windows',
            'analysis_options': {'opt_timeout': 240},
        }

        with self.assertRaisesRegex(RuntimeError, 'No alert evidence'):
            module.main(FakeQueueMessage(payload, dequeue_count=3))

        failed = [
            call for call in self.status_store.update.call_args_list
            if call.kwargs.get('state') == 'failed'
        ]
        self.assertEqual(len(failed), 1)
        defender_client.add_comment.assert_called_once()

    def test_intermediate_status_failure_does_not_abort_analysis(self):
        def process_alert(**kwargs):
            kwargs['status_callback'](
                'submitted_to_anyrun',
                {'latest_analysis': {'task_uuid': 'task-1'}},
            )
            return [{'task_uuid': 'task-1'}]

        module, _ = self._load_worker_for_test(
            'resilient_queue_worker_under_test',
            process_alert,
        )
        module.time.sleep = Mock()
        self.status_store.update.side_effect = [
            None,
            RuntimeError('temporary blob failure'),
            RuntimeError('temporary blob failure'),
            RuntimeError('temporary blob failure'),
            None,
        ]
        payload = {
            'job_id': 'job-resilient',
            'alert_id': 'alert-resilient',
            'alert_source': 'WindowsDefenderAtp',
            'machine_os_platform': 'windows',
            'analysis_options': {'opt_timeout': 240},
        }

        module.main(FakeQueueMessage(payload))

        completed = [
            call for call in self.status_store.update.call_args_list
            if call.kwargs.get('state') == 'completed'
        ]
        self.assertEqual(len(completed), 1)

    def test_initial_status_failure_does_not_abort_analysis(self):
        process_alert = Mock(return_value=[{'task_uuid': 'task-1'}])
        module, _ = self._load_worker_for_test(
            'initial_status_failure_worker_under_test',
            process_alert,
        )
        module.time.sleep = Mock()
        self.status_store.update.side_effect = [
            RuntimeError('temporary blob failure'),
            RuntimeError('temporary blob failure'),
            RuntimeError('temporary blob failure'),
            None,
        ]

        module.main(FakeQueueMessage({
            'job_id': 'job-initial-status',
            'alert_id': 'alert-initial-status',
            'alert_source': 'WindowsDefenderAtp',
            'machine_os_platform': 'windows',
            'analysis_options': {'opt_timeout': 240},
        }))

        process_alert.assert_called_once()
        self.assertEqual(
            self.status_store.update.call_args_list[-1].kwargs['state'],
            'completed',
        )

    def test_final_status_failure_requests_safe_checkpoint_recovery(self):
        module, defender_client = self._load_worker_for_test(
            'final_status_failure_worker_under_test',
            Mock(return_value=[{'task_uuid': 'task-1'}]),
        )
        module.time.sleep = Mock()
        self.status_store.update.side_effect = [
            None,
            RuntimeError('persistent blob failure'),
            RuntimeError('persistent blob failure'),
            RuntimeError('persistent blob failure'),
            RuntimeError('persistent blob failure'),
            RuntimeError('persistent blob failure'),
        ]

        with self.assertRaisesRegex(RuntimeError, 'safe recovery will retry'):
            module.main(FakeQueueMessage({
                'job_id': 'job-final-status',
                'alert_id': 'alert-final-status',
                'alert_source': 'WindowsDefenderAtp',
                'machine_os_platform': 'windows',
                'analysis_options': {'opt_timeout': 240},
            }))

        defender_client.add_comment.assert_called_once()
        self.assertIn(
            'analysis completed',
            defender_client.add_comment.call_args.args[1],
        )

    def test_status_retry_loop_stops_when_its_time_budget_is_exhausted(self):
        module, _ = self._load_worker_for_test(
            'bounded_status_retry_worker_under_test',
            Mock(),
        )
        self.status_store.update.side_effect = RuntimeError('storage unavailable')

        with patch.object(module.time, 'monotonic', side_effect=[0, 0, 11]), \
                patch.object(module.time, 'sleep'):
            persisted = module._persist_status(
                self.status_store,
                'job-bounded',
                state='processing',
                attempts=5,
                budget_seconds=10,
            )

        self.assertFalse(persisted)
        self.status_store.update.assert_called_once()

    def test_http_and_worker_bindings_use_the_same_queue(self):
        http = json.loads((HTTP_DIR / 'function.json').read_text())
        worker = json.loads((WORKER_DIR / 'function.json').read_text())
        host = json.loads((SOURCE_DIR / 'host.json').read_text())
        output = next(binding for binding in http['bindings'] if binding['type'] == 'queue')
        trigger = next(binding for binding in worker['bindings'] if binding['type'] == 'queueTrigger')

        self.assertEqual(output['queueName'], 'anyrun-mde-jobs')
        self.assertEqual(output['queueName'], trigger['queueName'])
        self.assertEqual(output['connection'], trigger['connection'])
        config = load_module('queue_settings_config', SOURCE_DIR / 'anyrun_mde_core' / 'config.py')
        self.assertEqual(host['extensions']['queues']['maxDequeueCount'], config.Config.QUEUE_MAX_DEQUEUE_COUNT)

    def test_status_function_returns_persisted_job_state(self):
        expected = {'job_id': 'job-1', 'state': 'completed'}
        self.status_store.get.return_value = expected
        module = load_module('status_function_under_test', STATUS_DIR / 'status.py')

        response = module.main(FakeRequest({'job_id': 'job-1'}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body), expected)
        self.status_store.get.assert_called_once_with('job-1')

    def test_status_function_returns_400_for_invalid_job_id(self):
        self.status_store.get.side_effect = ValueError('Invalid ANY.RUN job ID.')
        module = load_module('invalid_status_function_under_test', STATUS_DIR / 'status.py')

        response = module.main(FakeRequest({'job_id': '../secret'}))

        self.assertEqual(response.status_code, 400)

    def test_status_function_returns_404_for_missing_job(self):
        self.status_store.get.return_value = None
        module = load_module('missing_status_function_under_test', STATUS_DIR / 'status.py')

        response = module.main(FakeRequest({'job_id': 'missing-job'}))

        self.assertEqual(response.status_code, 404)

    def test_status_function_returns_500_for_storage_failure(self):
        self.status_store.get.side_effect = RuntimeError('storage unavailable')
        module = load_module('failed_status_function_under_test', STATUS_DIR / 'status.py')

        response = module.main(FakeRequest({'job_id': 'job-1'}))

        self.assertEqual(response.status_code, 500)

    def test_queue_retries_after_one_minute_without_changing_attempt_limit(self):
        host = json.loads((SOURCE_DIR / 'host.json').read_text())
        queue = host['extensions']['queues']

        self.assertEqual(queue['visibilityTimeout'], '00:01:00')
        self.assertEqual(queue['maxDequeueCount'], 3)
        self.assertEqual(queue['batchSize'], 1)
        self.assertEqual(queue['newBatchThreshold'], 0)

    def test_status_endpoint_is_post_only_and_function_authorized(self):
        status = json.loads((STATUS_DIR / 'function.json').read_text())
        trigger = next(binding for binding in status['bindings'] if binding['type'] == 'httpTrigger')
        self.assertEqual(trigger['methods'], ['post'])
        self.assertEqual(trigger['authLevel'], 'function')

    def test_logic_app_tracks_submission_and_verdict_without_long_http_calls(self):
        template = json.loads(LOGIC_TEMPLATE.read_text())
        workflow = next(
            resource for resource in template['resources']
            if resource['type'] == 'Microsoft.Logic/workflows'
        )
        actions = workflow['properties']['definition']['actions']

        self.assertEqual(LOGIC_TEMPLATE.read_text().count('DisableAsyncPattern'), 2)
        self.assertEqual(actions['Wait_until_evidence_is_submitted_to_ANYRUN']['type'], 'Until')
        self.assertEqual(actions['Wait_until_evidence_is_submitted_to_ANYRUN']['limit'], {'count': 480, 'timeout': 'PT2H'})
        self.assertEqual(actions['Wait_until_ANYRUN_verdict_is_available']['type'], 'Until')
        self.assertEqual(
            actions['Wait_until_evidence_is_submitted_to_ANYRUN']['operationOptions'],
            'FailWhenLimitsReached',
        )
        self.assertIn('ANYRUN-Sandbox-MDE-Status', LOGIC_TEMPLATE.read_text())
        self.assertEqual(actions['ANYRUN_verdict_received']['type'], 'Compose')


if __name__ == '__main__':
    unittest.main()
