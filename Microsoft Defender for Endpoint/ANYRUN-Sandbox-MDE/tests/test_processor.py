import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


SOURCE_DIR = Path(__file__).parents[1] / 'src' / 'anyrun_mde_core'


class RunTimeException(Exception):
    pass


def load_processor(defender_client):
    anyrun = types.ModuleType('anyrun')
    anyrun.RunTimeException = RunTimeException
    connectors = types.ModuleType('anyrun.connectors')
    connectors.SandboxConnector = object
    operation_systems = types.ModuleType('anyrun.connectors.sandbox.operation_systems')
    operation_systems.WindowsConnector = object
    operation_systems.LinuxConnector = object
    sys.modules.update({
        'anyrun': anyrun,
        'anyrun.connectors': connectors,
        'anyrun.connectors.sandbox': types.ModuleType('anyrun.connectors.sandbox'),
        'anyrun.connectors.sandbox.operation_systems': operation_systems,
    })
    base = types.ModuleType('anyrun.connectors.sandbox.base_connector')
    base.BaseSandboxConnector = object
    sys.modules[base.__name__] = base

    package = types.ModuleType('processor_test_package')
    package.__path__ = [str(SOURCE_DIR)]
    sys.modules[package.__name__] = package

    defender = types.ModuleType(f'{package.__name__}.defender')
    defender.MicrosoftDefender = Mock(return_value=defender_client)
    utils = types.ModuleType(f'{package.__name__}.utils')
    utils.get_env_variable = Mock()
    utils.prepare_url_analysis_options = Mock(side_effect=lambda options: options)
    utils.clear_indicators = Mock(side_effect=lambda indicators: indicators or [])
    utils.sanitize_error_text = Mock(return_value='sanitized collection error')
    config = types.ModuleType(f'{package.__name__}.config')
    config.Config = type('Config', (), {
        'VERSION': 'test', 'VERDICT_WAIT_MARGIN_SECONDS': 600,
        'VERDICT_POLL_SECONDS': 20, 'HEARTBEAT_SECONDS': 60,
        'REPORT_TRANSIENT_ERROR_LIMIT': 10,
    })
    bounded = types.ModuleType(f'{package.__name__}.sandbox_client')
    bounded.BoundedWindowsConnector = bounded.BoundedLinuxConnector = object
    sys.modules.update({
        defender.__name__: defender,
        utils.__name__: utils,
        config.__name__: config,
        bounded.__name__: bounded,
    })

    spec = importlib.util.spec_from_file_location(
        f'{package.__name__}.processor',
        SOURCE_DIR / 'processor.py',
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ProcessorTests(unittest.TestCase):
    @staticmethod
    def report(verdict='malicious', status='done', remaining=None):
        data = {'analysis': {'scores': {'verdict': {'score': 5, 'threatLevelText': verdict}},
                             'permanentUrl': 'https://app.any.run/tasks/task-uuid'}}
        if status is not None:
            data['status'] = status
        if remaining is not None:
            data['remaining'] = remaining
        return {'data': data}

    def test_polling_retries_not_ready_and_transient_transport_errors(self):
        module = load_processor(Mock())
        connector = Mock()
        errors = [module.SandboxAPIError(code, 'not ready') for code in (404, 409, 425, 429, 503)]
        errors += [module.SandboxTransportError('connection dropped'), TimeoutError('request timeout')]
        connector.get_analysis_report.side_effect = errors + [self.report()]
        with patch.object(module.time, 'sleep') as sleep:
            report = module._wait_for_report(connector, 'task', 240)
        self.assertEqual(report['data']['status'], 'done')
        self.assertEqual(sleep.call_count, len(errors))

    def test_unchanged_polling_progress_is_emitted_once(self):
        module = load_processor(Mock())
        connector, callback = Mock(), Mock()
        connector.get_analysis_report.side_effect = [self.report(status='RUNNING')] * 4 + [self.report()]
        clock = [0.0]
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(module.time, 'sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
            module._wait_for_report(connector, 'task', 240, status_callback=callback)
        callback.assert_called_once()
        self.assertEqual(connector.get_analysis_report.call_count, 5)

    def test_remaining_time_progress_is_throttled_but_status_changes_are_immediate(self):
        module = load_processor(Mock())
        connector, callback = Mock(), Mock()
        connector.get_analysis_report.side_effect = [
            self.report(status='PREPARING', remaining=180),
            self.report(status='RUNNING', remaining=160),
            self.report(status='RUNNING', remaining=140),
            self.report(status='RUNNING', remaining=120),
            self.report(status='RUNNING', remaining=100),
            self.report(),
        ]
        clock = [0.0]
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(module.time, 'sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
            module._wait_for_report(connector, 'task', 240, status_callback=callback)
        self.assertEqual([call.kwargs if call.kwargs else call.args[1] for call in callback.call_args_list], [
            {'anyrun_task_status': 'PREPARING', 'anyrun_seconds_remaining': 180.0},
            {'anyrun_task_status': 'RUNNING', 'anyrun_seconds_remaining': 160.0},
            {'anyrun_task_status': 'RUNNING', 'anyrun_seconds_remaining': 100.0},
        ])

    def test_fresh_analysis_skips_comment_reads_and_recovery_keeps_deduplication(self):
        module = load_processor(Mock())
        for resume in (None, {'analysis_type': 'file', 'evidence': 'x.exe', 'task_uuid': 'paid-task'}):
            defender, connector = Mock(), Mock()
            connector.run_file_analysis.return_value = 'paid-task'
            connector.get_analysis_report.side_effect = [self.report(), []]
            module.process_analysis('file', 'alert', connector, {}, defender,
                                    file=b'x', filename='x.exe', resume_item=resume)
            self.assertIs(defender.deduplicate_comments, resume is not None)
            self.assertEqual(connector.run_file_analysis.call_count, 0 if resume else 1)

    def test_recovery_rechecks_comment_after_its_checkpoint_write_failed(self):
        module = load_processor(Mock())
        defender, connector, saved = Mock(), Mock(), {}
        connector.run_file_analysis.return_value = 'paid-task'

        def checkpoint(stage, item):
            if item.get('reference_commented'):
                raise RuntimeError('comment checkpoint write failed')
            saved.update(item)

        with self.assertRaisesRegex(RuntimeError, 'comment checkpoint'):
            module.process_analysis('file', 'alert', connector, {}, defender, file=b'x', filename='x.exe',
                                    checkpoint_callback=checkpoint)
        self.assertNotIn('reference_commented', saved)
        self.assertEqual(saved['task_uuid'], 'paid-task')
        connector.get_analysis_report.side_effect = [self.report(), []]
        module.process_analysis('file', 'alert', connector, {}, defender, resume_item=saved)
        self.assertTrue(defender.deduplicate_comments)
        connector.run_file_analysis.assert_called_once()

    def test_polling_fails_on_auth_error_without_retry(self):
        module = load_processor(Mock())
        for code in (400, 401, 403):
            connector = Mock()
            connector.get_analysis_report.side_effect = module.SandboxAPIError(code, 'rejected')
            with patch.object(module.time, 'sleep') as sleep:
                with self.assertRaises(module.SandboxAPIError):
                    module._wait_for_report(connector, 'task', 240)
                sleep.assert_not_called()

    def test_polling_missing_status_never_accepts_provisional_verdict_even_after_timeout(self):
        module = load_processor(Mock())
        module.Config.VERDICT_WAIT_MARGIN_SECONDS = 20
        clock = [0.0]
        connector = Mock()
        connector.get_analysis_report.return_value = self.report(status=None)
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(module.time, 'sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
            with self.assertRaisesRegex(TimeoutError, 'not available in time'):
                module._wait_for_report(connector, 'task', 40)
        self.assertEqual(clock[0], 60)

    def test_polling_transient_errors_remain_bounded_by_wait_deadline(self):
        module = load_processor(Mock())
        module.Config.VERDICT_WAIT_MARGIN_SECONDS = 10
        clock = [0.0]
        connector = Mock()
        connector.get_analysis_report.side_effect = module.SandboxAPIError(503, 'temporary')
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(module.time, 'sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
            with self.assertRaises(TimeoutError):
                module._wait_for_report(connector, 'task', 10)
        self.assertEqual(clock[0], 20)

    def test_polling_caps_consecutive_transient_errors(self):
        module = load_processor(Mock())
        connector = Mock()
        connector.get_analysis_report.side_effect = module.SandboxAPIError(404, 'unknown task')
        with patch.object(module.time, 'sleep'):
            with self.assertRaises(module.SandboxAPIError):
                module._wait_for_report(connector, 'task', 240)
        self.assertEqual(connector.get_analysis_report.call_count, 10)

    def test_rejected_submission_clears_intent_and_is_permanent(self):
        module = load_processor(Mock())
        for code in (400, 401, 403, 413, 422):
            connector, saved = Mock(), {}
            connector.run_file_analysis.side_effect = module.SandboxAPIError(code, 'rejected')
            with self.assertRaises(module.SubmissionRejected):
                module.process_analysis('file', 'alert', connector, {}, Mock(), file=b'sample', filename='x.exe',
                                        checkpoint_callback=lambda stage, item: saved.update(item))
            self.assertFalse(saved['submission_intent'])
            self.assertEqual(saved['submission_http_status'], code)
            self.assertEqual(saved['stage'], 'submission_rejected')
            with self.assertRaises(module.SubmissionRejected):
                module.process_alert('job', 'alert', 'WindowsDefenderAv', 'windows', {}, resume_state={'analyses': [saved]})

    def test_rate_limited_submission_can_be_retried_on_next_delivery(self):
        defender = Mock()
        module = load_processor(defender)
        connector, saved = Mock(), {}
        connector.run_url_analysis.side_effect = module.SandboxAPIError(429, 'rate limit')
        with self.assertRaises(module.SandboxAPIError):
            module.process_analysis('url', 'alert', connector, {}, defender, url='https://example.test/',
                                    checkpoint_callback=lambda stage, item: saved.update(item))
        self.assertFalse(saved['submission_intent'])
        defender.get_evidences.return_value = ('machine', {'urls': ['https://example.test/']})
        module.setup_anyrun_connector = Mock(return_value={'enriched': True, 'task_uuid': 'retry-task'})
        result = module.process_alert('job', 'alert', 'WindowsDefenderAtp', 'windows', {},
                                      resume_state={'stage': 'submission_rejected', 'analyses': [saved]})
        self.assertEqual(result[0]['task_uuid'], 'retry-task')
        module.setup_anyrun_connector.assert_called_once()

    def test_ambiguous_submission_preserves_intent_and_requires_recovery(self):
        module = load_processor(Mock())
        for error in (module.SandboxAPIError(503, 'uncertain'), module.SandboxTransportError('network'), TimeoutError()):
            connector, saved = Mock(), {}
            connector.run_file_analysis.side_effect = error
            with self.assertRaises(module.RecoveryRequired):
                module.process_analysis('file', 'alert', connector, {}, Mock(), file=b'sample', filename='x.exe',
                                        checkpoint_callback=lambda stage, item: saved.update(item))
            self.assertTrue(saved['submission_intent'])
            self.assertNotIn('task_uuid', saved)

    def test_submission_timestamp_is_durable_and_preserved_on_resume(self):
        module = load_processor(Mock())
        connector = Mock()
        connector.run_file_analysis.return_value = 'paid-task'
        saved = {}
        class Interrupted(BaseException):
            pass
        def checkpoint(stage, item):
            saved.update(item)
            if stage == 'waiting_for_verdict':
                raise Interrupted()
        with self.assertRaises(Interrupted):
            module.process_analysis('file', 'alert', connector, {}, Mock(), file=b'x', filename='x.exe',
                                    checkpoint_callback=checkpoint)
        timestamp = saved['submitted_at']
        connector.get_analysis_report.side_effect = [self.report(), []]
        result = module.process_analysis('file', 'alert', connector, {}, Mock(), resume_item=saved)
        self.assertEqual(result['submitted_at'], timestamp)
        connector.run_file_analysis.assert_called_once()

    def test_report_polling_never_opens_sse_and_ignores_provisional_verdict(self):
        module = load_processor(Mock())
        connector = Mock()
        connector.get_task_status.side_effect = AssertionError('SSE must never be opened')
        connector.get_analysis_report.side_effect = [
            self.report(status='RUNNING', remaining='40'), self.report(status=100, remaining=0),
        ]
        callback = Mock()
        with patch.object(module.time, 'sleep'):
            report = module._wait_for_report(connector, 'task', 240, status_callback=callback)
        self.assertEqual(report['data']['status'], 100)
        connector.get_task_status.assert_not_called()
        callback.assert_called_once()

    def test_polling_deadline_uses_custom_timeout_and_margin(self):
        module = load_processor(Mock())
        module.Config.VERDICT_WAIT_MARGIN_SECONDS = 20
        clock = [0.0]
        connector = Mock()
        connector.get_analysis_report.return_value = self.report(verdict=None)
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(module.time, 'sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
            with self.assertRaisesRegex(TimeoutError, 'not available in time'):
                module._wait_for_report(connector, 'task', 600)
        self.assertEqual(clock[0], 620)

    def test_polling_handles_manual_extension_but_honours_overall_budget(self):
        module = load_processor(Mock())
        module.Config.VERDICT_WAIT_MARGIN_SECONDS = 10
        clock = [0.0]
        connector = Mock()
        connector.get_analysis_report.side_effect = [
            self.report(verdict=None, status='RUNNING', remaining=90),
            self.report(verdict=None, status='RUNNING', remaining=200),
            self.report(status='COMPLETED', remaining=0),
        ]
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(module.time, 'sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
            module._wait_for_report(connector, 'task', 10, deadline_monotonic=100)
        self.assertEqual(clock[0], 40)
        connector.get_analysis_report.side_effect = None
        connector.get_analysis_report.return_value = self.report(verdict=None, status='RUNNING', remaining=200)
        with patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(module.time, 'sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
            with self.assertRaisesRegex(RunTimeException, '90-minute'):
                module._wait_for_report(connector, 'task', 660, deadline_monotonic=50)
        self.assertEqual(clock[0], 50)

    def test_resume_after_process_death_reuses_paid_task(self):
        module = load_processor(Mock())
        defender = Mock()
        connector = Mock()
        connector.run_file_analysis.return_value = 'saved-task'
        connector.get_analysis_report.side_effect = [self.report(), None]
        saved = {}

        class ProcessKilled(BaseException):
            pass

        def checkpoint(stage, item):
            saved.update(item)
            if stage == 'waiting_for_verdict':
                raise ProcessKilled()

        with self.assertRaises(ProcessKilled):
            module.process_analysis('file', 'alert', connector, {'opt_timeout': 240}, defender,
                                    file=b'sample', filename='sample.exe', checkpoint_callback=checkpoint)
        self.assertEqual(saved['task_uuid'], 'saved-task')
        result = module.process_analysis('file', 'alert', connector, {'opt_timeout': 240}, defender,
                                         resume_item=saved, checkpoint_callback=Mock())
        self.assertTrue(result['enriched'])
        self.assertEqual(connector.run_file_analysis.call_count, 1)
        self.assertEqual(defender.add_task_reference_comment.call_count, 1)
        self.assertEqual(defender.add_summary_comment.call_count, 1)

    def test_resume_saved_verdict_only_enriches_and_enriched_item_is_skipped(self):
        module = load_processor(Mock())
        defender, connector = Mock(), Mock()
        connector.get_analysis_report.return_value = None
        saved = {'analysis_type': 'url', 'evidence': 'https://example.test/', 'task_uuid': 'paid-task',
                 'task_url': 'https://app.any.run/tasks/paid-task', 'verdict': 'malicious',
                 'reference_commented': True, 'threat_score': 100}
        result = module.process_analysis('url', 'alert', connector, {}, defender, resume_item=saved)
        connector.run_url_analysis.assert_not_called()
        connector.get_analysis_report.assert_called_once_with('paid-task', report_format='ioc')
        defender.add_summary_comment.assert_called_once()
        defender.reset_mock()
        connector.reset_mock()
        module.process_analysis('url', 'alert', connector, {}, defender, resume_item=result)
        self.assertEqual(defender.mock_calls, [])
        self.assertEqual(connector.mock_calls, [])

    def test_resume_existing_task_skips_live_response_even_for_legacy_status(self):
        defender = Mock()
        module = load_processor(defender)
        module.setup_anyrun_connector = Mock(return_value={'task_uuid': 'existing', 'enriched': True})
        state = {'evidence_count': 1, 'latest_analysis': {
            'analysis_type': 'file', 'task_uuid': 'existing', 'evidence': 'sample.exe',
        }}
        result = module.process_alert('job', 'alert', 'WindowsDefenderAv', 'windows', {}, resume_state=state)
        self.assertEqual(result[0]['task_uuid'], 'existing')
        defender.get_evidences.assert_not_called()
        defender.execute_ps_script_on_machine.assert_not_called()
        defender.upload_ps_script_to_library.assert_not_called()

    def test_multi_evidence_resume_does_not_recollect_saved_file(self):
        defender = Mock()
        defender.get_evidences.return_value = ('machine', {
            'filepaths': ['C:/one.exe', 'C:/two.exe'], 'filenames': ['one.exe', 'two.exe'], 'urls': [],
        })
        defender.download_file_from_machine.return_value = b'sample'
        module = load_processor(defender)
        module.setup_anyrun_connector = Mock(return_value={'enriched': True, 'task_uuid': 'task'})
        state = {'evidence_count': 2, 'analyses': [{
            'analysis_type': 'file', 'evidence_key': module._evidence_key('file', 'C:/one.exe'),
            'task_uuid': 'one-paid', 'evidence': 'one.exe', 'enriched': True,
        }]}
        results = module.process_alert('job', 'alert', 'WindowsDefenderAtp', 'windows', {}, resume_state=state)
        self.assertEqual(len(results), 2)
        defender.download_file_from_machine.assert_called_once_with('machine', 'C:/two.exe')

    def test_uncertain_submission_requires_recovery_instead_of_hash_history_guess(self):
        defender = Mock()
        module = load_processor(defender)
        module.setup_anyrun_connector = Mock()
        with self.assertRaisesRegex(module.RecoveryRequired, 'automatic resubmission is disabled'):
            module.process_alert('job', 'alert', 'WindowsDefenderAtp', 'windows', {}, resume_state={
                'analyses': [{'submission_intent': True, 'sha256': 'known-hash'}],
            })
        module.setup_anyrun_connector.assert_not_called()
        defender.get_evidences.assert_not_called()

    def test_checkpoint_failure_prevents_paid_post(self):
        module = load_processor(Mock())
        connector = Mock()
        with self.assertRaisesRegex(RuntimeError, 'storage down'):
            module.process_analysis('file', 'alert', connector, {}, Mock(), file=b'sample', filename='sample.exe',
                                    checkpoint_callback=Mock(side_effect=RuntimeError('storage down')))
        connector.run_file_analysis.assert_not_called()

    def test_url_identity_keeps_query_distinction_without_saving_query(self):
        module = load_processor(Mock())
        first, second = 'https://example.test/?sig=one', 'https://example.test/?sig=two'
        self.assertNotEqual(module._evidence_key('url', first), module._evidence_key('url', second))
        self.assertEqual(module._display_evidence('url', None, first), 'https://example.test/')
        self.assertNotIn('sig', module._evidence_key('url', first))

    def test_missing_edr_file_does_not_block_other_evidence_or_urls(self):
        defender_client = Mock()
        defender_client.get_evidences.return_value = (
            'machine-id',
            {
                'filepaths': ['C:/missing.exe', 'C:/available.exe'],
                'filenames': ['missing.exe', 'available.exe'],
                'urls': ['https://example.test/'],
            },
        )
        defender_client.download_file_from_machine.side_effect = [
            RunTimeException('GetFile failed'),
            b'available-file',
        ]
        module = load_processor(defender_client)
        module.setup_anyrun_connector = Mock()

        module.process_alert(
            job_id='job-1',
            alert_id='alert-1',
            alert_source='WindowsDefenderAtp',
            machine_os_platform='windows',
            analysis_options={'opt_timeout': 240},
        )

        self.assertEqual(module.setup_anyrun_connector.call_count, 2)
        file_call, url_call = module.setup_anyrun_connector.call_args_list
        self.assertEqual(file_call.args[0], 'file')
        self.assertEqual(file_call.args[6], 'available.exe')
        self.assertEqual(url_call.args[0], 'url')
        self.assertEqual(url_call.kwargs['url'], 'https://example.test/')
        defender_client.add_comment.assert_called_once()
        self.assertIn('missing.exe', defender_client.add_comment.call_args.args[1])
        self.assertIn('sanitized collection error', defender_client.add_comment.call_args.args[1])

    def test_expired_job_budget_fails_before_defender_work(self):
        defender_client = Mock()
        module = load_processor(defender_client)

        with self.assertRaisesRegex(RunTimeException, '90-minute job time budget'):
            module.process_alert(
                job_id='job-1',
                alert_id='alert-1',
                alert_source='WindowsDefenderAtp',
                machine_os_platform='windows',
                analysis_options={'opt_timeout': 240},
                deadline_monotonic=0,
            )

        defender_client.get_evidences.assert_not_called()

    def test_analysis_result_is_safe_and_exposed_to_status_callback(self):
        defender_client = Mock()
        defender_client.submit_indicators.return_value = []
        connector = Mock()
        connector.run_file_analysis.return_value = 'task-uuid'
        connector.get_task_status.return_value = ['running', 'done']
        connector.get_analysis_verdict.return_value = 'malicious'
        connector.get_analysis_report.side_effect = [
            {
                'data': {
                    'status': 'done',
                    'analysis': {
                        'scores': {'verdict': {'score': 5, 'threatLevelText': 'malicious'}},
                        'permanentUrl': (
                            'https://app.any.run/tasks/task-uuid?token=secret#fragment'
                        ),
                    }
                }
            },
            [{'type': 'domain', 'ioc': 'example.test', 'reputation': 2}],
        ]
        status_callback = Mock()
        module = load_processor(defender_client)

        result = module.process_analysis(
            analysis_type='file',
            alert_id='alert-1',
            connector=connector,
            analysis_options={'opt_timeout': 240},
            ms_defender=defender_client,
            file=b'sample',
            filename='sample.exe',
            status_callback=status_callback,
        )

        self.assertEqual(result['task_uuid'], 'task-uuid')
        self.assertEqual(result['verdict'], 'malicious')
        self.assertEqual(result['threat_score'], 5)
        self.assertEqual(result['indicators_count'], 1)
        self.assertEqual(
            result['task_url'],
            'https://app.any.run/tasks/task-uuid',
        )
        states = [call.args[0] for call in status_callback.call_args_list]
        self.assertIn('submitted_to_anyrun', states)
        self.assertEqual(states[-1], 'analysis_completed')

    def test_analysis_without_actionable_iocs_completes_with_zero_counts(self):
        defender_client = Mock()
        connector = Mock()
        connector.run_file_analysis.return_value = 'task-without-iocs'
        connector.get_task_status.return_value = ['done']
        connector.get_analysis_verdict.return_value = 'no threats detected'
        connector.get_analysis_report.side_effect = [
            {
                'data': {
                    'status': 'done',
                    'analysis': {
                        'scores': {'verdict': {'score': 0, 'threatLevelText': 'no threats detected'}},
                        'permanentUrl': 'https://app.any.run/tasks/task-without-iocs',
                    }
                }
            },
            None,
        ]
        status_callback = Mock()
        module = load_processor(defender_client)

        result = module.process_analysis(
            analysis_type='file',
            alert_id='alert-no-iocs',
            connector=connector,
            analysis_options={'opt_timeout': 240},
            ms_defender=defender_client,
            file=b'sample',
            filename=r'C:\Users\analyst\Downloads\sample.zip',
            status_callback=status_callback,
        )

        self.assertEqual(result['evidence'], 'sample.zip')
        self.assertEqual(result['indicators_count'], 0)
        self.assertEqual(result['rejected_indicators_count'], 0)
        defender_client.submit_indicators.assert_not_called()
        defender_client.add_ioc_comment.assert_not_called()
        defender_client.add_summary_comment.assert_called_once()
        self.assertEqual(status_callback.call_args.args[0], 'analysis_completed')


if __name__ == '__main__':
    unittest.main()
