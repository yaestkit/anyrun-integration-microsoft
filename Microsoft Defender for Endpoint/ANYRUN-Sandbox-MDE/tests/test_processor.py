import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock


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

    package = types.ModuleType('processor_test_package')
    package.__path__ = [str(SOURCE_DIR)]
    sys.modules[package.__name__] = package

    defender = types.ModuleType(f'{package.__name__}.defender')
    defender.MicrosoftDefender = Mock(return_value=defender_client)
    utils = types.ModuleType(f'{package.__name__}.utils')
    utils.get_env_variable = Mock()
    utils.prepare_url_analysis_options = Mock(side_effect=lambda options: options)
    utils.clear_indicators = Mock(side_effect=lambda indicators: indicators)
    config = types.ModuleType(f'{package.__name__}.config')
    config.Config = type('Config', (), {'VERSION': 'test'})
    sys.modules.update({
        defender.__name__: defender,
        utils.__name__: utils,
        config.__name__: config,
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


if __name__ == '__main__':
    unittest.main()
