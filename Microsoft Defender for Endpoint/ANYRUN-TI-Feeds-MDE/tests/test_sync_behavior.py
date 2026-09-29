import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock


SOURCE_DIR = Path(__file__).parents[1] / 'src' / 'ANYRUN-Feeds-MDE-FA'


class RunTimeException(Exception):
    pass


class FakeFeedsConnector:
    def __init__(self, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def check_authorization(self):
        pass


def load_module():
    requests = types.ModuleType('requests')
    requests.Response = object
    requests.RequestException = Exception
    requests.request = Mock()
    anyrun = types.ModuleType('anyrun')
    anyrun.RunTimeException = RunTimeException
    connectors = types.ModuleType('anyrun.connectors')
    connectors.FeedsConnector = FakeFeedsConnector
    sys.modules.update({
        'requests': requests,
        'anyrun': anyrun,
        'anyrun.connectors': connectors,
    })

    package = types.ModuleType('feeds_behavior_package')
    package.__path__ = [str(SOURCE_DIR)]
    sys.modules[package.__name__] = package
    spec = importlib.util.spec_from_file_location(
        f'{package.__name__}.anyrunfeeds',
        SOURCE_DIR / 'anyrunfeeds.py',
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.get_env_variable = Mock(return_value='api-key')
    return module


def make_feeds(module):
    feeds = module.AnyRunFeeds.__new__(module.AnyRunFeeds)
    feeds._log = Mock()
    feeds._client_id = 'client-id'
    feeds._feed_fetch_depth = 30
    feeds._minimum_confidence_threshold = 50
    return feeds


class SyncBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_empty_selected_feed_preserves_existing_indicators(self):
        feeds = make_feeds(self.module)
        feeds._get_indicators = Mock(return_value=([], 0, False))
        feeds._prepare_indicators = Mock(return_value=([], 0))
        feeds._list_indicators = Mock(return_value=[{
            'id': 'old-id',
            'indicatorType': 'DomainName',
            'indicatorValue': 'old.example',
            'action': 'Audit',
        }])
        feeds._load_indicators = Mock()
        feeds._delete_indicators = Mock()

        summary = feeds.process_enrichment()

        feeds._delete_indicators.assert_not_called()
        self.assertEqual(summary['deleted'], 0)
        self.assertEqual(summary['selected'], 0)

    def test_feed_at_limit_is_treated_as_truncated_and_preserves_stale(self):
        feeds = make_feeds(self.module)
        selected = [{'id': 'new'}]
        payload = {
            'indicatorType': 'DomainName',
            'indicatorValue': 'new.example',
            'action': 'Audit',
        }
        feeds._get_indicators = Mock(
            return_value=(selected, self.module.ANYRUN_FEED_LIMIT, True),
        )
        feeds._prepare_indicators = Mock(return_value=([payload], 0))
        feeds._list_indicators = Mock(return_value=[{
            'id': 'old-id',
            'indicatorType': 'DomainName',
            'indicatorValue': 'old.example',
            'action': 'Audit',
        }])
        feeds._load_indicators = Mock(return_value=(1, 0, set(), {'new-id'}))
        feeds._delete_indicators = Mock()

        summary = feeds.process_enrichment()

        feeds._delete_indicators.assert_not_called()
        self.assertTrue(summary['feed_truncated'])

    def test_rejected_new_value_does_not_block_stale_cleanup(self):
        feeds = make_feeds(self.module)
        selected = [{'id': 'new'}]
        payload = {
            'indicatorType': 'DomainName',
            'indicatorValue': 'new.example',
            'action': 'Audit',
        }
        feeds._get_indicators = Mock(return_value=(selected, 1, False))
        feeds._prepare_indicators = Mock(return_value=([payload], 0))
        feeds._list_indicators = Mock(return_value=[{
            'id': 'old-id',
            'indicatorType': 'DomainName',
            'indicatorValue': 'old.example',
            'action': 'Audit',
        }])
        feeds._load_indicators = Mock(return_value=(
            0,
            1,
            {('DomainName', 'new.example')},
            set(),
        ))
        feeds._delete_indicators = Mock(return_value=1)

        summary = feeds.process_enrichment()

        feeds._delete_indicators.assert_called_once_with(['old-id'])
        self.assertEqual(summary['deleted'], 1)
        self.assertEqual(summary['rejected'], 1)

    def test_domain_keys_are_case_insensitive(self):
        feeds = make_feeds(self.module)
        selected = [{'id': 'same'}]
        payload = {
            'indicatorType': 'DomainName',
            'indicatorValue': 'example.test',
            'action': 'Audit',
        }
        feeds._get_indicators = Mock(return_value=(selected, 1, False))
        feeds._prepare_indicators = Mock(return_value=([payload], 0))
        feeds._list_indicators = Mock(return_value=[{
            'id': 'existing-id',
            'indicatorType': 'DomainName',
            'indicatorValue': 'EXAMPLE.TEST',
            'action': 'Audit',
        }])
        feeds._load_indicators = Mock()
        feeds._delete_indicators = Mock(return_value=0)

        summary = feeds.process_enrichment()

        feeds._load_indicators.assert_not_called()
        feeds._delete_indicators.assert_called_once_with([])
        self.assertEqual(summary['attempted_import'], 0)


if __name__ == '__main__':
    unittest.main()
