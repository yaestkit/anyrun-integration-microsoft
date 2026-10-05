import importlib.util
import json
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
    feeds._config = module.Config
    feeds._client_id = 'client-id'
    feeds._feed_fetch_depth = 30
    feeds._minimum_confidence_threshold = 50
    return feeds


class SyncBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def configured(self, *, empty=False, at_limit=False):
        feeds = make_feeds(self.module)
        payloads = [] if empty else [{
            'indicatorType': 'DomainName', 'indicatorValue': 'same.example', 'action': 'Audit',
        }]
        feeds._get_indicators = Mock(return_value=([] if empty else [{'id': 'selected'}],
                                                  10000 if at_limit else len(payloads), at_limit))
        feeds._prepare_indicators = Mock(return_value=(payloads, 0))
        feeds._list_indicators = Mock(return_value=[{
            'id': 'old-id', 'indicatorType': 'DomainName',
            'indicatorValue': 'same.example', 'action': 'Audit',
        }])
        feeds._delete_indicators = Mock(return_value=1)
        feeds._load_indicators = Mock(return_value=(len(payloads), 0))
        return feeds, payloads

    def test_unchanged_indicators_are_deleted_and_imported_again(self):
        feeds, payloads = self.configured()
        flow = Mock()
        for name in ('_get_indicators', '_prepare_indicators', '_list_indicators',
                     '_delete_indicators', '_load_indicators'):
            flow.attach_mock(getattr(feeds, name), name)
        summary = feeds.process_enrichment()
        self.assertEqual([c[0] for c in flow.mock_calls], [
            '_get_indicators', '_prepare_indicators', '_list_indicators',
            '_delete_indicators', '_load_indicators',
        ])
        feeds._delete_indicators.assert_called_once_with(['old-id'])
        feeds._load_indicators.assert_called_once_with(payloads)
        self.assertEqual((summary['deleted'], summary['attempted_import'], summary['imported']), (1, 1, 1))

    def test_feed_at_limit_still_clears_the_entire_previous_set(self):
        feeds, payloads = self.configured(at_limit=True)
        summary = feeds.process_enrichment()
        feeds._delete_indicators.assert_called_once_with(['old-id'])
        feeds._load_indicators.assert_called_once_with(payloads)
        self.assertTrue(summary['feed_truncated'])
        self.assertEqual(summary['deleted'], 1)

    def test_valid_empty_feed_clears_previous_indicators_like_upstream(self):
        feeds, _ = self.configured(empty=True)
        summary = feeds.process_enrichment()
        feeds._delete_indicators.assert_called_once_with(['old-id'])
        feeds._load_indicators.assert_not_called()
        self.assertEqual((summary['deleted'], summary['imported']), (1, 0))

    def test_download_failure_keeps_previous_indicators(self):
        feeds, _ = self.configured()
        feeds._get_indicators.side_effect = RunTimeException('download failed')
        with self.assertRaisesRegex(RunTimeException, 'download failed'):
            feeds.process_enrichment()
        feeds._delete_indicators.assert_not_called()
        feeds._load_indicators.assert_not_called()

    def test_preparation_failure_keeps_previous_indicators(self):
        feeds, _ = self.configured()
        feeds._prepare_indicators.side_effect = ValueError('invalid data')
        with self.assertRaisesRegex(ValueError, 'invalid data'):
            feeds.process_enrichment()
        feeds._delete_indicators.assert_not_called()
        feeds._load_indicators.assert_not_called()

    def test_all_unsupported_selected_patterns_keep_previous_indicators(self):
        feeds, _ = self.configured()
        feeds._prepare_indicators.return_value = ([], 1)
        with self.assertRaisesRegex(RunTimeException, 'unsupported or invalid'):
            feeds.process_enrichment()
        feeds._delete_indicators.assert_not_called()
        feeds._load_indicators.assert_not_called()

    def test_deletion_failure_stops_before_import(self):
        feeds, _ = self.configured()
        feeds._delete_indicators.side_effect = RunTimeException('delete failed')
        with self.assertRaisesRegex(RunTimeException, 'delete failed'):
            feeds.process_enrichment()
        feeds._load_indicators.assert_not_called()

    def test_import_failure_is_not_reported_as_success(self):
        feeds, _ = self.configured()
        feeds._load_indicators.side_effect = RunTimeException('import failed')
        with self.assertRaisesRegex(RunTimeException, 'import failed'):
            feeds.process_enrichment()
        feeds._delete_indicators.assert_called_once_with(['old-id'])

    def test_partial_import_rejection_fails_the_refresh(self):
        feeds, _ = self.configured()
        feeds._load_indicators.return_value = (0, 1)
        with self.assertRaisesRegex(RunTimeException, 'full refresh is incomplete'):
            feeds.process_enrichment()

    def test_http_200_partial_rejection_is_detected_by_real_import(self):
        feeds = make_feeds(self.module)
        feeds._make_request = Mock(return_value=types.SimpleNamespace(
            status_code=200, json=lambda: {'value': [
                {'id': 'new-id', 'isFailed': False},
                {'isFailed': True, 'failureReason': 'Tenant quota exceeded'},
            ]},
        ))
        payloads = [{'indicatorType': 'DomainName', 'indicatorValue': name}
                    for name in ('one.example', 'two.example')]
        self.assertEqual(feeds._load_indicators(payloads), (1, 1))

    def test_repeated_ten_thousand_object_refresh_does_not_accumulate(self):
        feeds = make_feeds(self.module)
        inventory = {}
        serial = [0]
        events = []

        def request(method, url, data=None):
            if method == 'GET':
                self.assertIn('createdBy%20eq%20%27client-id%27', url)
                skip = int(url.split('$skip=')[1])
                return types.SimpleNamespace(status_code=200, json=lambda: {
                    'value': list(inventory.values())[skip:skip + 10000],
                })
            body = json.loads(data)
            if url.endswith('/BatchDelete'):
                self.assertLessEqual(len(body['IndicatorIds']), 500)
                events.append('delete')
                for item_id in body['IndicatorIds']:
                    del inventory[item_id]
                return types.SimpleNamespace(status_code=200)
            self.assertTrue(url.endswith('/import'))
            self.assertLessEqual(len(body['Indicators']), 500)
            events.append('import')
            results = []
            for item in body['Indicators']:
                serial[0] += 1
                item_id = str(serial[0])
                inventory[item_id] = {**item, 'id': item_id}
                results.append({'id': item_id, 'isFailed': False})
            self.assertLessEqual(len(inventory), 10000)
            return types.SimpleNamespace(status_code=200, json=lambda: {'value': results})

        feeds._make_request = Mock(side_effect=request)
        for run in range(3):
            payloads = [{'indicatorType': 'DomainName', 'indicatorValue': f'{run}-{i}.example',
                         'action': 'Audit'} for i in range(10000)]
            feeds._get_indicators = Mock(return_value=([{'id': str(i)} for i in range(10000)], 10000, True))
            feeds._prepare_indicators = Mock(return_value=(payloads, 0))
            events.clear()
            summary = feeds.process_enrichment()
            self.assertEqual(len(inventory), 10000)
            self.assertEqual(summary['imported'], 10000)
            self.assertEqual(summary['deleted'], 0 if run == 0 else 10000)
            if run:
                self.assertEqual(events, ['delete'] * 20 + ['import'] * 20)
            else:
                self.assertEqual(events, ['import'] * 20)


if __name__ == '__main__':
    unittest.main()
