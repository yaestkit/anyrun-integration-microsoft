import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import azure.functions as func

from test_sync_behavior import load_module, make_feeds, RunTimeException


class PartialHttpResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.feeds_module = load_module()
        spec = importlib.util.spec_from_file_location(
            'feeds_behavior_package.anyrun_connector',
            Path(__file__).parents[1] / 'src/ANYRUN-Feeds-MDE-FA/anyrun_connector.py',
        )
        cls.handler = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.handler
        spec.loader.exec_module(cls.handler)

    def request(self):
        return func.HttpRequest(
            method='POST', url='https://localhost/api/ANYRUN-Feeds-MDE-FA',
            headers={'Content-Type': 'application/json'}, params={},
            body=json.dumps({'feed_fetch_depth': 30, 'minimum_confidence_threshold': 50}).encode(),
        )

    def run_handler(self, feeds):
        with patch.object(self.handler, 'AnyRunFeeds', return_value=feeds):
            return self.handler.main(self.request())

    def test_real_pipeline_returns_200_for_9996_accepted_and_four_rejected(self):
        feeds = make_feeds(self.feeds_module)
        payloads = [{'indicatorType': 'DomainName', 'indicatorValue': f'{i}.example',
                     'action': 'Audit'} for i in range(10000)]
        feeds._get_indicators = Mock(return_value=([{'id': 'selected'}], 10000, True))
        feeds._prepare_indicators = Mock(return_value=(payloads, 0))
        feeds._list_indicators = Mock(return_value=[{'id': 'old-id'}])
        feeds._delete_indicators = Mock(return_value=1)
        calls = [0]

        def request(method, url, data=None):
            self.assertEqual(method, 'POST')
            self.assertTrue(url.endswith('/import'))
            indicators = json.loads(data)['Indicators']
            results = []
            for i, item in enumerate(indicators):
                rejected = calls[0] == 0 and i < 4
                results.append({'indicator': item['indicatorValue'], 'isFailed': rejected,
                                'failureReason': 'Invalid indicator value' if rejected else None})
            calls[0] += 1
            return types.SimpleNamespace(status_code=200, json=lambda: {'value': results})

        feeds._make_request = Mock(side_effect=request)
        response = self.run_handler(feeds)
        body = json.loads(response.get_body())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/json')
        self.assertEqual(body['status'], 'completed_with_warnings')
        self.assertEqual(body['summary']['imported'], 9996)
        self.assertEqual(body['summary']['rejected'], 4)
        self.assertEqual(body['summary']['attempted_import'], 10000)
        self.assertEqual(len(body['summary']['rejection_details']), 4)
        self.assertTrue(all(d['failureReason'] == 'Invalid indicator value'
                            for d in body['summary']['rejection_details']))
        self.assertFalse(body['summary']['rejection_details_truncated'])
        self.assertIn('rejected 4 of 10000', body['warning'])
        self.assertEqual(calls[0], 20)
        feeds._delete_indicators.assert_called_once_with(['old-id'])

    def test_complete_success_has_no_warning(self):
        response = self.run_handler(Mock(process_enrichment=Mock(return_value={
            'attempted_import': 10, 'imported': 10, 'rejected': 0,
        })))
        body = json.loads(response.get_body())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['status'], 'completed')
        self.assertNotIn('warning', body)

    def test_error_in_feed_download_deletion_or_import_still_returns_500(self):
        for stage in ('_get_indicators', '_delete_indicators', '_load_indicators'):
            with self.subTest(stage=stage):
                feeds = make_feeds(self.feeds_module)
                feeds._get_indicators = Mock(return_value=([{'id': 'selected'}], 1, False))
                feeds._prepare_indicators = Mock(return_value=([{'indicatorValue': 'x.example'}], 0))
                feeds._list_indicators = Mock(return_value=[{'id': 'old-id'}])
                feeds._delete_indicators = Mock(return_value=1)
                feeds._load_indicators = Mock(return_value=(1, 0, []))
                getattr(feeds, stage).side_effect = RunTimeException('upstream request failed')
                response = self.run_handler(feeds)
                self.assertEqual(response.status_code, 500)
                self.assertIn(b'upstream request failed', response.get_body())

    def test_authentication_error_still_returns_500(self):
        with patch.object(self.handler, 'AnyRunFeeds', side_effect=RunTimeException('authentication failed')):
            response = self.handler.main(self.request())
        self.assertEqual(response.status_code, 500)
        self.assertIn(b'authentication failed', response.get_body())

    def test_large_rejection_list_is_bounded_without_losing_counts(self):
        feeds = make_feeds(self.feeds_module)
        payloads = [{'indicatorValue': f'{i}.example'} for i in range(500)]
        feeds._get_indicators = Mock(return_value=([{'id': 'selected'}], 500, False))
        feeds._prepare_indicators = Mock(return_value=(payloads, 0))
        feeds._list_indicators = Mock(return_value=[])
        feeds._delete_indicators = Mock(return_value=0)
        feeds._make_request = Mock(return_value=types.SimpleNamespace(status_code=200, json=lambda: {
            'value': [{'isFailed': True, 'failureReason': 'Tenant quota exceeded'} for _ in payloads],
        }))
        response = self.run_handler(feeds)
        body = json.loads(response.get_body())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body['summary']['rejected'], 500)
        self.assertEqual(body['summary']['imported'], 0)
        self.assertEqual(len(body['summary']['rejection_details']), 10)
        self.assertTrue(body['summary']['rejection_details_truncated'])

    def test_incomplete_api_results_still_return_500(self):
        feeds = make_feeds(self.feeds_module)
        feeds._get_indicators = Mock(return_value=([{'id': 'selected'}], 1, False))
        feeds._prepare_indicators = Mock(return_value=([{'indicatorValue': 'x.example'}], 0))
        feeds._list_indicators = Mock(return_value=[])
        feeds._delete_indicators = Mock(return_value=0)
        feeds._make_request = Mock(return_value=types.SimpleNamespace(status_code=200, json=lambda: {'value': []}))
        response = self.run_handler(feeds)
        self.assertEqual(response.status_code, 500)
        self.assertIn(b'incomplete import result', response.get_body())


if __name__ == '__main__':
    unittest.main()
