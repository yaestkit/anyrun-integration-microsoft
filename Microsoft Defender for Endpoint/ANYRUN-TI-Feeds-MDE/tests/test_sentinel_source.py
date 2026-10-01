import importlib.util
import os
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch


SOURCE_DIR = Path(__file__).parents[1] / 'src' / 'ANYRUN-Feeds-MDE-FA'


class RunTimeException(Exception):
    pass


def load_module():
    anyrun = types.ModuleType('anyrun')
    anyrun.RunTimeException = RunTimeException
    sys.modules['anyrun'] = anyrun
    requests = types.ModuleType('requests')
    requests.Response = object
    requests.RequestException = Exception
    requests.request = Mock()
    sys.modules['requests'] = requests
    spec = importlib.util.spec_from_file_location('sentinel_source', SOURCE_DIR / 'sentinel.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Response:
    def __init__(self, status_code=200, document=None, text=''):
        self.status_code = status_code
        self._document = document or {}
        self.text = text

    def json(self):
        return self._document


class SentinelSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def make_source(self):
        source = self.module.SentinelThreatIntelligenceSource.__new__(
            self.module.SentinelThreatIntelligenceSource
        )
        source._log = Mock()
        source._minimum_confidence_threshold = 70
        source._max_indicators = 10000
        source._subscription_id = '00000000-0000-0000-0000-000000000000'
        source._resource_group = 'sentinel-rg'
        source._workspace_name = 'sentinel-workspace'
        source._sources = ['ANY.RUN']
        source._required_tags = {'promote-to-mde'}
        source._headers = {'Authorization': 'Bearer token'}
        return source

    def indicator(self, **overrides):
        properties = {
            'confidence': 90,
            'source': 'ANY.RUN',
            'revoked': False,
            'defanged': False,
            'threatIntelligenceTags': ['promote-to-mde'],
            'pattern': "[domain-name:value = 'bad.example']",
            'validFrom': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            'validUntil': (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            'description': 'ANY.RUN indicator',
            'externalReferences': [{'url': 'https://intelligence.any.run/analysis/example'}],
        }
        properties.update(overrides)
        return {'name': 'indicator-id', 'properties': properties}

    def test_filters_source_tags_lifecycle_and_confidence_fail_closed(self):
        source = self.make_source()
        self.assertIsNotNone(source._normalize_indicator(self.indicator()))
        self.assertIsNone(source._normalize_indicator(self.indicator(source='Other vendor')))
        self.assertIsNone(source._normalize_indicator(self.indicator(threatIntelligenceTags=[])))
        self.assertIsNone(source._normalize_indicator(self.indicator(revoked=True)))
        self.assertIsNone(source._normalize_indicator(self.indicator(defanged=True)))
        self.assertIsNone(source._normalize_indicator(self.indicator(confidence=69)))
        self.assertIsNone(source._normalize_indicator(self.indicator(confidence=True)))
        self.assertIsNone(source._normalize_indicator(self.indicator(
            validUntil=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        )))

    def test_query_uses_server_side_source_and_confidence_filters_and_paginates(self):
        source = self.make_source()
        first = Response(document={
            'value': [self.indicator()],
            'nextLink': 'https://management.azure.com/next?$skipToken=page-2',
        })
        second = Response(document={'value': [self.indicator(
            pattern="[ipv4-addr:value = '192.0.2.10']",
        )]})
        source._request = Mock(side_effect=[first, second])

        indicators, downloaded, truncated = source.get_indicators()

        self.assertEqual(downloaded, 2)
        self.assertEqual(len(indicators), 2)
        self.assertFalse(truncated)
        first_body = source._request.call_args_list[0].kwargs['json']
        second_body = source._request.call_args_list[1].kwargs['json']
        self.assertEqual(first_body['sources'], ['ANY.RUN'])
        self.assertEqual(first_body['minConfidence'], 70)
        self.assertEqual(second_body['skipToken'], 'page-2')

    def test_repeated_pagination_token_fails_closed(self):
        source = self.make_source()
        response = Response(document={
            'value': [],
            'nextLink': 'https://management.azure.com/next?$skipToken=same',
        })
        source._request = Mock(side_effect=[response, response])
        with self.assertRaises(RunTimeException):
            source.get_indicators()

    def test_managed_identity_is_required(self):
        with patch.dict(os.environ, {}, clear=True):
            source = self.module.SentinelThreatIntelligenceSource.__new__(
                self.module.SentinelThreatIntelligenceSource
            )
            with self.assertRaises(RunTimeException):
                source._managed_identity_token()


if __name__ == '__main__':
    unittest.main()
