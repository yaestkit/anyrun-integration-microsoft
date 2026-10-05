import unittest
from pathlib import Path


SOURCE = (
    Path(__file__).parents[1]
    / 'src'
    / 'ANYRUN-Feeds-MDE-FA'
    / 'anyrunfeeds.py'
).read_text(encoding='utf-8')


class SyncContractTests(unittest.TestCase):
    def test_defender_listing_is_paginated_and_scoped_to_connector_identity(self):
        body = SOURCE.split('def _list_indicators', 1)[1].split('def _get_indicators', 1)[0]
        self.assertIn("createdBy eq '{self._client_id}'", body)
        self.assertIn('$top={DEFENDER_PAGE_SIZE}&$skip={skip}', body)
        self.assertIn('skip += DEFENDER_PAGE_SIZE', body)

    def test_batch_delete_and_import_use_api_limit(self):
        self.assertIn('DEFENDER_BATCH_SIZE = 500', SOURCE)
        self.assertIn('batched(indicators, DEFENDER_BATCH_SIZE)', SOURCE)

    def test_http_200_per_item_import_failures_are_reported_and_classified(self):
        body = SOURCE.split('def _load_indicators', 1)[1].split('def _make_request', 1)[0]
        self.assertIn("result.get('isFailed')", body)
        self.assertIn("result.get('failureReason')", body)
        self.assertIn('Microsoft Defender rejected', body)
        self.assertIn('incomplete import result', body)
        self.assertNotIn('raise RunTimeException(\n                f\'Microsoft Defender rejected', body)
    def test_only_audit_and_block_are_accepted(self):
        body = SOURCE.split('def _prepare_indicators', 1)[1].split('def _load_indicators', 1)[0]
        self.assertIn("{'Audit', 'Block'}", body)
        self.assertNotIn("'Allowed'", body)

    def test_summary_contains_auditable_counts(self):
        for key in ('selected', 'prepared', 'unsupported', 'attempted_import', 'deleted', 'imported', 'rejected'):
            self.assertIn(f"'{key}'", SOURCE)

    def test_oauth_and_api_hosts_are_separated(self):
        config = (
            Path(__file__).parents[1]
            / 'src'
            / 'ANYRUN-Feeds-MDE-FA'
            / 'config.py'
        ).read_text(encoding='utf-8')
        self.assertIn('DEFENDER_OAUTH_RESOURCE', config)
        self.assertIn('DEFENDER_API_BASE_URL', config)
        self.assertNotIn('DEFENDER_API_URL', SOURCE)


if __name__ == '__main__':
    unittest.main()
