import importlib.util
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / 'src' / 'anyrun_mde_core' / 'utils.py'


def load_utils():
    spec = importlib.util.spec_from_file_location('utils_security_under_test', SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ErrorSanitizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_utils()

    def test_absolute_and_relative_url_queries_are_redacted(self):
        text = self.module.sanitize_error_text(
            'GET https://account.blob.core.windows.net/c/file?sv=1&sig=secret#fragment '
            'failed with url: /result/file?sv=2&sig=other.'
        )

        self.assertNotIn('secret', text)
        self.assertNotIn('other', text)
        self.assertNotIn('fragment', text)
        self.assertEqual(text.count('?[REDACTED]'), 2)

    def test_connection_strings_and_bearer_tokens_are_redacted(self):
        text = self.module.sanitize_error_text(
            'DefaultEndpointsProtocol=https;AccountName=test;AccountKey=base64-key;'
            'SharedAccessSignature=sv=1&sig=sas-secret;Password=p@ss '
            'Bearer eyJhbGciOiJub25lIn0.payload.signature'
        )

        for secret in ('base64-key', 'sas-secret', 'p@ss', 'eyJhbGci'):
            self.assertNotIn(secret, text)
        self.assertIn('AccountKey=[REDACTED]', text)
        self.assertIn('SharedAccessSignature=[REDACTED]', text)
        self.assertIn('Bearer [REDACTED]', text)

    def test_json_style_secret_assignments_are_redacted(self):
        text = self.module.sanitize_error_text(
            'response={"client_secret":"secret-one","access_token":"secret-two",'
            '"api_key":"secret-three"}'
        )

        self.assertNotIn('secret-one', text)
        self.assertNotIn('secret-two', text)
        self.assertNotIn('secret-three', text)

    def test_short_sas_names_are_not_redacted_outside_query_strings(self):
        original = 'Parser reported sp: some text, st=ordinary and se: another value.'

        self.assertEqual(self.module.sanitize_error_text(original), original)

    def test_bare_sas_signature_and_identity_fields_are_redacted(self):
        text = self.module.sanitize_error_text(
            'sv=2026-01-01&sr=b&sp=c&skoid=object-id&sktid=tenant-id&sig=SECRET'
        )

        for secret in ('object-id', 'tenant-id', 'SECRET'):
            self.assertNotIn(secret, text)
        self.assertIn('skoid=[REDACTED]', text)

    def test_clear_indicators_returns_an_empty_list_when_report_has_no_iocs(self):
        self.assertEqual(self.module.clear_indicators(None), [])
        self.assertEqual(
            self.module.clear_indicators([{'reputation': 0, 'ioc': 'safe.test'}]),
            [],
        )


if __name__ == '__main__':
    unittest.main()
