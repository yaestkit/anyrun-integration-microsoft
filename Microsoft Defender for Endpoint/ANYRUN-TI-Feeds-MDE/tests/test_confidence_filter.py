import importlib.util
import unittest
from pathlib import Path


UTILS_PATH = (
    Path(__file__).parents[1]
    / 'src'
    / 'ANYRUN-Feeds-MDE-FA'
    / 'utils.py'
)
SPEC = importlib.util.spec_from_file_location('feeds_utils', UTILS_PATH)
feeds_utils = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(feeds_utils)


class ConfidenceFilterTests(unittest.TestCase):
    def test_default_rollout_threshold_50_selects_medium_and_high_confidence(self):
        indicators = [
            {'id': 'low', 'confidence': 25},
            {'id': 'medium', 'confidence': 75},
            {'id': 'high', 'confidence': 100},
        ]

        selected, below, invalid = feeds_utils.filter_indicators_by_confidence(
            indicators,
            50,
        )

        self.assertEqual([indicator['id'] for indicator in selected], ['medium', 'high'])
        self.assertEqual(below, 1)
        self.assertEqual(invalid, 0)

    def test_threshold_is_inclusive(self):
        indicators = [
            {'id': 'below', 'confidence': 89},
            {'id': 'equal', 'confidence': 90},
            {'id': 'above', 'confidence': 100},
        ]

        selected, below, invalid = feeds_utils.filter_indicators_by_confidence(
            indicators,
            90,
        )

        self.assertEqual(
            [indicator['id'] for indicator in selected],
            ['equal', 'above'],
        )
        self.assertEqual(below, 1)
        self.assertEqual(invalid, 0)

    def test_missing_and_invalid_confidence_fail_closed(self):
        indicators = [
            {'id': 'missing'},
            {'id': 'none', 'confidence': None},
            {'id': 'string', 'confidence': '100'},
            {'id': 'boolean', 'confidence': True},
            {'id': 'negative', 'confidence': -1},
            {'id': 'too-high', 'confidence': 101},
            {'id': 'valid', 'confidence': 100},
        ]

        selected, below, invalid = feeds_utils.filter_indicators_by_confidence(
            indicators,
            100,
        )

        self.assertEqual([indicator['id'] for indicator in selected], ['valid'])
        self.assertEqual(below, 0)
        self.assertEqual(invalid, 6)

    def test_threshold_must_be_between_1_and_100(self):
        for value in (1, '50', 100):
            with self.subTest(value=value):
                self.assertEqual(
                    feeds_utils.validate_minimum_confidence_threshold(value),
                    int(value),
                )

        for value in (0, 101, 'not-a-number', True, None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    feeds_utils.validate_minimum_confidence_threshold(value)

    def test_supported_stix_patterns_map_to_defender_types(self):
        cases = {
            "[ipv4-addr:value = '192.0.2.10']": ('IpAddress', '192.0.2.10'),
            "[domain-name:value = 'example.org']": ('DomainName', 'example.org'),
            "[url:value = 'https://example.org/a']": ('Url', 'https://example.org/a'),
            "[file:hashes.'MD5' = 'aabb']": ('FileMd5', 'aabb'),
            "[file:hashes.'SHA-1' = 'ccdd']": ('FileSha1', 'ccdd'),
            "[file:hashes.'SHA-256' = 'eeff']": ('FileSha256', 'eeff'),
            "[x509-certificate:hashes.'SHA-1' = '1122']": ('CertificateThumbprint', '1122'),
        }
        for pattern, expected in cases.items():
            with self.subTest(pattern=pattern):
                self.assertEqual(feeds_utils.extract_indicator_data(pattern), expected)

    def test_unsupported_or_compound_stix_patterns_fail_closed(self):
        patterns = (
            "[ipv6-addr:value = '2001:db8::1']",
            "[email-addr:value = 'x@example.org']",
            "[ipv4-addr:value = '192.0.2.1'] OR [ipv4-addr:value = '192.0.2.2']",
            None,
        )
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertIsNone(feeds_utils.extract_indicator_data(pattern))


if __name__ == '__main__':
    unittest.main()
