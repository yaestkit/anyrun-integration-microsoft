from __future__ import annotations

import os
import re


MIN_CONFIDENCE_THRESHOLD = 1
MAX_CONFIDENCE_THRESHOLD = 100

STIX_PATTERN = re.compile(
    r"^\[(?P<object_type>[a-z0-9-]+):(?P<property>[^ ]+) = '(?P<value>(?:\\.|[^'])*)'\]$",
    re.IGNORECASE,
)

DEFENDER_INDICATOR_TYPES = {
    ('ipv4-addr', 'value'): 'IpAddress',
    ('domain-name', 'value'): 'DomainName',
    ('url', 'value'): 'Url',
    ('file', 'hashes.md5'): 'FileMd5',
    ('file', 'hashes.sha-1'): 'FileSha1',
    ('file', 'hashes.sha-256'): 'FileSha256',
    ('x509-certificate', 'hashes.sha-1'): 'CertificateThumbprint',
}


def get_env_variable(name: str, default: str | None = None) -> str:
    """
    Retrieves environment variable value

    :param name: Environment variable name
    :param default: Value to return if the variable is not set; when omitted, missing variable raises
    :return: Environment variable value
    :raises ValueError: If variable is not set and no default is provided
    """
    variable = os.environ.get(name)

    if not variable:
        if default is not None:
            return default
        raise ValueError(f'Environment variable {name} is not set.')
        
    return variable


def validate_minimum_confidence_threshold(value: int | str) -> int:
    """Validate and normalize the inclusive confidence threshold."""
    if isinstance(value, bool):
        raise ValueError('minimum_confidence_threshold must be an integer from 1 to 100.')

    try:
        minimum_confidence_threshold = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError('minimum_confidence_threshold must be an integer from 1 to 100.') from error

    if not MIN_CONFIDENCE_THRESHOLD <= minimum_confidence_threshold <= MAX_CONFIDENCE_THRESHOLD:
        raise ValueError('minimum_confidence_threshold must be an integer from 1 to 100.')

    return minimum_confidence_threshold


def filter_indicators_by_confidence(
    indicators: list[dict],
    minimum_confidence_threshold: int,
) -> tuple[list[dict], int, int]:
    """
    Select indicators whose STIX confidence meets the inclusive threshold.

    Indicators with missing, boolean, non-numeric, or out-of-range confidence
    values are excluded. Returns selected indicators and counts of indicators
    excluded for low and invalid confidence respectively.
    """
    minimum_confidence_threshold = validate_minimum_confidence_threshold(minimum_confidence_threshold)
    selected = []
    below_threshold = 0
    invalid_confidence = 0

    for indicator in indicators:
        confidence = indicator.get('confidence')

        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0 <= confidence <= MAX_CONFIDENCE_THRESHOLD
        ):
            invalid_confidence += 1
            continue

        if confidence < minimum_confidence_threshold:
            below_threshold += 1
            continue

        selected.append(indicator)

    return selected, below_threshold, invalid_confidence


def extract_indicator_data(pattern: str) -> tuple[str, str] | None:
    """
    Extracts indicator type, value using raw indicator

    :param pattern: STIX pattern
    :return: Microsoft Defender indicator type and value, or None when the
        STIX pattern cannot be represented by the Defender Indicators API.
    """
    if not isinstance(pattern, str):
        return None

    match = STIX_PATTERN.fullmatch(pattern.strip())
    if not match:
        return None

    object_type = match.group('object_type').lower()
    property_name = match.group('property').replace("'", '').lower()
    indicator_type = DEFENDER_INDICATOR_TYPES.get((object_type, property_name))
    if not indicator_type:
        return None

    indicator_value = match.group('value').replace("\\'", "'").replace('\\\\', '\\')
    return indicator_type, indicator_value


def get_severity(confidence: int) -> str:
    if confidence == 0:
        return 'Informational'
    elif 1 <= confidence < 50:
        return 'Low'
    elif 50 <= confidence < 100:
        return 'Medium'
    elif confidence == 100:
        return 'High'


def get_description(external_references: list[dict[str, str]]) -> str:
    if not external_references:
        return 'No description'
    urls = [reference.get('url') for reference in external_references[:9] if reference.get('url')]
    return ','.join(urls) or 'No description'
