import os


MIN_CONFIDENCE = 1
MAX_CONFIDENCE = 100


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


def validate_minimum_confidence(value: int | str) -> int:
    """Validate and normalize the inclusive confidence threshold."""
    if isinstance(value, bool):
        raise ValueError('minimum_confidence must be an integer from 1 to 100.')

    try:
        minimum_confidence = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError('minimum_confidence must be an integer from 1 to 100.') from error

    if not MIN_CONFIDENCE <= minimum_confidence <= MAX_CONFIDENCE:
        raise ValueError('minimum_confidence must be an integer from 1 to 100.')

    return minimum_confidence


def filter_indicators_by_confidence(
    indicators: list[dict],
    minimum_confidence: int,
) -> tuple[list[dict], int, int]:
    """
    Select indicators whose STIX confidence meets the inclusive threshold.

    Indicators with missing, boolean, non-numeric, or out-of-range confidence
    values are excluded. Returns selected indicators and counts of indicators
    excluded for low and invalid confidence respectively.
    """
    minimum_confidence = validate_minimum_confidence(minimum_confidence)
    selected = []
    below_threshold = 0
    invalid_confidence = 0

    for indicator in indicators:
        confidence = indicator.get('confidence')

        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0 <= confidence <= MAX_CONFIDENCE
        ):
            invalid_confidence += 1
            continue

        if confidence < minimum_confidence:
            below_threshold += 1
            continue

        selected.append(indicator)

    return selected, below_threshold, invalid_confidence


def extract_indicator_data(pattern: str) -> tuple[str, str]:
    """
    Extracts indicator type, value using raw indicator

    :param pattern: STIX pattern
    :return: ANY.RUN indicator type, ANY.RUN indicator value
    """
    indicator_type = pattern.split(":")[0][1:]
    indicator_value = pattern.split(" = '")[1][:-2]

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
    return ','.join(reference.get('url') for reference in external_references[:9])
