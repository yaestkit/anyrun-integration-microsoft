import os


DEFAULT_MINIMUM_CONFIDENCE_THRESHOLD = 50
MINIMUM_CONFIDENCE_THRESHOLD_MIN = 1
MINIMUM_CONFIDENCE_THRESHOLD_MAX = 100


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
    error_message = 'minimum_confidence_threshold must be an integer from 1 to 100.'

    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(error_message)

    try:
        minimum_confidence_threshold = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(error_message) from error

    if not (
        MINIMUM_CONFIDENCE_THRESHOLD_MIN
        <= minimum_confidence_threshold
        <= MINIMUM_CONFIDENCE_THRESHOLD_MAX
    ):
        raise ValueError(error_message)

    return minimum_confidence_threshold


def filter_indicators_by_minimum_confidence_threshold(
    indicators: list[dict],
    minimum_confidence_threshold: int,
) -> tuple[list[dict], int, int]:
    """
    Select indicators whose STIX confidence meets the inclusive threshold.

    Indicators with missing, boolean, non-numeric, or out-of-range confidence
    values are excluded. Returns selected indicators and counts of indicators
    excluded for low and invalid confidence respectively.
    """
    minimum_confidence_threshold = validate_minimum_confidence_threshold(
        minimum_confidence_threshold,
    )
    selected = []
    below_threshold = 0
    invalid_confidence = 0

    for indicator in indicators:
        confidence = indicator.get('confidence')

        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, int)
            or not 0 <= confidence <= MINIMUM_CONFIDENCE_THRESHOLD_MAX
        ):
            invalid_confidence += 1
            continue

        if confidence < minimum_confidence_threshold:
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
