from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable


def get_env_variable(name: str, default: str | None = None) -> str:
    """
    Retrieves environment variable value

    :param name: Environment variable name
    :return: Environment variable value
    :raises ValueError: If variable is not set
    """
    if not (variable := os.environ.get(name)):
        if default is not None:
            return default
        raise ValueError(f'Environment variable {name} is not set.')
    return variable


def prepare_url_analysis_options(analysis_options: dict) -> dict:
    """
    Removes file analysis options from the dict

    :param analysis_options: Analysis options
    :return: Url analysis options
    """
    analysis_options.pop('obj_ext_startfolder', None)
    analysis_options.pop('obj_ext_cmd', None)
    analysis_options.pop('obj_ext_extension', None)
    analysis_options.pop('run_as_root', None)
    analysis_options.pop('obj_force_elevation', None)

    return analysis_options


def generate_filepath(
    filename: str,
    filepath: str,
    machine_os_platform: str
) -> str:
    """
    Generates filepath according to the os platform

    :param filename: Target filename
    :param filepath: Target filepath
    :param machine_os_platform: OS platform type
    :return: Prepared filepath
    """
    if machine_os_platform == 'windows':
        filepath = str(Path(f'{filename}\\{filepath}'))
    elif machine_os_platform == 'linux':
        filepath = str(Path(f'{filename}/{filepath}'))
    return filepath


def generate_task_uuid_comment(evidence: str, task_uuid: str) -> str:
    """
    Generates analysis reference text using received parameters

    :param evidence:  Analysis evidence
    :param task_uuid: Analysis uuid
    :return: Text reference
    """
    return (
        f'ANY.RUN Sandbox Analysis Started\n\n'
        f'Evidence:\n{evidence}\n\n'
        f'Link to interactive task:\nhttps://app.any.run/tasks/{task_uuid}'
    )


def generate_analysis_summary_comment(
    evidence: str,
    analysis_verdict: str,
    score: int,
    task_url: str
) -> str:
    """
    Generates text report using received parameters

    :param evidence: Analysis evidence
    :param analysis_verdict: Analysis Threat Level
    :param score: Analysis score
    :param task_url: Analysis url
    :return: Text report
    """
    return (
        f'ANY.RUN analysis of Evidence results:\n\n'
        f'Evidence:\n{evidence}'
        f'\n\nVerdict:\n{analysis_verdict}'
        f'\n\nThreat score:\n{score}'
        f'\n\nLink to interactive report:\n{task_url}'
        f'\n\nThe indicators with Suspicious and Malicious severity can be found on the following path: '
        f'System/Settings/Endpoints/Rules/Indicators'
    )


def generate_ioc_comment(indicators: Iterable[dict] | None) -> str:
    """
    Generates text table using received IOCs

    :param indicators: List of indicators
    :return: IOCs text table
    """
    rows = 'Detected IOCs:'

    if not indicators:
        return rows + 'No indicators found'

    for indicator in indicators:
        rows += (
            f'\n\nType: {indicator.get("type").upper()}'
            f'\nThreat level: {convert_reputation(indicator.get("reputation"))}'
            f'\nIOC:\n{indicator.get("ioc")}'
        )
    return rows


def convert_reputation(reputation: int) -> str:
    """
    Converts integer reputation to the text threat level

    :param reputation: IOC reputation
    :return: IOC Threat Level
    """
    return {0: 'No info', 1: 'Suspicious', 2: 'Malicious'}.get(reputation)


def clear_indicators(indicators: list[dict]) -> list[dict] | None:
    """
    Removes indicators with zero reputation

    :param indicators: ANY.RUN indicators
    :return: ANY.RUN indicators
    """
    return [indicator for indicator in indicators if indicator.get('reputation') in (1, 2)] if indicators else None
