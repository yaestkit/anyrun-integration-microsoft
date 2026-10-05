from __future__ import annotations

import json
import traceback
from datetime import datetime, timedelta, timezone
from itertools import islice
from urllib.parse import quote

import requests
from anyrun import RunTimeException
from anyrun.connectors import FeedsConnector

from .config import Config
from .utils import (
    extract_indicator_data,
    filter_indicators_by_confidence,
    get_description,
    get_env_variable,
    get_severity,
    validate_minimum_confidence_threshold,
)

DATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFENDER_PAGE_SIZE = 10000
DEFENDER_BATCH_SIZE = 500
ANYRUN_FEED_LIMIT = 10000


def batched(iterable, size):
    """Yield fixed-size tuples without requiring a particular Python minor version."""
    iterator = iter(iterable)
    while batch := tuple(islice(iterator, size)):
        yield batch


class AnyRunFeeds:
    """ Class - wrapper to interact with MS Defender and ANY.RUN REST API """
    def __init__(self, log, feed_fetch_depth: int, minimum_confidence_threshold: int = 50) -> None:
        self._headers = None
        self._config = Config
        self._log = log

        self._feed_fetch_depth = int(feed_fetch_depth)
        self._minimum_confidence_threshold = validate_minimum_confidence_threshold(minimum_confidence_threshold)

        self._authenticate()

    def _authenticate(self):
        """
        Authenticates connector in MS Defender API
        """
        self._client_id = get_env_variable('AzureClientID')

        url = f"https://login.microsoftonline.com/{get_env_variable('AzureTenantID')}/oauth2/token"
        body = {
            'resource': self._config.DEFENDER_OAUTH_RESOURCE,
            'client_id': self._client_id,
            'client_secret': get_env_variable('AzureClientSecret'),
            'grant_type': 'client_credentials',
        }
        response = self._make_request(method='POST', url=url, data=body)

        if response.status_code >= 300:
            self._throw_error(
                f'Failed to authenticate at: {self._config.DEFENDER_OAUTH_RESOURCE}. Please, check your credentials.', response
            )

        self._headers = {
            'Authorization': f"Bearer {response.json().get('access_token')}",
            'Content-Type': 'application/json',
        }

    def process_enrichment(self) -> dict[str, int]:
        """ Initializes IOCs enrichment """
        with FeedsConnector(
            api_key=get_env_variable('ANYRUN_api_key'),
            integration=Config.VERSION
        ) as connector:
            connector.check_authorization()
            self._log.info('Successful credentials check.')
            self._log.info('Initialized IOCs enrichment.')

            # Fetch and validate the replacement set before deleting the active
            # indicators. An ANY.RUN/network/parsing failure must not remove the
            # last known-good Defender set.
            selected_indicators, downloaded_count, feed_truncated = self._get_indicators(connector)
            payloads, unsupported = self._prepare_indicators(selected_indicators)
            if selected_indicators and not payloads:
                raise RunTimeException(
                    'All selected ANY.RUN indicators use unsupported or invalid STIX patterns; '
                    'the existing Defender indicators were preserved.'
                )

            # Restore the original full-refresh policy: remove this dedicated
            # app's entire previous set before importing the current set. This
            # frees capacity even when the feed reaches its configured limit.
            existing = self._list_indicators()
            existing_ids = [item['id'] for item in existing if item.get('id')]
            deleted = self._delete_indicators(existing_ids)
            if feed_truncated:
                self._log.warning(
                    'ANY.RUN returned the configured limit of %s objects; '
                    'the previous connector set was cleared and will be replaced '
                    'with this fetched set.', ANYRUN_FEED_LIMIT,
                )
            if payloads:
                imported, rejected = self._load_indicators(payloads)
            else:
                imported, rejected = 0, 0
            summary = {
                'downloaded': downloaded_count,
                'selected': len(selected_indicators),
                'prepared': len(payloads),
                'unsupported': unsupported,
                'feed_truncated': feed_truncated,
                'attempted_import': len(payloads),
                'deleted': deleted,
                'imported': imported,
                'rejected': rejected,
            }
            self._log.info('IOC enrichment summary: %s', json.dumps(summary, sort_keys=True))
            if rejected:
                raise RunTimeException(
                    f'Microsoft Defender rejected {rejected} of {len(payloads)} indicators; '
                    'the full refresh is incomplete. Retry after resolving the import errors.'
                )
            return summary

    def _delete_indicators(self, indicators: list[str]) -> int:
        """ Deletes indicators from the XDR """
        if not indicators:
            self._log.info('No previous ANY.RUN indicators found in Microsoft XDR.')
            return 0

        self._log.info(f'Found {len(indicators)} ANY.RUN indicators to delete.')

        url = f'{self._config.DEFENDER_API_BASE_URL}/api/indicators/BatchDelete'

        for chunk in batched(indicators, DEFENDER_BATCH_SIZE):
            payload = {'IndicatorIds': list(chunk)}

            response = self._make_request('POST', url, json.dumps(payload))

            if response.status_code >= 300:
                self._throw_error('Failed to batch delete indicators in Microsoft XDR.', response)

        self._log.info('Indicators successfully deleted.')
        return len(indicators)

    def _list_indicators(self) -> list[dict]:
        """
        Retrieves indicator identifiers

        :return: Indicators created by this connector identity
        """
        # 'title' is not a reliably filterable indicator property in the Defender API; scope the
        # query to indicators created by this app's own identity so unrelated/manual indicators
        # (e.g. hand-added hashes) are never matched and deleted.
        odata_filter = quote(f"createdBy eq '{self._client_id}'")
        indicators = []
        skip = 0

        while True:
            url = (
                f'{self._config.DEFENDER_API_BASE_URL}/api/indicators'
                f'?$filter={odata_filter}&$top={DEFENDER_PAGE_SIZE}&$skip={skip}'
            )
            response = self._make_request('GET', url)
            if response.status_code >= 300:
                self._throw_error('Failed to fetch indicators from Microsoft XDR', response)

            page = response.json().get('value') or []
            indicators.extend(page)
            if len(page) < DEFENDER_PAGE_SIZE:
                break
            skip += DEFENDER_PAGE_SIZE

        return indicators


    def _get_indicators(self, connector: FeedsConnector) -> tuple[list[dict], int, bool]:
        """
       Gets actual indicators using ANY.RUN TAXII STIX server

       :param connector: ANY.RUN TI Feeds connector instance
       :return: List of the indicators
       """

        feeds = connector.get_taxii_stix(
            match_type='indicator',
            match_version='all',
            limit=ANYRUN_FEED_LIMIT,
            modified_after=(datetime.now(timezone.utc) - timedelta(days=self._feed_fetch_depth)).strftime(DATE_TIME_FORMAT)
        )

        downloaded_indicators = feeds.get('objects') or []
        indicators, below_threshold, invalid_confidence = filter_indicators_by_confidence(
            downloaded_indicators,
            self._minimum_confidence_threshold,
        )

        self._log.info(
            'Downloaded %s indicators; selected %s with confidence >= %s.',
            len(downloaded_indicators),
            len(indicators),
            self._minimum_confidence_threshold,
        )

        if below_threshold:
            self._log.info(
                'Skipped %s indicators below the minimum confidence threshold.',
                below_threshold,
            )

        if invalid_confidence:
            self._log.warning(
                'Skipped %s indicators with missing or invalid confidence.',
                invalid_confidence,
            )

        if indicators:
            self._log.info(f'Found {len(indicators)} indicators after confidence filtering.')
        else:
            self._log.warning(
                'No ANY.RUN TI indicators met the minimum confidence threshold of %s.',
                self._minimum_confidence_threshold,
            )

        return indicators, len(downloaded_indicators), len(downloaded_indicators) >= ANYRUN_FEED_LIMIT

    def _prepare_indicators(self, indicators: list[dict]) -> tuple[list[dict], int]:
        """Convert supported STIX indicators into Defender API entities."""
        indicator_action = get_env_variable('DefenderIndicatorAction', default='Audit')
        if indicator_action not in {'Audit', 'Block'}:
            raise ValueError('DefenderIndicatorAction must be Audit or Block.')

        payloads = []
        unsupported = 0
        for indicator in indicators:
            severity = get_severity(indicator.get('confidence'))
            parsed = extract_indicator_data(indicator.get('pattern'))
            if severity == 'Informational' or not parsed:
                unsupported += 1
                continue

            indicator_type, indicator_value = parsed
            payloads.append(
                {
                    'indicatorValue': indicator_value,
                    'title': 'IoC from ANY.RUN TI Feeds',
                    'description': get_description(indicator.get('external_references')),
                    'action': indicator_action,
                    'generateAlert': True,
                    'severity': severity,
                    'indicatorType': indicator_type,
                }
            )

        if unsupported:
            self._log.warning(
                'Skipped %s selected indicators with unsupported or invalid STIX patterns.',
                unsupported,
            )
        self._log.info('Prepared %s indicators for Microsoft Defender import.', len(payloads))
        return payloads, unsupported

    def _load_indicators(
        self,
        indicators: list[dict],
    ) -> tuple[int, int]:
        """
        Loads actual indicators to the XDR

        :param indicators: The list of the ANY.RUN indicators
        """
        url = f'{self._config.DEFENDER_API_BASE_URL}/api/indicators/import'
        imported = 0
        failures = []
        for chunk in batched(indicators, DEFENDER_BATCH_SIZE):
            chunk_items = list(chunk)
            payload = {'Indicators': chunk_items}
            response = self._make_request('POST', url, data=json.dumps(payload))

            if response.status_code >= 300:
                self._throw_error('Failed to load indicators to the Microsoft Defender', response)

            results = response.json().get('value') or []
            if len(results) != len(chunk_items):
                raise RunTimeException(
                    'Microsoft Defender returned an incomplete import result: '
                    f'attempted {len(chunk_items)}, received {len(results)} result records.'
                )

            chunk_failures = []
            for source, result in zip(chunk_items, results):
                if result.get('isFailed'):
                    chunk_failures.append((source, result))
            imported += len(results) - len(chunk_failures)
            failures.extend(chunk_failures)
            self._log.info(
                'Defender import batch result: attempted=%s, succeeded=%s, failed=%s.',
                len(chunk_items),
                len(results) - len(chunk_failures),
                len(chunk_failures),
            )

        if failures:
            sample = [
                {
                    'indicator': result.get('indicator') or source.get('indicatorValue'),
                    'failureReason': result.get('failureReason'),
                }
                for source, result in failures[:10]
            ]
            self._log.error(
                'Microsoft Defender rejected %s indicators. First failures: %s',
                len(failures),
                json.dumps(sample, ensure_ascii=False),
            )
        self._log.info(
            'Microsoft Defender import completed: accepted=%s, rejected=%s.',
            imported,
            len(failures),
        )
        return imported, len(failures)

    def _make_request(
        self,
        method: str,
        url: str,
        data: dict | str | None = None
        ) -> requests.Response:
        """
        Executes a request ti the specified API endpoint

        :param method: HTTP Request method
        :param url: Endpoint URL
        :param data: Request body
        :return: Response object
        """
        try:
            response = requests.request(method, url, headers=self._headers, data=data)
        except (requests.RequestException, OSError) as error:
            self._throw_error(f'Unspecified network exception: {error}')
        return response

    def _throw_error(self, error_message: str, response: requests.Response | None = None) -> None:
        """
        Logs error text then builds and raises exception

        :param error_message: Error text
        :param response: Response object
        """
        self._log.error(error_message)

        if response is not None:
            raise RunTimeException(error_message + response.text, response.status_code)
        raise RunTimeException(error_message)
