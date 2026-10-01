from __future__ import annotations

import os
from datetime import datetime, timezone
from urllib.parse import parse_qs, quote, urlparse

import requests
from anyrun import RunTimeException


ARM_RESOURCE = 'https://management.azure.com/'
SENTINEL_API_VERSION = '2025-09-01'
SENTINEL_PAGE_SIZE = 100


def _csv_values(value: str | None) -> list[str]:
    """Parse a comma-separated setting into unique, non-empty values."""
    result = []
    seen = set()
    for item in (value or '').split(','):
        normalized = item.strip()
        folded = normalized.casefold()
        if normalized and folded not in seen:
            seen.add(folded)
            result.append(normalized)
    return result


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class SentinelThreatIntelligenceSource:
    """Read a curated ANY.RUN indicator snapshot from Microsoft Sentinel."""

    def __init__(
        self,
        log,
        minimum_confidence_threshold: int,
        *,
        max_indicators: int = 10000,
    ) -> None:
        self._log = log
        self._minimum_confidence_threshold = int(minimum_confidence_threshold)
        self._max_indicators = int(max_indicators)
        if self._max_indicators < 1:
            raise ValueError('SentinelMaxIndicators must be greater than zero.')

        self._subscription_id = self._required_setting('SentinelSubscriptionID')
        self._resource_group = self._required_setting('SentinelResourceGroupName')
        self._workspace_name = self._required_setting('SentinelWorkspaceName')
        self._sources = _csv_values(self._required_setting('SentinelIndicatorSources'))
        self._required_tags = {
            value.casefold() for value in _csv_values(os.environ.get('SentinelRequiredTags'))
        }
        self._headers = {
            'Authorization': f'Bearer {self._managed_identity_token()}',
            'Content-Type': 'application/json',
        }

    @staticmethod
    def _required_setting(name: str) -> str:
        value = os.environ.get(name)
        if not value:
            raise ValueError(f'Environment variable {name} is not set.')
        return value

    def _managed_identity_token(self) -> str:
        endpoint = os.environ.get('IDENTITY_ENDPOINT')
        identity_header = os.environ.get('IDENTITY_HEADER')
        if not endpoint or not identity_header:
            raise RunTimeException(
                'The Function App managed identity endpoint is unavailable. '
                'Enable the system-assigned identity before using the Sentinel source.'
            )

        response = self._request(
            'GET',
            endpoint,
            headers={'X-IDENTITY-HEADER': identity_header},
            params={
                'resource': ARM_RESOURCE,
                'api-version': '2019-08-01',
            },
        )
        if response.status_code >= 300:
            self._raise_response_error('Failed to authenticate with the Function App managed identity.', response)
        token = response.json().get('access_token')
        if not token:
            raise RunTimeException('The managed identity token response did not contain an access token.')
        return token

    def get_indicators(self) -> tuple[list[dict], int, bool]:
        """Return active, source-scoped Sentinel indicators in the connector STIX shape."""
        workspace = quote(self._workspace_name, safe='')
        resource_group = quote(self._resource_group, safe='')
        url = (
            f'{ARM_RESOURCE}subscriptions/{self._subscription_id}'
            f'/resourceGroups/{resource_group}'
            f'/providers/Microsoft.OperationalInsights/workspaces/{workspace}'
            '/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators'
            f'?api-version={SENTINEL_API_VERSION}'
        )
        body = {
            'includeDisabled': False,
            'minConfidence': self._minimum_confidence_threshold,
            'pageSize': SENTINEL_PAGE_SIZE,
            'sources': self._sources,
            'sortBy': [
                {'itemKey': 'lastUpdatedTimeUtc', 'sortOrder': 'descending'},
            ],
        }

        selected = []
        downloaded = 0
        truncated = False
        seen_page_tokens = set()

        while True:
            response = self._request('POST', url, headers=self._headers, json=body)
            if response.status_code >= 300:
                self._raise_response_error('Failed to query Microsoft Sentinel threat indicators.', response)

            document = response.json()
            page = document.get('value') or []
            downloaded += len(page)
            for item in page:
                normalized = self._normalize_indicator(item)
                if normalized is not None:
                    selected.append(normalized)
                if len(selected) >= self._max_indicators:
                    truncated = bool(document.get('nextLink')) or len(page) == SENTINEL_PAGE_SIZE
                    break

            if len(selected) >= self._max_indicators:
                break

            next_link = document.get('nextLink')
            if not next_link:
                break
            skip_token = self._skip_token(next_link)
            if not skip_token or skip_token in seen_page_tokens:
                raise RunTimeException('Microsoft Sentinel returned an invalid or repeated pagination token.')
            seen_page_tokens.add(skip_token)
            body['skipToken'] = skip_token

        self._log.info(
            'Queried %s Microsoft Sentinel indicators from sources %s; selected %s.',
            downloaded,
            ', '.join(self._sources),
            len(selected),
        )
        if truncated:
            self._log.warning(
                'Sentinel selection reached SentinelMaxIndicators=%s; stale Defender indicators will be preserved.',
                self._max_indicators,
            )
        return selected, downloaded, truncated

    def _normalize_indicator(self, item: dict) -> dict | None:
        properties = item.get('properties') or {}
        source = properties.get('source')
        if not isinstance(source, str) or source.casefold() not in {
            value.casefold() for value in self._sources
        }:
            return None
        if properties.get('revoked') is True or properties.get('defanged') is True:
            return None

        now = datetime.now(timezone.utc)
        valid_from = _parse_timestamp(properties.get('validFrom'))
        valid_until = _parse_timestamp(properties.get('validUntil'))
        if valid_from and valid_from > now:
            return None
        if valid_until and valid_until <= now:
            return None

        tags = {
            str(tag).casefold()
            for tag in (properties.get('threatIntelligenceTags') or [])
            if tag is not None
        }
        if self._required_tags and not self._required_tags.issubset(tags):
            return None

        confidence = properties.get('confidence')
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not self._minimum_confidence_threshold <= confidence <= 100
        ):
            return None

        pattern = properties.get('pattern')
        if not isinstance(pattern, str) or not pattern.strip():
            return None

        return {
            'id': properties.get('externalId') or item.get('name'),
            'confidence': confidence,
            'pattern': pattern,
            'external_references': properties.get('externalReferences') or [],
            'description': properties.get('description'),
            'source': source,
            'valid_until': properties.get('validUntil'),
        }

    @staticmethod
    def _skip_token(next_link: str) -> str | None:
        query = parse_qs(urlparse(next_link).query)
        values = query.get('$skipToken') or query.get('skipToken')
        return values[0] if values else None

    @staticmethod
    def _request(method: str, url: str, **kwargs) -> requests.Response:
        try:
            return requests.request(method, url, timeout=(10, 60), **kwargs)
        except (requests.RequestException, OSError) as error:
            raise RunTimeException(f'Microsoft Sentinel request failed: {error}') from error

    @staticmethod
    def _raise_response_error(message: str, response: requests.Response) -> None:
        detail = response.text[:2000]
        raise RunTimeException(f'{message} HTTP {response.status_code}: {detail}', response.status_code)
