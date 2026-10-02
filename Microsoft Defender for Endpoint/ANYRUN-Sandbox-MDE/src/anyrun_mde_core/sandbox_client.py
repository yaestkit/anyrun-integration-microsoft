"""Bound every SDK HTTP request, including SDK paths passing timeout=None."""
from __future__ import annotations

import time
from urllib.parse import urlsplit

import aiohttp
import requests

from anyrun.connectors.sandbox.operation_systems import WindowsConnector, LinuxConnector
from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector

from .config import Config
from .api_errors import SandboxAPIError, SandboxTransportError


class BoundedRequests:
    def __init__(self, *args, deadline_monotonic=None, **kwargs):
        self.deadline_monotonic = deadline_monotonic
        self.request_deadline = None
        super().__init__(*args, **kwargs)

    async def _make_request_async(self, method, url, *args, **kwargs):
        submitting = str(method).upper() == 'POST' and urlsplit(url).path.rstrip('/').endswith('/analysis')
        timeout = Config.ANYRUN_SUBMIT_TIMEOUT_SECONDS if submitting else Config.ANYRUN_REQUEST_TIMEOUT_SECONDS
        deadlines = [limit for limit in (self.deadline_monotonic, self.request_deadline) if limit is not None]
        if deadlines:
            remaining = min(deadlines) - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('ANY.RUN job time budget expired before the HTTP request.')
            timeout = min(timeout, remaining)
        kwargs['request_timeout'] = min(kwargs.get('request_timeout') or timeout, timeout)
        # SDK 1.14.19 wraps its own HTTP exception, losing status_code. Ask for
        # the raw response and classify it here, including non-JSON failures.
        parse_response = kwargs.pop('parse_response', True)
        try:
            response = await super()._make_request_async(method, url, *args, parse_response=False, **kwargs)
            if not parse_response:
                return response
            status = response.status_code if self._enable_requests else response.status
            try:
                payload = response.json() if self._enable_requests else await response.json()
            except (ValueError, aiohttp.ContentTypeError):
                if status not in (200, 201, 202):
                    raise SandboxAPIError(status, 'Response did not contain a JSON error body.')
                raise
            if status not in (200, 201, 202):
                description = (payload.get('message') or payload.get('description')) if isinstance(payload, dict) else None
                raise SandboxAPIError(status, str(description or 'Request rejected.'))
            return payload
        except SandboxAPIError:
            # A classified HTTP response is not an unknown transport outcome,
            # even if JSON parsing attached a ClientError as its context.
            raise
        except Exception as error:
            # Preserve transport errors wrapped by the SDK without guessing
            # from text. __context__ retains the original underlying exception.
            cause, seen = error, set()
            while cause is not None and id(cause) not in seen:
                seen.add(id(cause))
                if isinstance(cause, (aiohttp.ClientError, requests.RequestException, OSError, TimeoutError)):
                    raise SandboxTransportError('ANY.RUN transport failed; request outcome is unknown.') from error
                cause = cause.__cause__ or cause.__context__
            raise


class BoundedWindowsConnector(BoundedRequests, WindowsConnector):
    pass


class BoundedLinuxConnector(BoundedRequests, LinuxConnector):
    pass


class BoundedBaseConnector(BoundedRequests, BaseSandboxConnector):
    pass
