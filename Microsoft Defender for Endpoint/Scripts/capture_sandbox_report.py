#!/usr/bin/env python3
"""Read-only capture of completion metadata for an EXISTING paid task.

No submission, no SDK dependency, no sample/URL/IOC/raw-report capture. JSONL
goes to stdout; API key is read from the environment or a hidden prompt.
Run separately from tests, only against the operator's test account.
"""
import argparse
from datetime import datetime, timezone
import getpass
import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler
from uuid import UUID


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # Never forward an API key to a redirected host.


def metadata(payload):
    data = payload.get('data') if isinstance(payload, dict) else None
    data = data if isinstance(data, dict) else {}
    analysis = data.get('analysis')
    analysis = analysis if isinstance(analysis, dict) else {}
    scores = analysis.get('scores') or {}
    verdict = scores.get('verdict') if isinstance(scores, dict) else {}
    verdict = verdict if isinstance(verdict, dict) else {}
    # Presence and values of these fields are the exact polling contract under
    # test. No file names, URLs, credentials, process lists or report bodies.
    return {
        'data.status': data.get('status'), 'data.analysis.status': analysis.get('status'),
        'data.remaining': data.get('remaining'), 'data.seconds_remaining': data.get('seconds_remaining'),
        'data.analysis.remaining': analysis.get('remaining'),
        'threatLevelText': verdict.get('threatLevelText'), 'score': verdict.get('score'),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task-uuid', required=True, type=UUID)
    parser.add_argument('--duration', type=int, default=900)
    parser.add_argument('--interval', type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.duration <= 7200 or not 1 <= args.interval <= 60:
        parser.error('duration must be 1..7200 seconds; interval must be 1..60 seconds')
    api_key = os.environ.get('ANYRUN_API_KEY') or getpass.getpass('ANY.RUN API key (hidden): ')
    api_key = api_key.strip()
    if not api_key:
        parser.error('API key is required')
    if not api_key.startswith('API-KEY '):
        api_key = 'API-KEY ' + api_key
    opener = build_opener(NoRedirect())
    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        record = {'timestamp': datetime.now(timezone.utc).isoformat(), 'task_uuid': str(args.task_uuid)}
        request = Request(f'https://api.any.run/v1/analysis/{args.task_uuid}', headers={'Authorization': api_key})
        try:
            with opener.open(request, timeout=min(60, max(0.1, deadline - time.monotonic()))) as response:
                record['http_status'] = response.status
                try:
                    record.update(metadata(json.load(response)))
                except (ValueError, TypeError):
                    record['error_type'] = 'InvalidReport'
        except HTTPError as error:
            record['http_status'] = error.code
            error.close()
        except (URLError, TimeoutError, OSError) as error:
            record['error_type'] = type(error).__name__  # Never print URL/error text/headers.
        print(json.dumps(record, ensure_ascii=False), flush=True)
        time.sleep(max(0, min(args.interval, deadline - time.monotonic())))


if __name__ == '__main__':
    main()
