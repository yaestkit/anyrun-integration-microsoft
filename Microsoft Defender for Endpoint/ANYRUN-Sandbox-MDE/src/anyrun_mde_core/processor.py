from __future__ import annotations

import hashlib
import logging as log
import math
import time
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from anyrun import RunTimeException

from .config import Config
from .api_errors import SandboxAPIError, SandboxTransportError, SubmissionRejected
from .defender import MicrosoftDefender
from .sandbox_client import BoundedWindowsConnector, BoundedLinuxConnector
from .utils import clear_indicators, get_env_variable, prepare_url_analysis_options, sanitize_error_text

StatusCallback = Callable[[str, dict[str, object]], None]


class RecoveryRequired(RuntimeError):
    """A paid POST may have succeeded; automatic resubmission is unsafe."""


def _evidence_key(analysis_type: str, value: str) -> str:
    # Hash full identity, including URL query. Display text is not identity.
    if analysis_type == 'file':
        value = value.replace('\\', '/')
    return hashlib.sha256(f'{analysis_type}:{value}'.encode()).hexdigest()


def process_alert(
    job_id: str, alert_id: str, alert_source: str, machine_os_platform: str,
    analysis_options: dict[str, str | int | bool],
    deadline_monotonic: float | None = None, status_callback: StatusCallback | None = None,
    checkpoint_callback: StatusCallback | None = None, resume_state: dict | None = None,
) -> list[dict[str, object]]:
    """Resume saved tasks before collecting any new evidence."""
    _check_deadline(deadline_monotonic)
    ms_defender = MicrosoftDefender(log, deadline_monotonic=deadline_monotonic)
    ms_defender.deduplicate_comments = bool((resume_state or {}).get('work_started_at'))
    saved = list((resume_state or {}).get('analyses') or [])
    latest = (resume_state or {}).get('latest_analysis')
    if isinstance(latest, dict) and not any(
        item.get('task_uuid') == latest.get('task_uuid') and item.get('evidence_key') == latest.get('evidence_key')
        for item in saved
    ):
        saved.append(latest)
    results, processed, legacy_names = [], set(), set()
    for item in saved:
        if not item.get('task_uuid'):
            if item.get('submission_rejected') and item.get('submission_http_status') != 429:
                raise SubmissionRejected(f'ANY.RUN rejected submission with HTTP {item.get("submission_http_status")}.')
            if item.get('submission_intent') or (resume_state or {}).get('stage') == 'submitting_to_anyrun':
                raise RecoveryRequired(
                    'A submission may have created a paid ANY.RUN task, but its UUID was not saved. '
                    'Check ANY.RUN history and restore the UUID; automatic resubmission is disabled.'
                )
            continue
        if item.get('evidence_key'):
            processed.add(item['evidence_key'])
        else:
            legacy_names.add(_file_basename(str(item.get('evidence', ''))))
        result = item if item.get('enriched') else setup_anyrun_connector(
            str(item['analysis_type']), alert_id, machine_os_platform, analysis_options.copy(),
            ms_defender, filename=str(item.get('evidence', '')),
            deadline_monotonic=deadline_monotonic, status_callback=status_callback,
            checkpoint_callback=checkpoint_callback, resume_item=item,
        )
        if result:
            results.append(result)
    if results and len(results) >= (resume_state or {}).get('evidence_count', math.inf):
        return results

    machine_id, evidences = ms_defender.get_evidences(alert_id, machine_os_platform)
    filepaths, filenames, urls = (evidences.get(key) or [] for key in ('filepaths', 'filenames', 'urls'))
    urls = list(dict.fromkeys(urls))
    _emit_status(status_callback, 'collecting_evidence', evidence_count=len(filepaths) + len(urls))
    for name in legacy_names:
        if sum(_file_basename(path) == name for path in filepaths) > 1:
            raise RecoveryRequired('Legacy checkpoint matches multiple files; manual recovery is required.')
    pending = list(dict.fromkeys(
        (path, filenames[index] if index < len(filenames) else _file_basename(path))
        for index, path in enumerate(filepaths)
        if _evidence_key('file', path) not in processed and _file_basename(path) not in legacy_names
    ))

    def analyse_file(file, path, filename):
        if not file:
            ms_defender.add_comment(alert_id, f'Requested file: {_file_basename(filename)} was not found.')
            return
        _emit_status(status_callback, 'evidence_collected', evidence_type='file',
                     evidence=_file_basename(filename), sha256=hashlib.sha256(file).hexdigest())
        result = setup_anyrun_connector(
            'file', alert_id, machine_os_platform, analysis_options.copy(), ms_defender,
            file, _file_basename(filename), deadline_monotonic=deadline_monotonic,
            status_callback=status_callback, checkpoint_callback=checkpoint_callback,
            evidence_key=_evidence_key('file', path),
        )
        if result:
            results.append(result)

    if alert_source == 'WindowsDefenderAtp':
        for path, filename in pending:
            _check_deadline(deadline_monotonic)
            try:
                file = ms_defender.download_file_from_machine(machine_id, path)
            except RunTimeException as error:
                message = f'Requested file: {_file_basename(path)} could not be collected: {sanitize_error_text(error, limit=1000)}'
                log.warning(message)
                ms_defender.add_comment(alert_id, message[:1500])
                continue
            analyse_file(file, path, filename)
    elif alert_source == 'WindowsDefenderAv' and pending:
        ms_defender.upload_ps_script_to_library(machine_os_platform)
        targets = ms_defender.execute_ps_script_on_machine(machine_id, machine_os_platform, pending, job_id)
        for (path, _), (filename, blob_name) in zip(pending, targets):
            analyse_file(ms_defender.download_file_from_storage(blob_name), path, filename)
    for url in urls:
        key = _evidence_key('url', url)
        if key in processed:
            continue
        _check_deadline(deadline_monotonic)
        result = setup_anyrun_connector(
            'url', alert_id, machine_os_platform, analysis_options.copy(), ms_defender,
            url=url, deadline_monotonic=deadline_monotonic, status_callback=status_callback,
            checkpoint_callback=checkpoint_callback, evidence_key=key,
        )
        if result:
            results.append(result)
    return results


def setup_anyrun_connector(
    analysis_type, alert_id, machine_os_platform, analysis_options, ms_defender,
    file=None, filename=None, url=None, deadline_monotonic=None, status_callback=None,
    checkpoint_callback=None, resume_item=None, evidence_key=None,
):
    connector_type = {'windows': BoundedWindowsConnector, 'linux': BoundedLinuxConnector}.get(machine_os_platform)
    if connector_type is None:
        return None
    with connector_type(api_key=get_env_variable('ANYRUN_API_KEY'), integration=Config.VERSION,
                        deadline_monotonic=deadline_monotonic) as connector:
        return process_analysis(
            analysis_type, alert_id, connector, analysis_options, ms_defender,
            file, filename, url, deadline_monotonic, status_callback,
            checkpoint_callback, resume_item, evidence_key,
        )


def process_analysis(
    analysis_type, alert_id, connector, analysis_options, ms_defender,
    file=None, filename=None, url=None, deadline_monotonic=None, status_callback=None,
    checkpoint_callback=None, resume_item=None, evidence_key=None,
) -> dict[str, object]:
    _check_deadline(deadline_monotonic)
    item = dict(resume_item or {
        'analysis_type': analysis_type, 'evidence': _display_evidence(analysis_type, filename, url),
        'evidence_key': evidence_key or _evidence_key(analysis_type, filename or url or ''),
    })
    item['evidence'] = _display_evidence(analysis_type, str(item.get('evidence', '')), str(item.get('evidence', '')))
    if item.get('enriched'):
        return item

    # Fresh analyses cannot have comments from this task yet. On recovery the
    # previous PATCH may have succeeded before its checkpoint was saved, so
    # preserve the GET check for every unfinished comment operation.
    ms_defender.deduplicate_comments = resume_item is not None

    def save(stage):
        item['stage'] = stage
        if checkpoint_callback is not None:
            checkpoint_callback(stage, dict(item))
        else:
            _emit_status(status_callback, stage, latest_analysis=dict(item))

    if not item.get('task_uuid'):
        if resume_item:
            raise RecoveryRequired('Cannot resubmit an uncertain paid analysis without its task UUID.')
        if file is not None:
            item['sha256'] = hashlib.sha256(file).hexdigest()
        item['submission_intent'] = True
        item['submission_started_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        save('submitting_to_anyrun')  # A failed checkpoint prevents the paid POST.
        try:
            if analysis_type == 'file':
                analysis_options.pop('obj_ext_browser', None)
                task_uuid = connector.run_file_analysis(file_content=file, filename=filename, **analysis_options)
            else:
                task_uuid = connector.run_url_analysis(obj_url=url, **prepare_url_analysis_options(analysis_options))
        except SandboxAPIError as error:
            if error.status_code in {400, 401, 403, 413, 422, 429}:
                # Only an explicit rejection permits clearing the intent. A
                # failed persistence here must still leave recovery fail-closed.
                item.update(submission_intent=False, submission_rejected=True,
                            submission_http_status=error.status_code)
                save('submission_rejected')
                if error.status_code != 429:
                    raise SubmissionRejected(str(error)) from error
                raise  # Rate limit: the next queue delivery may retry the POST.
            item['submission_http_status'] = error.status_code
            save('submitting_to_anyrun')
            raise RecoveryRequired(f'HTTP {error.status_code} submission outcome is uncertain; check ANY.RUN history before recovery.') from error
        except Exception as error:
            # Includes timeouts, transport failures, malformed successful
            # responses and unclassified errors. Never pay again automatically.
            raise RecoveryRequired('Submission outcome is uncertain; check ANY.RUN history before recovery.') from error
        if not task_uuid:
            raise RecoveryRequired('ANY.RUN submission did not return a task UUID; do not resubmit automatically.')
        item.update(task_uuid=str(task_uuid), task_url=f'https://app.any.run/tasks/{task_uuid}',
                    submitted_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
        save('submitted_to_anyrun')
    task_uuid = item['task_uuid']
    if not item.get('reference_commented'):
        ms_defender.add_task_reference_comment(alert_id, item['evidence'], task_uuid=task_uuid)
        item['reference_commented'] = True
        save('submitted_to_anyrun')
    if not item.get('verdict'):
        save('waiting_for_verdict')
        report = _wait_for_report(connector, task_uuid, int(analysis_options.get('opt_timeout', 240)),
                                  deadline_monotonic, status_callback)
        item.update(
            verdict=_report_value(report, 'data', 'analysis', 'scores', 'verdict', 'threatLevelText'),
            threat_score=_report_value(report, 'data', 'analysis', 'scores', 'verdict', 'score'),
            task_url=_display_evidence('url', None, str(_report_value(report, 'data', 'analysis', 'permanentUrl') or item['task_url'])),
        )
        save('verdict_received')
    else:
        report = {'data': {'analysis': {'scores': {'verdict': {
            'threatLevelText': item['verdict'], 'score': item.get('threat_score'),
        }}, 'permanentUrl': item['task_url']}}}
    _check_deadline(deadline_monotonic)
    indicators = connector.get_analysis_report(task_uuid, report_format='ioc')
    valid = clear_indicators(indicators) or []
    if not item.get('ioc_imported'):
        rejected = (ms_defender.submit_indicators(valid, task_uuid) or []) if valid else []
        item.update(indicators_count=len(valid), rejected_indicators_count=len(rejected), ioc_imported=True)
        save('enriching_alert')
    if item.get('rejected_indicators_count') and not item.get('ioc_rejections_commented'):
        ms_defender.add_comment(
            alert_id,
            f'Microsoft Defender rejected {item["rejected_indicators_count"]} of '
            f'{item["indicators_count"]} indicators produced by ANY.RUN task {task_uuid}. '
            'See Function App logs for failure reasons.',
        )
        item['ioc_rejections_commented'] = True
        save('enriching_alert')
    if valid and not item.get('ioc_commented'):
        ms_defender.add_ioc_comment(alert_id, valid)
        item['ioc_commented'] = True
        save('enriching_alert')
    if not item.get('summary_commented'):
        ms_defender.add_summary_comment(alert_id, item['evidence'], item['verdict'], report)
        item['summary_commented'] = True
        save('enriching_alert')
    item['enriched'] = True
    save('analysis_completed')
    return item


def _wait_for_report(connector, task_uuid, analysis_timeout_seconds, deadline_monotonic=None, status_callback=None):
    """Poll bounded HTTP requests; never enter the SDK's SSE iterator."""
    wait_deadline = time.monotonic() + analysis_timeout_seconds + Config.VERDICT_WAIT_MARGIN_SECONDS
    last_log = -math.inf
    last_progress = None
    last_progress_at = -math.inf
    consecutive_errors = 0
    while True:
        _check_deadline(deadline_monotonic)
        if time.monotonic() >= wait_deadline:
            raise TimeoutError(f'ANY.RUN verdict for task {task_uuid} was not available in time.')
        previous_deadline = getattr(connector, 'request_deadline', None)
        connector.request_deadline = min(wait_deadline, deadline_monotonic) if deadline_monotonic is not None else wait_deadline
        try:
            try:
                report = connector.get_analysis_report(task_uuid, report_format='json')
                consecutive_errors = 0
            except (SandboxAPIError, SandboxTransportError, TimeoutError) as error:
                retryable = not isinstance(error, SandboxAPIError) or (
                    error.status_code in {404, 409, 425, 429} or 500 <= error.status_code <= 599
                )
                consecutive_errors += 1
                if not retryable or consecutive_errors >= Config.REPORT_TRANSIENT_ERROR_LIMIT:
                    raise
                log.warning('Report polling for task %s delayed (%s/%s): %s.', task_uuid,
                            consecutive_errors, Config.REPORT_TRANSIENT_ERROR_LIMIT, type(error).__name__)
                report = None
        finally:
            connector.request_deadline = previous_deadline
        verdict = _report_value(report, 'data', 'analysis', 'scores', 'verdict', 'threatLevelText')
        # SDK confirms the verdict path. Status/remaining are optional API hints.
        status = _report_value(report, 'data', 'status')
        if status is None:
            status = _report_value(report, 'data', 'analysis', 'status')
        remaining = _remaining_seconds(report)
        active = str(status).upper() in {'RUNNING', 'PREPARING', 'PENDING'} or (
            isinstance(status, (int, float)) and 0 <= status < 100
        )
        if str(status).upper() in {'FAILED', '-1'}:
            raise RuntimeError(f'ANY.RUN task {task_uuid} failed.')
        # A provisional verdict is not proof of completion. Elapsed opt_timeout
        # cannot prove it either (preparation/manual extensions). Missing or
        # unknown status fails closed; require a positive completion signal.
        finished = str(status).upper() in {'DONE', 'COMPLETED', '100'}
        if verdict and finished and remaining in (None, 0):
            _check_deadline(deadline_monotonic)
            return report
        now = time.monotonic()
        if remaining is not None and remaining > 0:
            wait_deadline = max(wait_deadline, now + remaining + Config.VERDICT_WAIT_MARGIN_SECONDS)
        elif active:
            # Accommodate manual extension when this report omits remaining.
            # The overall persisted 90-minute job budget still applies.
            wait_deadline = max(wait_deadline, now + Config.VERDICT_WAIT_MARGIN_SECONDS)
        progress = {'anyrun_task_status': status, 'anyrun_seconds_remaining': remaining}
        if progress != last_progress and (
            status != (last_progress or {}).get('anyrun_task_status')
            or now - last_progress_at >= Config.HEARTBEAT_SECONDS
        ):
            _emit_status(status_callback, 'waiting_for_verdict', **progress)
            last_progress, last_progress_at = progress, now
        if now - last_log >= Config.HEARTBEAT_SECONDS:
            log.info('Waiting for ANY.RUN task %s: %s, remaining %s s.', task_uuid, status, remaining)
            last_log = now
        limit = min(wait_deadline, deadline_monotonic) if deadline_monotonic is not None else wait_deadline
        time.sleep(max(0, min(Config.VERDICT_POLL_SECONDS, limit - time.monotonic())))


def _remaining_seconds(report):
    for path in [('data', 'remaining'), ('data', 'seconds_remaining'), ('data', 'analysis', 'remaining')]:
        value = _report_value(report, *path)
        if value is not None:
            try:
                value = float(value)
                return max(0, value) if math.isfinite(value) else None
            except (ValueError, TypeError):
                pass
    return None


def _check_deadline(deadline_monotonic):
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        raise RunTimeException('ANY.RUN analysis exceeded the 90-minute job time budget; remaining evidence was not submitted.')


def _emit_status(callback, state, **details):
    if callback is not None:
        callback(state, details)


def _display_evidence(analysis_type, filename, url):
    if analysis_type == 'file':
        return _file_basename(filename or 'unnamed-file')[:260]
    parsed = urlsplit(url or '')
    return urlunsplit((parsed.scheme, parsed.netloc.rsplit('@', 1)[-1], parsed.path, '', ''))[:500]


def _file_basename(filename):
    return str(filename).replace('\\', '/').rsplit('/', 1)[-1]


def _report_value(report, *path):
    value = report
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value
