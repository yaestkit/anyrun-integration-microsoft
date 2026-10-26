import json
import logging as log
import traceback

import azure.functions as func
from anyrun import RunTimeException

from .anyrunfeeds import AnyRunFeeds


def main(req: func.HttpRequest) -> func.HttpResponse:
    log.info('AnyRunFeeds started. Checking TI Feeds credentials...')

    try:
        try:
            request_body = req.get_json()
        except ValueError:
            request_body = {}
        if not isinstance(request_body, dict):
            raise ValueError('The request body must be a JSON object.')

        feed_fetch_depth = req.params.get('feed_fetch_depth') or request_body.get('feed_fetch_depth')
        minimum_confidence_threshold = req.params.get('minimum_confidence_threshold')

        if minimum_confidence_threshold is None:
            minimum_confidence_threshold = request_body.get('minimum_confidence_threshold', 50)

        if not feed_fetch_depth:
            raise ValueError(
                f'The following parameters: feed_fetch_depth are required.'
            )

        feed_connector = AnyRunFeeds(log, feed_fetch_depth, minimum_confidence_threshold)
        summary = feed_connector.process_enrichment()

        rejected = summary.get('rejected', 0)
        response_body = {
            'status': 'completed_with_warnings' if rejected else 'completed',
            'message': 'IOC enrichment completed with warnings.' if rejected else 'IOC enrichment successful.',
            'summary': summary,
        }
        if rejected:
            response_body['warning'] = (
                f"Microsoft Defender rejected {rejected} of {summary['attempted_import']} indicators. "
                'Accepted indicators remain imported; see summary.rejection_details for the rejection reasons.'
            )

        return func.HttpResponse(
            json.dumps(response_body),
            status_code=200,
            mimetype='application/json',
        )

    except RunTimeException as error:
        return func.HttpResponse(str(error), status_code=500)
    except Exception:
        error_msg = traceback.format_exc()
        log.error(f'Unspecified exception occurred: {error_msg}')
        log.error(error_msg)
        return func.HttpResponse(f'Unspecified exception: {error_msg}', status_code=500)
