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

        feed_fetch_depth = req.params.get('feed_fetch_depth') or request_body.get('feed_fetch_depth')
        minimum_confidence = req.params.get('minimum_confidence')

        if minimum_confidence is None:
            minimum_confidence = request_body.get('minimum_confidence', 100)

        if not feed_fetch_depth:
            raise ValueError(
                f'The following parameters: feed_fetch_depth are required.'
            )

        feed_connector = AnyRunFeeds(log, feed_fetch_depth, minimum_confidence)
        feed_connector.process_enrichment()

        return func.HttpResponse(
            json.dumps({"message": "IOC enrichment successful."}),
            status_code=200,
        )

    except RunTimeException as error:
        return func.HttpResponse(str(error), status_code=500)
    except Exception:
        error_msg = traceback.format_exc()
        log.error(f'Unspecified exception occurred: {error_msg}')
        log.error(error_msg)
        return func.HttpResponse(f'Unspecified exception: {error_msg}', status_code=500)
