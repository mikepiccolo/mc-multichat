import json
import os
import time
import logging

# Minimal API Gateway v2-compatible response

def lambda_handler(event, context):
    logger = logging.getLogger(__name__)
    logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
    logger.info("Received event: %s", json.dumps(event))

    body = {
        "ok": True,
        "service": "health",
        "ts": int(time.time()),
        "region": os.environ.get("AWS_REGION", "unknown"),
        "runtime": "python3.13",
        # echo bits of the request for troubleshooting
        "request": {
            "rawPath": event.get("rawPath"),
            "requestContext": {
                "http": event.get("requestContext", {}).get("http", {})
            }
        }
    }

    logger.info("Response body: %s", json.dumps(body))

    # Return a 200 OK response
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
        "isBase64Encoded": False,
    }