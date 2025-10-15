import base64
import io
import json
import os
import hmac
import hashlib
import datetime as dt

import boto3
from boto3.dynamodb.conditions import Key
import requests

import logging

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

JSON = {"content-type": "application/json"}

def convert_to_e164(number: str) -> str:
    logger.info("Converting number to E164 - %s", number)
    number = number.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if number.startswith("+") and len(number) == 12 and number[1:].isdigit():
        return number
    # For simplicity, assume US country code if not provided
    if len(number) == 10 and number.isdigit():
        return f"+1{number}"
    elif len(number) == 11 and number.startswith("1") and number[1:].isdigit():
        return f"+{number}"
    else:
        raise ValueError("Number must be in E164 format or a 10-digit US number")

def get_secret(arn: str) -> str:
    logger.debug("Fetching secret from ARN: %s", arn)
    sm = boto3.client("secretsmanager")
    return sm.get_secret_value(SecretId=arn)["SecretString"]

def get_secret_json(arn: str) -> dict:
    logger.debug("Fetching JSON secret from ARN: %s", arn)
    return json.loads(get_secret(arn))

# def db_conn():
#     logger.debug("Connecting to DB");
#     creds = get_secret_json(os.environ["RDS_SECRET_ARN"])
#     ctx = ssl.create_default_context()
#     return pg8000.connect(
#         user=creds["username"], password=creds["password"],
#         host=creds["host"], port=int(creds["port"]), database=creds["dbname"],
#         ssl_context=ctx,
#     )

def ok(body): 
    msg = {"statusCode": 200, "headers": JSON, "body": json.dumps(body)}
    logger.info("Response: %s", json.dumps(msg))
    return msg

def bad(status, msg): 
    error = {"statusCode": status, "headers": JSON, "body": json.dumps({"ok": False, "error": msg})}
    logger.error("Error response: %s", json.dumps(error));
    return error

def get_token_from_event(event) -> str | None:
    # Try query param ?token=..., then JSON body {"token": "..."}
    qs = event.get("queryStringParameters") or {}
    if "token" in qs and qs["token"]:
        return qs["token"]
    try:
        body = json.loads(event.get("body") or "{}")
        t = body.get("token")
        if t: return t
    except Exception:
        pass
    return None

def require_studio_token(event) -> bool:
    logger.debug("Validating Studio Bearer token");
    token = get_token_from_event(event)
    if not token: return False
    logger.debug("Received token");
    expected = get_secret(os.environ["STUDIO_BEARER_ARN"])
    if not expected:
        logger.error("STUDIO_BEARER_ARN secret is empty or not set");
        return False
    else:
        logger.debug("Fetched secret from bearer ARN");
    
    return hmac.compare_digest(token, expected)

# 
# def require_studio_bearer(headers) -> bool:
#     logger.debug("Validating Studio Bearer token");
#     """Studio HTTP Request widget does not include Twilio signatures.
#     We protect with a shared Bearer token + API key (API Gateway)."""
#     auth = (headers or {}).get("authorization") or (headers or {}).get("Authorization")
#     if not auth or not auth.startswith("Bearer "): return False
#     token = auth.split(" ", 1)[1]
#     expected = get_secret(os.environ["STUDIO_BEARER_ARN"])
#     return hmac.compare_digest(token, expected)

# Optional: Twilio signature validation (for direct Twilio webhooks, not Studio HTTP Request)
def twilio_valid_signature(url: str, params: dict, signature_header: str) -> bool:
    logger.debug("Validating Twilio signature");
    token = get_secret(os.environ["TWILIO_TOKEN_ARN"])
    s = url
    if params:
        # Twilio spec: concatenate raw POST params in lexicographic order by key
        for k in sorted(params.keys()):
            s += k + (params[k] if params[k] is not None else "")
    mac = hmac.new(token.encode("utf-8"), s.encode("utf-8"), hashlib.sha1)
    expected = base64.b64encode(mac.digest()).decode("utf-8")
    return hmac.compare_digest(expected, signature_header or "")

# ---------- Embeddings/Transcription helpers ----------
def openai_key() -> str:
    logger.debug("Fetching OpenAI API key");
    return get_secret(os.environ["OPENAI_SECRET_ARN"])

def transcribe_via_openai(mp3_bytes: bytes) -> str:
    logger.info("Transcribing voicemail via OpenAI Whisper");
    """Use OpenAI Whisper transcription via REST multipart."""
    files = {
        "file": ("voicemail.mp3", io.BytesIO(mp3_bytes), "audio/mpeg"),
        "model": (None, "whisper-1"),
    }
    r = requests.post(
        "https://api.openai.com/v1/audio/transcriptions",
        headers={"Authorization": f"Bearer {openai_key()}"},
        files=files,
        timeout=60,
    )
    r.raise_for_status()
    return r.json().get("text", "")

def send_sms_via_twilio(from_e164: str, to_e164: str, body: str):
    logger.info("Sending SMS via Twilio from %s to %s", from_e164, to_e164)
    sid = get_secret(os.environ["TWILIO_SID_ARN"])
    tok = get_secret(os.environ["TWILIO_TOKEN_ARN"])
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    r = requests.post(
        url,
        auth=(sid, tok),
        data={"From": from_e164, "To": to_e164, "Body": body},
        timeout=15,
    )
    logger.debug("Twilio SMS response status: %d", r.status_code);
    r.raise_for_status()
    return r.json()

# ---------- DDB helpers ----------
def ddb():
    return boto3.client("dynamodb")

def conversations_table() -> str:
    return os.environ["DDB_CONVERSATIONS"]

def clients_table() -> str:
    return os.environ["DDB_CLIENTS"]

def consent_pk(client_id: str, from_e164: str) -> str:
    return f"CLIENT#{client_id}#USER#{from_e164}"

def consent_sk(ts_iso: str) -> str:
    return f"CONSENT#{ts_iso}"

def consent_exists(client_id: str, from_e164: str) -> bool:
    table = conversations_table()
    pk = consent_pk(client_id, from_e164)
    # Query: pk AND begins_with(sk, 'CONSENT#'), limit 1
    resp = ddb().query(
        TableName=table,
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={":pk": {"S": pk}, ":p": {"S": "CONSENT#"}},
        Limit=1,
        ScanIndexForward=False,
    )
    return resp.get("Count", 0) > 0

def put_consent(client_id: str, from_e164: str, to_e164: str, call_sid: str, source: str, digit: str) -> str:
    table = conversations_table()
    pk = consent_pk(client_id, from_e164)
    ts = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    sk = consent_sk(ts)
    item = {
        "pk": {"S": pk},
        "sk": {"S": sk},
        "gsi1pk": {"S": f"CLIENT#{client_id}"},
        "gsi1sk": {"S": f"TS#{ts}"},
        "type": {"S": "consent"},
        "client_id": {"S": client_id},
        "from": {"S": from_e164},
        "to": {"S": to_e164},
        "call_sid": {"S": call_sid},
        "source": {"S": source},
        "digit": {"S": digit},
        "ts": {"S": ts}
    }
    ddb().put_item(
        TableName=table, Item=item,
        ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)"
    )
    return ts

# ---------- Lookup ----------
def lookup_client_via_ddb(called_e164: str):
    logger.debug("Looking up client via DDB for called number: %s", called_e164);
    pr_table = os.environ["DDB_PHONE_ROUTES"]
    c_table  = clients_table()
    # 1) phone_routes[called] -> client_id
    pr = ddb().get_item(TableName=pr_table, Key={"phone_e164": {"S": called_e164}})
    if "Item" not in pr:
        logger.warning("No phone_routes entry for called number: %s", called_e164);
        return None
    client_id = pr["Item"]["client_id"]["S"]
    logger.debug("Found client_id: %s", client_id);
    # 2) clients[client_id] -> forward_to
    cr = ddb().get_item(TableName=c_table, Key={"client_id": {"S": client_id}})
    item = cr.get("Item", {})
    forward_to = item.get("escalation_phone_e164", {}).get("S") or item.get("twilio_number_e164", {}).get("S")
    greeting_message = item.get("greeting_message", {}).get("S") or os.environ.get("DEFAULT_GREETING_MESSAGE", "Sorry we missed your call.  Please leave a message after the tone.")  
    consent_message = item.get("consent_message", {}).get("S") or os.environ.get("DEFAULT_CONSENT_MESSAGE", "Press 1 to consent to receive SMS text messages. Message and data rates may apply. Reply STOP to opt out at any time.")  

    return {"client_id": client_id, "forward_to": forward_to, "greeting_message": greeting_message, "consent_message": consent_message}

# ---------- Route handlers ----------
def handle_lookup(event):
    logger.debug("Handling lookup event: %s", json.dumps(event));
    # Auth
    if not require_studio_token(event):
        return bad(401, "Unauthorized (studio token)")

    qs = event.get("queryStringParameters") or {}
    called = qs.get("called")
    caller = qs.get("from")
    if not called:
        return bad(400, "called required")

    # if not called.strip().startswith("+"):
    #     logger.debug("Prepending + to called number: %s", called);
    #     called = "+" + called.strip()
    try:
        called = convert_to_e164(called)
        caller = convert_to_e164(caller) 
    except Exception as e:
        return bad(400, f"called number invalid: {e}")

    # # Simple DynamoDB lookup:
    # # ddb = boto3.client("dynamodb")
    # pr_table = os.environ.get("DDB_PHONE_ROUTES", "")
    # c_table  = os.environ.get("DDB_CLIENTS", "")
    # if not pr_table or not c_table:
    #     # fall back to "clients" using the "called" == twilio_number_e164
    #     # pass
    #     return bad(500, "Phone routes table not configured");

    # logger.debug("Looking up clients table for called number: %s", called);
    # logger.debug("DynamoDB phone routes table: %s", pr_table);
    # # Minimal: return forward_to and client_id from "clients" table
    # # (You likely already inserted a clients row with twilio_number_e164)
    # ddbc = boto3.resource("dynamodb")
    # # resp = ddbc.scan(
    # #     TableName=c_table,
    # #     FilterExpression="twilio_number_e164 = :n",
    # #     ExpressionAttributeValues={":n": {"S": called}},
    # #     Limit=1,
    # # )

    # table = ddbc.Table(pr_table)
    # resp = table.query(
    #     KeyConditionExpression=Key("phone_e164").eq(called),
    # )

    # logger.debug("DynamoDB query response: %s", json.dumps(resp))

    # items = resp.get("Items", []) 
    # if not items:
    #     return bad(404, "Unknown number")
    # item = items[0]
    # client_id = item["client_id"]
    # forward_to = item["escalation_phone_e164"] 
    # # lookup client_id in clients table to get greeting_message
    # table = ddbc.Table(c_table)
    # resp = table.query(
    #     KeyConditionExpression=Key("client_id").eq(client_id),
    # )
    # items = resp.get("Items", [])
    # if not items:
    #     return bad(404, "Unknown client_id")
    
    # item = items[0]
    # greeting_message = item["greeting_message"] or "Please leave a message after the beep."
    
    consent = False
    looked = {}

    try :
        looked = lookup_client_via_ddb(called)
        if not looked:
            return bad(404, "Unknown number")
        
        if consent_exists(looked["client_id"], caller):
            consent = True

    except Exception as e:
        logger.error("DynamoDB lookup error: %s", e)
        return bad(500, f"DynamoDB lookup error: {e}")
    
    return ok({
        "ok": True,
        "client_id": looked["client_id"],
        "forward_to": looked["forward_to"],
        "called": called,
        "caller": caller,
        "greeting_message": looked["greeting_message"],
        "consent_message": looked["consent_message"],
        "consent_exists": consent,
        "voicemail_max_seconds": 120
    })

def handle_consent(event):
    if not require_studio_token(event):
        return bad(401, "Unauthorized (studio token)")
    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        return bad(400, "Invalid JSON")
    client_id = body.get("client_id")
    from_e164 = body.get("from")
    to_e164   = body.get("to")
    call_sid  = body.get("call_sid") or ""
    source    = body.get("source") or "ivr-dtmf"
    digit     = body.get("digit") or ""

    if not client_id or not from_e164 or not to_e164:
        return bad(400, "client_id, from, to required")

    try:
        from_e164 = convert_to_e164(from_e164)
        to_e164   = convert_to_e164(to_e164)
        if consent_exists(client_id, from_e164):
            return ok({"ok": True, "already_consented": True})
        ts = put_consent(client_id, from_e164, to_e164, call_sid, source, digit)
        return ok({"ok": True, "already_consented": False, "ts": ts})
    except Exception as e:
        return bad(500, f"consent write failed: {e}")

def handle_voicemail(event):
    logger.debug("Handling voicemail event: %s", json.dumps(event))
    if not require_studio_token(event):
        return bad(401, "Unauthorized (studio bearer)")
    
    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        return bad(400, "Invalid JSON")

    rec_url = body.get("recording_url") or body.get("RecordingUrl")
    caller  = body.get("from") or body.get("From")
    called  = body.get("to") or body.get("To")
    client_id = body.get("client_id")

    if not rec_url:
        logger.debug("No recording_url in body, calling handle_no_voicemail: %s", json.dumps(body))
        return handle_no_voicemail(event)

    if not caller or not called or not client_id:
        return bad(400, "from, to, client_id required")

    try:
        caller = convert_to_e164(caller)
        called = convert_to_e164(called)
    except Exception as e:
        return bad(400, f"phone number invalid: {e}")
    
    # if not called.strip().startswith("+"):
    #     logger.debug("Prepending + to called number: %s", called);
    #     called = "+" + called.strip()

   # Download MP3 (Twilio requires basic auth)
    sid = get_secret(os.environ["TWILIO_SID_ARN"])
    tok = get_secret(os.environ["TWILIO_TOKEN_ARN"])
    audio = requests.get(rec_url + ".mp3", auth=(sid, tok), timeout=60)
    audio.raise_for_status()

    transcript = ""
    try:
        transcript = transcribe_via_openai(audio.content)
    except Exception as e:
        transcript = f"[transcription_error: {e}]"

    if len(transcript) == 0:
        logger.info("Transcription empty, calling handle_no_voicemail")
        return handle_no_voicemail(event)
    
    # Notify client (owner) by SMS
    # From = the Twilio number (called), To = client's escalation phone
    # ddbc = boto3.client("dynamodb")
    # c_table = os.environ.get("DDB_CLIENTS","")
    # client_row = ddbc.get_item(TableName=c_table, Key={"client_id": {"S": client_id}}).get("Item", {})
    # notify_to = client_row.get("escalation_phone_e164", {}).get("S") or client_row.get("twilio_number_e164", {}).get("S")
    msg = f"Missed call voicemail from {caller}:\n{transcript[:800]}"

    ddbc = boto3.resource("dynamodb")
    pr_table = os.environ.get("DDB_PHONE_ROUTES", "")
    table = ddbc.Table(pr_table)
    resp = table.query(
        KeyConditionExpression=Key("phone_e164").eq(called),
    )

    logger.debug("DynamoDB query response: %s", json.dumps(resp))

    items = resp.get("Items", []) 
    if not items:
        return bad(404, "Unknown number")
    item = items[0]
    notify_to = item["escalation_phone_e164"] #or item.get("twilio_number_e164", {}).get("S")

    send_sms_via_twilio(from_e164=called, to_e164=notify_to, body=msg)

    # (Optional) Notify caller with a quick acknowledgment
    ack = "Thanks for your voicemail. We’ll get back to you shortly."
    try:
        if consent_exists(client_id, caller):
            send_sms_via_twilio(from_e164=called, to_e164=caller, body=ack)
    except Exception:
        pass

    return ok({"ok": True, "transcribed": bool(transcript), "length_bytes": len(audio.content)})

def handle_no_voicemail(event):
    logger.debug("Handling no-voicemail event: %s", json.dumps(event))
    if not require_studio_token(event):
        return bad(401, "Unauthorized (studio bearer)")
    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        return bad(400, "Invalid JSON")
    caller = body.get("from") or body.get("From")
    called = body.get("to") or body.get("To")
    client_id = body.get("client_id")
    if not caller or not called or not client_id:
        return bad(400, "from, to, client_id required")

    try:
        caller = convert_to_e164(caller);
        called = convert_to_e164(called);
    except Exception as e:
        return bad(400, f"phone number invalid: {e}")
    
    # if not called.strip().startswith("+"):
    #     logger.debug("Prepending + to called number: %s", called);
    #     called = "+" + called.strip()


    # Default missed-call SMS to caller (starts chatbot in a later step)
    try:
        if consent_exists(client_id, caller):
            send_sms_via_twilio(from_e164=called, to_e164=caller,
                        body="Sorry we missed your call. How can we help?")
    except Exception:
        pass

    # Notify client
    # ddbc = boto3.client("dynamodb")
    # c_table = os.environ.get("DDB_CLIENTS","")
    # client_row = ddbc.get_item(TableName=c_table, Key={"client_id": {"S": client_id}}).get("Item", {})
    # notify_to = client_row.get("escalation_phone_e164", {}).get("S") or client_row.get("twilio_number_e164", {}).get("S")
    ddbc = boto3.resource("dynamodb")
    pr_table = os.environ.get("DDB_PHONE_ROUTES", "")
    table = ddbc.Table(pr_table)
    resp = table.query(
        KeyConditionExpression=Key("phone_e164").eq(called),
    )

    logger.debug("DynamoDB query response: %s", json.dumps(resp))

    items = resp.get("Items", []) 
    if not items:
        return bad(404, "Unknown number")
    item = items[0]
    notify_to = item["escalation_phone_e164"] #or item.get("twilio_number_e164", {}).get("S")

 
    send_sms_via_twilio(from_e164=called, to_e164=notify_to,
                        body=f"Missed call from {caller}. No voicemail left.")

    return ok({"ok": True, "notified": True})

def lambda_handler(event, context):
    path = (event.get("requestContext", {}).get("resourcePath") or event.get("rawPath") or "").lower()
    method = (event.get("httpMethod") or "").upper()
    # Resource paths configured in Terraform:
    logger.info("Received request: %s %s", method, path)
    if path.endswith("/twilio/studio/lookup") and method == "GET": return handle_lookup(event)
    if path.endswith("/twilio/studio/consent") and method == "POST": return handle_consent(event)
    if path.endswith("/twilio/studio/voicemail") and method == "POST": return handle_voicemail(event)
    if path.endswith("/twilio/studio/no-voicemail") and method == "POST": return handle_no_voicemail(event)
    return bad(404, "Handler not found")
