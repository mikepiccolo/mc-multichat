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

def now_iso():
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def lambda_client(): return boto3.client("lambda")

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
    logger.debug("Transcribing voicemail via OpenAI Whisper");
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

# ---------- Twilio ----------
def send_sms_via_ms(msid: str, to_e164: str, body: str) -> dict:
    logger.debug("Sending SMS via Twilio Messaging Service SID: %s to %s", msid, to_e164)
    sid = get_secret(os.environ["TWILIO_SID_ARN"])
    tok = get_secret(os.environ["TWILIO_TOKEN_ARN"])
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    r = requests.post(url, auth=(sid, tok), data={
        "To": to_e164,
        "MessagingServiceSid": msid,
        "Body": body
    }, timeout=20)
    r.raise_for_status()
    return r.json()

def fetch_twilio_recording_bytes(recording_url: str) -> bytes:
    logger.debug("Fetching Twilio recording from URL: %s", recording_url)
    """
    recording_url from Studio is like:
    https://api.twilio.com/2010-04-01/Accounts/ACxxx/Recordings/REyyy
    We’ll try with '.mp3' first, then raw.
    """
    sid = get_secret(os.environ["TWILIO_SID_ARN"])
    tok = get_secret(os.environ["TWILIO_TOKEN_ARN"])
    for url in (recording_url + ".mp3", recording_url):
        resp = requests.get(url, auth=(sid, tok), timeout=30)
        if resp.ok and resp.content:
            return resp.content
    raise RuntimeError("failed to download recording")

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
    logger.debug("Looking up client via DDB for called number: %s", called_e164)
    pr_table = os.environ["DDB_PHONE_ROUTES"]
    c_table  = clients_table()
    # 1) phone_routes[called] -> client_id
    pr = ddb().get_item(TableName=pr_table, Key={"phone_e164": {"S": called_e164}})
    if "Item" not in pr:
        logger.warning("No phone_routes entry for called number: %s", called_e164)
        return None
    client_id = pr["Item"]["client_id"]["S"]
    logger.debug("Found client_id: %s", client_id);
    # 2) clients[client_id] -> forward_to
    cr = ddb().get_item(TableName=c_table, Key={"client_id": {"S": client_id}})
    item = cr.get("Item", {})

    def S(k, d=""): return item.get(k, {}).get("S", d)
    def B(k, d=False): return item.get(k, {}).get("BOOL", d)

    forward_to =  S("escalation_phone_e164",None) or item.get("twilio_number_e164", {}).get("S")
    greeting_message = S("greeting_message",None) or os.environ.get("DEFAULT_GREETING_MESSAGE", "Sorry we missed your call.  Please leave a message after the tone.")  
    consent_message = S("consent_message",None) or os.environ.get("DEFAULT_CONSENT_MESSAGE", "Press 1 to consent to receive SMS text messages. Message and data rates may apply. Reply STOP to opt out at any time.")  
    messaging_service_sid = S("messaging_service_sid","")
    a2p_approved = B("a2p_approved", False)
    
    return {"client_id": client_id, 
            "display_name": S("display_name",""),
            "forward_to": forward_to, 
            "greeting_message": greeting_message, 
            "consent_message": consent_message,
            "messaging_service_sid": messaging_service_sid,
            "a2p_approved": a2p_approved
            }

# ---------- persist helpers ----------
def put_event_missed_call(client_id: str, from_e164: str, to_e164: str, call_sid: str, transcript: str | None, forwarded_from: str | None) -> bool:
    logger.debug("Putting missed call event for CallSid: %s", call_sid)
    """
    Writes a single immutable event row keyed by CallSid.
    Returns True if created (not duplicate), False if already existed (dedupe).
    """
    pk = f"CLIENT#{client_id}#USER#{from_e164}"
    ts = now_iso()
    sk = f"EVENT#MISSED#{call_sid}"
    item = {
        "pk": {"S": pk},
        "sk": {"S": sk},
        "gsi1pk": {"S": f"CLIENT#{client_id}"},
        "gsi1sk": {"S": f"TS#{ts}"},
        "type": {"S": "event_missed_call"},
        "from": {"S": from_e164},
        "to": {"S": to_e164},
        "call_sid": {"S": call_sid},
        "forwarded_from": {"S": forwarded_from or ""},
        "transcript": {"S": (transcript or "")[:4000]},
        "ts": {"S": ts}
    }
    try:
        ddb().put_item(
            TableName=conversations_table(),
            Item=item,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)"
        )
        return True
    except ddb().exceptions.ConditionalCheckFailedException:
        return False

def put_outbound_message(client_id: str, from_e164: str, to_e164: str, body: str, sid: str | None):
    logger.debug("Logging outbound message to conversations table for audit")
    pk = f"CLIENT#{client_id}#USER#{to_e164}"
    ts = now_iso()
    sk = f"TS#{ts}#OUT#{sid or 'NA'}"
    item = {
        "pk": {"S": pk},
        "sk": {"S": sk},
        "gsi1pk": {"S": f"CLIENT#{client_id}"},
        "gsi1sk": {"S": f"TS#{ts}"},
        "type": {"S": "outbound_msg"},
        "from": {"S": from_e164},
        "to": {"S": to_e164},
        "body": {"S": body[:1200]},
        "sid": {"S": sid or ""},
        "ts": {"S": ts}
    }
    ddb().put_item(TableName=conversations_table(), Item=item)


# Helper to get last 10 digits of a phone number 
def _last10(e164_or_any: str | None) -> str | None:
    logger.debug("Extracting last 10 digits from: %s", e164_or_any);
    if not e164_or_any:
        return None
    digs = "".join(ch for ch in e164_or_any if ch.isdigit())

    last10 = digs[-10:] if len(digs) >= 10 else digs or None
    logger.debug("Last 10 digits: %s", last10);
    return last10

# ---------- Orchestrator invocation ----------
def invoke_orchestrator(client_id: str, from_e164: str, text: str, call_sid: str, transcript: str | None) -> str:
    logger.debug("Invoking orchestrator for client_id=%s, from=%s, call_sid=%s", client_id, from_e164, call_sid);
    fn = os.environ.get("ORCHESTRATOR_FN")
    if not fn:
        return ""
    payload = {
        "client_id": client_id,
        "channel": "sms",
        "user_e164": from_e164,
        "text": text or "",                  # may be empty; orchestrator will use transcript
        "event": "missed_call",
        "transcript": transcript or "",
        "call_sid": call_sid
    }
    try:
        resp = lambda_client().invoke(
            FunctionName=fn, InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8")
        )
        data = json.loads(resp.get("Payload").read().decode("utf-8"))
        body = data.get("body")
        if isinstance(body, str):
            body = json.loads(body)
        return (body or {}).get("reply", "") if isinstance(body, dict) else (data.get("reply", "") or "")
    except Exception:
        return ""
    
# ---------- Route handlers ----------
def handle_lookup(event):
    logger.debug("Handling lookup event: %s", json.dumps(event));
    # Auth
    if not require_studio_token(event):
        return bad(401, "Unauthorized (studio token)")

    qs = event.get("queryStringParameters") or {}
    called = qs.get("called")
    caller = qs.get("from")
    fwd    = qs.get("fwd") 

    if not called:
        return bad(400, "called required")

    try:
        called = convert_to_e164(called)
        caller = convert_to_e164(caller) 
    except Exception as e:
        return bad(400, f"called number invalid: {e}")
    
    consent = False
    looked = {}
    skip_dial = False

    try :
        looked = lookup_client_via_ddb(called)
        if not looked:
            return bad(404, "Unknown number")
        
        if consent_exists(looked["client_id"], caller):
            consent = True

        forward_to = looked["forward_to"] or ""

        # Determine whether we should skip dialing the client (to avoid loop on forwarded calls)
        # Compare last 10 digits to tolerate formatting differences.
        is_forwarded_from_client = (_last10(fwd) is not None) and (_last10(fwd) == _last10(forward_to))
        skip_dial = "true" if is_forwarded_from_client else "false"
        logger.debug("skip_dial=%s (fwd=%s, forward_to=%s)", skip_dial, fwd, forward_to);
    

    except Exception as e:
        logger.error("DynamoDB lookup error: %s", e)
        return bad(500, f"DynamoDB lookup error: {e}")
    
    # Log inbound call to conversations table for audit
    # Do not fail on error
    try:
        logger.debug("Logging inbound call to conversations table for audit");
        table = os.environ["DDB_CONVERSATIONS"]
        pk = f"CLIENT#{looked['client_id']}#USER#{caller or 'unknown'}"
        ts = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        boto3.client("dynamodb").put_item(
            TableName=table,
            Item={
                "pk": {"S": pk},
                "sk": {"S": f"CALL#{ts}"},
                "gsi1pk": {"S": f"CLIENT#{looked['client_id']}"},
                "gsi1sk": {"S": f"TS#{ts}"},
                "type": {"S": "inbound_call"},
                "from": {"S": caller or ""},
                "to": {"S": called or ""},
                "forwarded_from": {"S": fwd or ""},
                "skip_dial": {"S": skip_dial},
                "ts": {"S": ts},
            }
        )
    except Exception:
        logger.error("Failed to log inbound call to conversations table")
        pass

    return ok({
        "ok": True,
        "client_id": looked["client_id"],
        "forward_to": looked["forward_to"],
        "called": called,
        "caller": caller,
        "forwarded_from": fwd,
        "skip_dial": skip_dial,
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
    call_sid  = body.get("call_sid")
    fwd       = body.get("forwarded_from")

    if not rec_url:
        logger.debug("No recording_url in body, calling handle_no_voicemail: %s", json.dumps(body))
        return handle_no_voicemail(event)

    if not caller or not called or not client_id:
        return bad(400, "from, to, client_id required")

    if not call_sid:
        return bad(400, "call_sid required")
    
    try:
        caller = convert_to_e164(caller)
        called = convert_to_e164(called)
    except Exception as e:
        return bad(400, f"phone number invalid: {e}")
    
     # (1) Transcribe (best-effort)
    transcript = ""
    try:
        audio = fetch_twilio_recording_bytes(rec_url)
        transcript = transcribe_via_openai(audio) or ""
    except Exception as e:
        logger.error("Transcription error: %s", e)
        transcript = ""

    if len(transcript) == 0:
        logger.info("Transcription empty, calling handle_no_voicemail")
        return handle_no_voicemail(event)
    
    # Notify client (owner) by SMS
    msg = f"Missed call voicemail from {caller}:\n{transcript[:800]}"
    client = lookup_client_via_ddb(called)
 
    logger.debug("handle_voicemail: Client record details - %s", json.dumps(client))

    try:
        send_sms_via_ms(client.get("messaging_service_sid",""), to_e164=client.get("forward_to",""), body=msg)
    except Exception as e:
        logger.error("Failed to send SMS to escalation number via Messaging Service SID: %s", e)
        pass
        
    # (2) Create dedupe event (one per CallSid)
    created = put_event_missed_call(client_id, caller, called, call_sid, transcript, fwd)
    if not created:
        # already processed this CallSid
        return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True, "deduped": True})}

    # (3) Decide if we can text the caller
    may_text = client["a2p_approved"] and consent_exists(client_id, caller) and bool(client["messaging_service_sid"])

    reply_text = ""
    if may_text:
        # Let the orchestrator generate a first outreach message, grounded by transcript
        reply_text = invoke_orchestrator(client_id, caller, "", call_sid, transcript)
        if not reply_text:
            # Fallback template
            brand = client["display_name"]
            if transcript:
                reply_text = f"{brand}: Got your voicemail—thanks for the details. I can help next steps. What’s the best time to text/call back? Reply STOP to opt out."
            else:
                reply_text = f"{brand}: Sorry we missed your call. How can we help? Reply STOP to opt out."
        try:
            sent = send_sms_via_ms(client["messaging_service_sid"], caller, reply_text)
            put_outbound_message(client_id, called, caller, reply_text, sent.get("sid"))
        except Exception as e:
            # swallow; we still wrote the event
            logger.error(f"Failed to send outbound SMS to caller, {e}")
            pass
    else:
        logger.info("Not sending SMS to caller %s: may_text=%s", caller, may_text)

    return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True, "texted": bool(reply_text)})}

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
    call_sid  = body.get("call_sid")
    fwd       = body.get("forwarded_from")

    if not caller or not called or not client_id and not call_sid:
        return {"statusCode": 400, "headers": JSON, "body": json.dumps({"ok": False, "error": "missing fields"})}

    try:
        caller = convert_to_e164(caller)
        called = convert_to_e164(called)
    except Exception as e:
        return bad(400, f"phone number invalid: {e}")
    
    # (1) Create dedupe event (one per CallSid)
    created = put_event_missed_call(client_id, caller, called, call_sid, None, fwd)
    if not created:
        return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True, "deduped": True})}

    # (2) If allowed, send a generic auto-reply
    client = lookup_client_via_ddb(called)
    may_text = client["a2p_approved"] and consent_exists(client_id, caller) and bool(client["messaging_service_sid"])

    reply_text = ""
    if may_text:
        reply_text = invoke_orchestrator(client_id, caller, "", call_sid, None)
        if not reply_text:
            brand = client["display_name"]
            reply_text = f"{brand}: Sorry we missed your call. How can we help? Reply STOP to opt out."
        try:
            sent = send_sms_via_ms(client["messaging_service_sid"], caller, reply_text)
            
            put_outbound_message(client_id, called, caller, reply_text, sent.get("sid"))
            
            send_sms_via_ms(client["messaging_service_sid"], to_e164=client.get("forward_to",""), 
                            body=f"Missed call from {caller}. No voicemail left.")
        except Exception as e:
            logger.error(f"Failed to send outbound SMS to caller, {e}")
            pass
    else:
        logger.info("Not sending SMS to caller %s: may_text=%s", caller, may_text)

    return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True, "texted": bool(reply_text)})}    

def lambda_handler(event, context):
    path = (event.get("requestContext", {}).get("resourcePath") or event.get("rawPath") or "").lower()
    method = (event.get("httpMethod") or "").upper()
    # Resource paths configured in Terraform:
    logger.info("Received request: %s %s", method, path)
    try:
        if path.endswith("/twilio/studio/lookup") and method == "GET": 
            return handle_lookup(event)
        if path.endswith("/twilio/studio/consent") and method == "POST": 
            return handle_consent(event)
        if path.endswith("/twilio/studio/voicemail") and method == "POST": 
            return handle_voicemail(event)
        if path.endswith("/twilio/studio/no-voicemail") and method == "POST": 
            return handle_no_voicemail(event)
    except Exception as e:
        logger.error("Unhandled exception: %s", e)
        return bad(500, f"Unhandled exception in lambda_handler: {e}")
    
    return bad(404, "Handler not found")
