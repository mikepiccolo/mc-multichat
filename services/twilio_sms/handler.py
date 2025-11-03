import json
import os
import urllib.parse
import datetime as dt

import boto3
import requests

import hashlib
import hmac
import base64
import urllib.parse

JSON = {"content-type": "application/json"}
FORM = "application/x-www-form-urlencoded"

import logging

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

def convert_to_e164(number: str) -> str:
    logger.debug("Converting number to E164 - %s", number)
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

# ---------- Secrets & DDB helpers ----------
def sm():
    return boto3.client("secretsmanager")

def get_secret(arn: str) -> str:
    return sm().get_secret_value(SecretId=arn)["SecretString"]

def ddb():
    return boto3.client("dynamodb")

def lambda_client():
    return boto3.client("lambda")

def tbl_clients(): return os.environ["DDB_CLIENTS"]
def tbl_routes():  return os.environ["DDB_PHONE_ROUTES"]
def tbl_convos():  return os.environ["DDB_CONVERSATIONS"]

def now_iso():
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def last10(s: str | None):
    if not s: return None
    digs = "".join(ch for ch in s if ch.isdigit())
    return digs[-10:] if digs else None

# ---------- Twilio signature validation ----------
def build_request_url(event) -> str:
    logger.debug("Building request URL for signature validation")
    # Canonical URL Twilio posted to (scheme + host + path). No query string for our endpoints.
    headers = event.get("headers") or {}
    proto = headers.get("X-Forwarded-Proto") or headers.get("x-forwarded-proto") or "https"
    host  = headers.get("Host") or headers.get("host")
    path  = (event.get("requestContext", {}).get("path")  # REST API v1
             or event.get("rawPath") or "")
    if not path.startswith("/"):
        path = "/" + path
    return f"{proto}://{host}{path}"

def parse_form(body: str) -> dict:
    logger.debug("Parsing form-urlencoded body")
    # keep_blank_values is CRUCIAL for signature validation
    # Ref: https://norahsakal.com/.../keep-blank-values/
    pairs = urllib.parse.parse_qs(body, keep_blank_values=True)
    # Flatten to first value per key
    return {k: v[0] if isinstance(v, list) else v for k, v in pairs.items()}

# ---------- Twilio signature validation (no external deps) ----------
def _build_canonical_url(event) -> str:
    logger.debug("Building canonical URL for Twilio signature validation")
    headers = event.get("headers") or {}
    proto = headers.get("X-Forwarded-Proto") or headers.get("x-forwarded-proto") or "https"
    host  = headers.get("Host") or headers.get("host")
    # REST API v1 gives requestContext.path; HTTP API v2 gives rawPath
    path  = (event.get("requestContext", {}).get("path") or event.get("rawPath") or "")
    if not path.startswith("/"):
        path = "/" + path
    # Twilio signs POSTs against the URL WITHOUT query string
    return f"{proto}://{host}{path}"

def _parse_form_urlencoded(body: str) -> dict:
    logger.debug("Parsing form-urlencoded body for Twilio signature validation")
    # keep blank values to match Twilio’s calculation
    pairs = urllib.parse.parse_qsl(body or "", keep_blank_values=True)
    out = {}
    for k, v in pairs:
        # If a key repeats (e.g., MediaUrl0/1 are distinct keys), last one wins — that’s fine.
        out[k] = v
    return out

def _compute_twilio_signature(url: str, params: dict, auth_token: str) -> str:
    logger.debug("Computing expected Twilio signature")
    # Sort params by key (lexicographically), then concat key+value with no separators
    s = url + "".join(k + params[k] for k in sorted(params.keys()))
    digest = hmac.new(auth_token.encode("utf-8"), s.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("utf-8")

def _safe_compare(a: str, b: str) -> bool:
    logger.debug("Comparing signatures safely")
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        # Fallback if types are weird
        return str(a) == str(b)

def is_valid_twilio_request(event) -> bool:
    logger.debug("Validating Twilio request signature")
    headers = event.get("headers") or {}
    given = headers.get("X-Twilio-Signature") or headers.get("x-twilio-signature")
    if not given:
        return False
    url = _build_canonical_url(event)
    body = event.get("body") or ""
    # Our Messaging Service webhooks are POST form-encoded
    params = _parse_form_urlencoded(body)
    auth_token = get_secret(os.environ["TWILIO_TOKEN_ARN"])
    expected = _compute_twilio_signature(url, params, auth_token)
    return _safe_compare(given, expected)

# ---------- Core helpers ----------
def lookup_client_by_to(to_e164: str) -> dict | None:
    logger.debug("Looking up client by To number: %s", to_e164)
    # phone_routes[To] -> client_id, then clients[client_id]
    r = ddb().get_item(TableName=tbl_routes(), Key={"phone_e164": {"S": to_e164}})
    if "Item" not in r:
        return None
    client_id = r["Item"]["client_id"]["S"]
    c = ddb().get_item(TableName=tbl_clients(), Key={"client_id": {"S": client_id}}).get("Item", {})
    # Optional attributes
    msid  = c.get("messaging_service_sid", {}).get("S")
    a2p   = c.get("a2p_approved", {}).get("BOOL", False)
    brand = c.get("display_name", {}).get("S", client_id)
    return {"client_id": client_id, "messaging_service_sid": msid, "a2p_approved": a2p, "brand": brand}

def consent_exists(client_id: str, from_e164: str) -> bool:
    logger.debug("Checking consent for client %s and user %s", client_id, from_e164)
    pk = f"CLIENT#{client_id}#USER#{from_e164}"
    resp = ddb().query(
        TableName=tbl_convos(),
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={":pk": {"S": pk}, ":p": {"S": "CONSENT#"}},
        Limit=1,
        ScanIndexForward=False,
    )
    return resp.get("Count", 0) > 0

def put_inbound_message(form: dict, from_e164: str, to_e164: str, client_id: str):
    logger.debug("put_inbout_message: begin ")
    pk = f"CLIENT#{client_id}#USER#{form.get('From','')}"
    ts = now_iso()
    sid = form.get("MessageSid", "")
    # New: time-sortable SK so we can query recent turns quickly
    sk = f"TS#{ts}#IN#{sid or 'NA'}"
    logger.debug("put_inbound_message: adding message to conversations for client %s, from %s, to %s, sid %s",client_id, from_e164, to_e164, sid)
    item = {
        "pk": {"S": pk},
        "sk": {"S": sk},
        "gsi1pk": {"S": f"CLIENT#{client_id}"},
        "gsi1sk": {"S": f"TS#{ts}"},
        "type": {"S": "inbound_msg"},
        "from": {"S": from_e164},
        "to": {"S": to_e164},
        "body": {"S": (form.get("Body") or "")[:1200]},
        "num_media": {"N": form.get("NumMedia","0") or "0"},
        "service_sid": {"S": form.get("MessagingServiceSid","")},
        "sid": {"S": sid},
        "ts": {"S": ts}
    }
    try:
        ddb().put_item(
            TableName=tbl_convos(),
            Item=item,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)"
        )
        return True
    except ddb().exceptions.ConditionalCheckFailedException:
        return False

def put_outbound_message(client_id: str, from_e164: str, to_e164: str, body: str, sid: str):
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
    ddb().put_item(TableName=tbl_convos(), Item=item)

def update_message_status(form: dict):
    logger.debug("Updating message status for MessageSid: %s", form.get("MessageSid"))
    # Update by MessageSid
    sid = form.get("MessageSid")
    if not sid:
        return
    # We don't have pk easily; do a thin GSI design later.
    # For MVP, upsert a status item keyed by SID.
    ts = now_iso()
    item = {
        "pk": {"S": f"MSG#{sid}"},
        "sk": {"S": f"STATUS#{ts}"},
        "type": {"S": "msg_status"},
        "status": {"S": form.get("MessageStatus","")},
        "error_code": {"S": form.get("ErrorCode","")},
        "ts": {"S": ts}
    }
    ddb().put_item(TableName=tbl_convos(), Item=item)

def send_reply_via_twilio(msid: str, to_e164: str, body: str):
    sid = get_secret(os.environ["TWILIO_SID_ARN"])
    tok = get_secret(os.environ["TWILIO_TOKEN_ARN"])
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    r = requests.post(
        url, auth=(sid, tok),
        data={"To": to_e164, "MessagingServiceSid": msid, "Body": body},
        timeout=15
    )
    r.raise_for_status()
    return r.json()

def orchestrate_reply(client_id: str, from_e164: str, to_e164: str, text: str, message_sid: str | None) -> str:
    logger.debug("orchestrate_reply: begin with client: %s, from: %s, to: %s, text: %s, message_sid: %s", 
                 client_id, from_e164, to_e164,text,message_sid)
    
    fn = os.environ.get("ORCHESTRATOR_FN")
    if not fn:
        return ""
    payload = {
        "client_id": client_id,
        "channel": "sms",
        "user_e164": from_e164,
        "text": text,
        "message_sid": message_sid  # let orchestrator avoid echoing current inbound twice
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

# ---------- Handlers ----------
def handle_inbound(event):
    logger.debug("Handling inbound SMS event")
    if not is_valid_twilio_request(event):
        return {"statusCode": 403, "headers": JSON, "body": json.dumps({"ok": False, "error": "invalid signature"})}

    form = parse_form(event.get("body") or "")
    from_e164 = form.get("From")
    to_e164   = form.get("To")
    body_text = (form.get("Body") or "").strip()
    if not from_e164 or not to_e164:
        return {"statusCode": 400, "headers": JSON, "body": json.dumps({"ok": False, "error": "From/To required"})}

    try:
        from_e164 = convert_to_e164(from_e164)
        to_e164   = convert_to_e164(to_e164)    
    except ValueError:
        return {"statusCode": 400, "headers": JSON, "body": json.dumps({"ok": False, "error": "invalid From/To format"})}
   
    # Route to client by To:
    client = lookup_client_by_to(to_e164)
    if not client:
        return {"statusCode": 404, "headers": JSON, "body": json.dumps({"ok": False, "error": "unknown number"})}

    # Persist inbound (idempotent by MessageSid)
    put_inbound_message(form, from_e164, to_e164, client["client_id"])

    # Respect STOP/HELP (belt + suspenders; Twilio Advanced Opt-Out should be enabled on MS)
    if body_text.upper() in {"STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT"}:
        # no reply here; Twilio will handle with its default if Advanced Opt-Out is enabled
        return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True})}

    if body_text.upper() == "HELP":
        # Optional human-readable HELP
        help_msg = f"{client['brand']}: Reply STOP to opt out. Msg&Data rates may apply."
        if client.get("messaging_service_sid") and client.get("a2p_approved", False):
            try:
                send_reply_via_twilio(client["messaging_service_sid"], from_e164, help_msg)
            except Exception:
                pass
        return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True})}

    # Consent + A2P gating for replies to the user
    allowed = client.get("a2p_approved", False) and consent_exists(client["client_id"], from_e164)

    if allowed and client.get("messaging_service_sid"):
        # Ask orchestrator for a channel-aware reply
        logger.info("Generating orchestrated reply for client %s and user %s", client["client_id"], from_e164)
        reply_text = orchestrate_reply(client["client_id"], from_e164, to_e164, body_text, form.get("MessageSid")) or \
                     f"{client['brand']}: Thanks for your message. A specialist will follow up shortly."
        try:
            sent = send_reply_via_twilio(client["messaging_service_sid"], from_e164, reply_text)
            put_outbound_message(client["client_id"], to_e164, from_e164, reply_text, sent.get("sid", ""))
        except Exception:
            # swallow errors; webhook must return 200 to Twilio
            pass

    return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True})}

def handle_status(event):
    logger.debug("Handling status callback event")
    if not is_valid_twilio_request(event):
        return {"statusCode": 403, "headers": JSON, "body": json.dumps({"ok": False, "error": "invalid signature"})}
    form = parse_form(event.get("body") or "")
    update_message_status(form)
    return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True})}

def lambda_handler(event, context):
    logger.debug("Lambda handler invoked with event: %s", json.dumps(event))
    path = (event.get("requestContext", {}).get("resourcePath") or event.get("rawPath") or "").lower()
    method = (event.get("httpMethod") or "").upper()
    if path.endswith("/twilio/sms/inbound") and method == "POST":
        return handle_inbound(event)
    if path.endswith("/twilio/sms/status") and method == "POST":
        return handle_status(event)
    return {"statusCode": 404, "headers": JSON, "body": json.dumps({"ok": False, "error": "not found"})}
