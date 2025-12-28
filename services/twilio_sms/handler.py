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
import re


JSON = {"content-type": "application/json"}
FORM = "application/x-www-form-urlencoded"

import logging

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

def _optin_keyword() -> str:
    logger.debug("_optin_keyword: Retrieving opt-in keyword")
    return (os.environ.get("OPTIN_KEYWORD") or "hello").strip().lower()

def is_optin_hello(body: str) -> bool:
    logger.debug("is_optin_hello: Checking if body matches opt-in keyword")
    kw = re.escape(_optin_keyword())
    # match e.g. "hello", " Hello! ", "hello." (no extra text)
    return bool(re.match(rf"^\s*{kw}\s*[!\.\?]*\s*$", (body or "").lower()))

def record_consent_sms_keyword(client_id: str, from_e164: str, to_e164: str, keyword: str = "hello") -> bool:
    logger.debug("record_consent_sms_keyword: Recording consent for client %s and user %s", client_id, from_e164)
    pk = f"CLIENT#{client_id}#USER#{from_e164}"
    ts = now_iso()
    sk = f"CONSENT#TS#{ts}#sms-keyword"
    item = {
        "pk": {"S": pk},
        "sk": {"S": sk},
        "gsi1pk": {"S": f"CLIENT#{client_id}"},
        "gsi1sk": {"S": f"TS#{ts}"},
        "type": {"S": "consent"},
        "source": {"S": "sms-keyword"},
        "keyword": {"S": keyword},
        "to": {"S": to_e164},
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
        logger.info("record_consent_sms_keyword: Consent already exists for client %s and user %s", client_id, from_e164)
        return False
    
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
    escalation_phone_e164 = c.get("escalation_phone_e164", {}).get("S")
    owner_numbers = c.get("owner_numbers", {}).get("S", "")
    max_reply_len = c.get("max_reply_len", {}).get("N", 600)
    welcome_message = c.get("welcome_message", {}).get("S", "")

    return {"client_id": client_id, 
            "messaging_service_sid": msid, 
            "a2p_approved": a2p, 
            "escalation_phone_e164": escalation_phone_e164,
            "owner_numbers": owner_numbers,
            "brand": brand,
            "welcome_message": welcome_message,
            "max_reply_len": int(max_reply_len) if max_reply_len else 600}

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

def add_opt_out_notice(reply: str, max_len: int) -> str:
    if not "Reply STOP to opt out".casefold() in reply.casefold():
        notice = "\n\nReply STOP to opt out"
        if len(reply) + len(notice) <= max_len:
            return reply + notice
    return reply

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

# --- Owner SMS / admin functions orchestration ---
def is_owner_sms(client: dict, from_e164: str) -> bool:
    logger.debug("is_owner_sms: Checking if SMS is from owner number: %s", from_e164)
    if not client: 
        return False
    owner = (client.get("escalation_phone_e164") or "").strip()
    if owner and owner == from_e164:
        logger.debug("is_owner_sms: Match found with escalation_phone_e164")
        return True
    # Optional: support comma-sep list in client["owner_numbers"]
    logger.debug("is_owner_sms: Checking owner_numbers list")
    owners = (client.get("owner_numbers") or "").split(",")
    is_owners = from_e164 in [o.strip() for o in owners if o.strip()]
    logger.debug("is_owner_sms: owner_numbers match: %s", is_owners)
    return  is_owners

def invoke_orchestrator_owner(client_id: str, from_e164: str, body_text: str) -> dict:
    logger.debug("invoke_orchestrator_owner: Invoking orchestrator in owner mode for client %s and user %s", client_id, from_e164)
    payload = {
        "client_id": client_id,
        "channel": "sms_owner",     # signals owner mode
        "role": "owner",
        "user_e164": from_e164,
        "text": body_text or "",
        "message_sid": None
    }
    # if you already have direct Lambda invoke:
    import boto3, json, os
    lf = boto3.client("lambda")
    fn = os.environ["ORCHESTRATOR_FN"]
    resp = lf.invoke(FunctionName=fn, InvocationType="RequestResponse",
                     Payload=json.dumps(payload).encode("utf-8"))
    out = json.loads(resp["Payload"].read().decode("utf-8") or "{}")
    try:
        return json.loads(out.get("body") or "{}")
    except Exception as e:
        logger.error("Failed to invoke orchestrator in owner mode: %s", e)
        return out or {}

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

    # --- Handle owner sms, skip save inbound message ---
    if is_owner_sms(client, from_e164):
        logger.info("Inbound SMS from owner %s for client %s", from_e164, client["client_id"])
        # Owner/admin path: bypass consent/STOP logic; respond via Twilio back to owner.
        result = invoke_orchestrator_owner(client["client_id"], from_e164, body_text)
        reply = (result.get("reply") or "OK").strip()
        logger.debug("Orchestrator returned reply for owner %s: %s", from_e164, reply)
        # send SMS back to owner using Messaging Service
        if client.get("messaging_service_sid"):
            try:
                sent = send_reply_via_twilio(client["messaging_service_sid"], from_e164, reply)
                logger.debug("Sent owner reply SMS to %s via Twilio, SID: %s", from_e164, sent.get("sid"))
                put_outbound_message(client["client_id"], to_e164, from_e164, reply, sent.get("sid"))
            except Exception as e:
                logger.error("Failed to send owner reply SMS to %s: %s", from_e164, e)
                pass

        return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True, "owner": True})}

    # --- SMS opt-in via keyword ("hello") ---
    if is_optin_hello(body_text):
        logger.debug("Inbound opt-in keyword detected from %s for client %s", from_e164, client["client_id"])
        # If already consented, treat like normal inbound (fall through)
        already = consent_exists(client["client_id"], from_e164) if client else False
        if not already and client:
            logger.debug("Recording new consent for %s for client %s", from_e164, client["client_id"])
            record_consent_sms_keyword(client["client_id"], from_e164, to_e164, _optin_keyword())

            # Acknowledge opt-in only if we can legally/textually reply
            if client.get("a2p_approved", False) and client.get("messaging_service_sid"):
                # customize ack message per client usimng welcome message
                ack = client.get("welcome_message") or f"{client['brand']}: Thanks for opting in to texts. How can we help you today?"
                try:
                    final = add_opt_out_notice(ack, client.get("max_reply_len", 600))
                    sent = send_reply_via_twilio(client["messaging_service_sid"], from_e164, final)
                    put_outbound_message(client["client_id"], to_e164, from_e164, ack, sent.get("sid"))
                    return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True, "ack": True})}
                except Exception:
                    logger.error("Failed to send opt-in acknowledgment to %s for client %s", from_e164, client["client_id"])
                    # fall through; at least we stored the consent
                    pass
            # If not approved or no MS SID, just end after storing consent
            return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True, "ack": False})}
        else:
            logger.debug("Consent already exists for %s for client %s", from_e164, client["client_id"])
            # fall through to normal inbound processing
   
    # Respect STOP/HELP (belt + suspenders; Twilio Advanced Opt-Out should be enabled on MS)
    if body_text.upper() in {"STOP", "STOPALL", "UNSUBSCRIBE", "END", "QUIT"}:
        # no reply here; Twilio will handle with its default if Advanced Opt-Out is enabled
        return {"statusCode": 200, "headers": JSON, "body": json.dumps({"ok": True})}

    if body_text.upper() == "HELP":
        # Optional human-readable HELP
        help_msg = f"{client['brand']}: Reply STOP to opt out. Reply START to opt back in. Msg&Data rates may apply."
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
            final = add_opt_out_notice(reply_text, client.get("max_reply_len", 600))
            sent = send_reply_via_twilio(client["messaging_service_sid"], from_e164, final)
            put_outbound_message(client["client_id"], to_e164, from_e164, reply_text, sent.get("sid", ""))
        except Exception:
            # swallow errors; webhook must return 200 to Twilio
            pass
    else:
        logger.warning("handle_inbound:Failed consent check. Not sending reply to %s with messaging_service_id: %s.  A2P not approved, or consent does not exist for sender",
                    from_e164,
                    client.get("messaging_service_sid") or "MISSING")

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
