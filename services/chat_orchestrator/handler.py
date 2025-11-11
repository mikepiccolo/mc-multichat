import json
import os
import secrets
import time
import datetime as dt
import urllib.parse
from typing import Dict, Any, Tuple, List

import boto3
import requests

import logging

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

JSON = {"content-type": "application/json"}

def sm(): return boto3.client("secretsmanager")
def ddb(): return boto3.client("dynamodb")

def get_secret(arn: str) -> str:
    return sm().get_secret_value(SecretId=arn)["SecretString"]

def tbl_clients(): return os.environ["DDB_CLIENTS"]
def tbl_convos():  return os.environ["DDB_CONVERSATIONS"]

def now_iso():
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

# ------------ Client config ------------
def _S(item, key, default=""): return item.get(key, {}).get("S", default)
def _B(item, key, default=False): return item.get(key, {}).get("BOOL", default)
def _N(item, key, default=0): 
    v = item.get(key, {}).get("N")
    try: return int(v) if v is not None else int(default)
    except: return int(default)

def get_client(client_id: str) -> dict:
    logger.debug("Fetching client config for %s", client_id)
    r = ddb().get_item(TableName=tbl_clients(), Key={"client_id": {"S": client_id}})
    item = r.get("Item", {}) or {}
    return {
        "client_id": client_id,
        "display_name": _S(item,"display_name", client_id),
        "timezone": _S(item,"timezone", "America/New_York"),
        "business_hours": _S(item,"business_hours", ""),
        "bot_persona": _S(item,"bot_persona", ""),
        "bot_enabled": _B(item,"bot_enabled", True),
        "max_reply_len": _N(item,"max_reply_len", 320),
         # Lead agent (per-tenant toggles)
        "lead_agent_enabled": _B(item, "lead_agent_enabled", False),
        "lead_vertical": _S(item, "lead_vertical", "generic"),
        "lead_required_fields": _S(item, "lead_required_fields", ""),  # optional CSV/JSON string; else defaults used
        "lead_notify_sms_e164": _S(item, "lead_notify_sms_e164", _S(item, "escalation_phone_e164", "")),
        "messaging_service_sid": _S(item, "messaging_service_sid", "")
    }

def _api_base_url():
    logger.debug("Determining API base URL")
    # Prefer explicit API_BASE_URL if you kept it; otherwise compose from parts
    api_base = os.environ.get("API_BASE_URL")
    if api_base:
        return api_base
    rest_id = os.environ.get("API_REST_ID")
    stage   = os.environ.get("API_STAGE_NAME", "v1")
    region  = os.environ.get("AWS_REGION", "us-east-1")
    return f"https://{rest_id}.execute-api.{region}.amazonaws.com/{stage}"

# ------------ Tools ------------
def tool_search_kb(client_id: str, query: str, k: int = 5) -> dict:
    api_base = _api_base_url()
    apikey   = get_secret(os.environ["APIGW_KEY_SECRET_ARN"])
    url = f"{api_base}/kb/search?q={urllib.parse.quote_plus(query)}&client_id={urllib.parse.quote_plus(client_id)}&k={int(k)}"
    logger.debug("Searching KB for client %s with query: %s", client_id, query)
    r = requests.get(url, headers={"x-api-key": apikey}, timeout=10)
    r.raise_for_status()
    data = r.json()
    return {"ok": True, "hits": data.get("hits", [])[:k]}

def tool_get_business_hours(client: dict) -> dict:
    return {"ok": True, "business_hours": client.get("business_hours", "")}

# ------------ History (short-term memory) ------------
def fetch_recent_messages(client_id: str, user_e164: str, limit: int = 10, current_msg_sid: str | None = None):
    logger.debug("fetch_recent_messages: begin")
    """
    Returns messages as [{'role':'user'|'assistant','content': str}, ...] in chronological order,
    using only items with time-sortable SK (TS#...).
    Also returns a flag indicating whether the current inbound SID is already in history.
    """
    pk = f"CLIENT#{client_id}#USER#{user_e164}"
    # Query latest N items that start with TS#
    resp = ddb().query(
        TableName=tbl_convos(),
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={":pk": {"S": pk}, ":p": {"S": "TS#"}},
        Limit=limit,
        ScanIndexForward=False,  # newest first
    )
    items = resp.get("Items", [])
    # chronological (oldest -> newest)
    items.reverse()

    msgs = []
    saw_current = False
    for it in items:
        typ = _S(it, "type", "")
        sid = _S(it, "sid", "")
        if current_msg_sid and sid and sid == current_msg_sid and typ == "inbound_msg":
            saw_current = True
        if typ == "inbound_msg":
            msgs.append({"role": "user", "content": _S(it, "body", "")})
        elif typ == "outbound_msg":
            msgs.append({"role": "assistant", "content": _S(it, "body", "")})
        # ignore other types for chat context
    return msgs, saw_current

# ---------------- Lead Agent (preview) ----------------
def _lead_defaults(vertical: str) -> Tuple[List[str], List[str]]:
    logger.debug("_lead_defaults: vertical=%s", vertical)
    """returns (core_fields, vertical_fields) lists"""
    core = ["name", "best_contact", "request_summary", "urgency"]
    if vertical == "realtor":
        extra = ["zip_or_city", "buy_or_sell", "timeline", "price_range", "property_address"]
    elif vertical == "home_services":
        extra = ["zip_or_city", "service_type", "address", "availability_window", "photos_link"]
    else:
        extra = []

    logger.debug("_lead_defaults: core=%s, extra=%s", core, extra)
    return core, extra

def _parse_required_fields(cfg: str, vertical: str) -> List[str]:
    logger.debug("_parse_required_fields: cfg=%s, vertical=%s", cfg, vertical)
    if not cfg:  # use defaults
        core, extra = _lead_defaults(vertical)
        return core + extra
    # allow CSV or JSON list
    s = cfg.strip()
    if s.startswith("["):
        try: return [x.strip() for x in json.loads(s) if isinstance(x, str)]
        except: pass
    return [x.strip() for x in s.split(",") if x.strip()]

def _lead_state_key(client_id: str, user_e164: str) -> Dict[str, Dict[str, str]]:
    pk = f"CLIENT#{client_id}#USER#{user_e164}"
    sk = "LEADSTATE#ACTIVE"
    return {"pk":{"S":pk}, "sk":{"S":sk}}

def lead_state_get(client_id: str, user_e164: str) -> dict:
    logger.debug("lead_state_get: Fetching lead state for client %s and user %s", client_id, user_e164)
    r = ddb().get_item(TableName=tbl_convos(), Key=_lead_state_key(client_id, user_e164))
    it = r.get("Item")
    if not it: return {"fields":{}, "questions":0, "started": now_iso(), "updated": now_iso()}
    fields = {}
    try:
        fields = json.loads(_S(it, "fields_json", "{}"))
    except: fields = {}
    return {
        "fields": fields,
        "questions": _N(it, "questions", 0),
        "started": _S(it, "started", now_iso()),
        "updated": _S(it, "updated", now_iso())
    }

def lead_state_put(client_id: str, user_e164: str, state: dict):
    logger.debug("lead_state_put: Updating lead state for client %s and user %s", client_id, user_e164)
    item = {
        "pk": _lead_state_key(client_id, user_e164)["pk"],
        "sk": _lead_state_key(client_id, user_e164)["sk"],
        "type": {"S":"lead_state"},
        "fields_json": {"S": json.dumps(state.get("fields",{}))},
        "questions": {"N": str(int(state.get("questions",0)))},
        "started": {"S": state.get("started", now_iso())},
        "updated": {"S": now_iso()}
    }
    ddb().put_item(TableName=tbl_convos(), Item=item)

def lead_state_clear(client_id: str, user_e164: str):
    logger.debug("lead_state_clear: Clearing lead state for client %s and user %s", client_id, user_e164)
    try:
        ddb().delete_item(TableName=tbl_convos(), Key=_lead_state_key(client_id, user_e164))
    except Exception as e:
        logger.error("lead_state_clear: Error clearing lead state for client %s and user %s: %s", client_id, user_e164, e)
        pass

def _short_id() -> str:
    return "lead-" + secrets.token_hex(6)

def lead_recent_exists(client_id: str, user_e164: str, minutes: int) -> bool:
    logger.debug("lead_recent_exists: Checking for recent leads for client %s and user %s within last %d minutes", client_id, user_e164, minutes)
    """Simple dedupe window: any lead in last N minutes."""
    pk = f"CLIENT#{client_id}#USER#{user_e164}"
    resp = ddb().query(
        TableName=tbl_convos(),
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        FilterExpression="#lead = :t",
        ExpressionAttributeNames={"#lead": "type"},
        ExpressionAttributeValues={":pk":{"S":pk}, ":p":{"S":"TS#"}, ":t":{"S":"lead"}},
        Limit=20, ScanIndexForward=False
    )
    items = resp.get("Items", [])
    cutoff = dt.datetime.utcnow() - dt.timedelta(minutes=minutes)
    for it in items:
        if _S(it,"type","") == "lead":
            ts = _S(it,"ts", now_iso())
            try:
                t = dt.datetime.fromisoformat(ts.replace("Z",""))
                if t >= cutoff: 
                    logger.warning("lead_recent_exists: Found recent lead at %s", ts)
                    return True
            except: pass
    
    logger.debug("lead_recent_exists: No recent leads found")
    return False

def lead_create_item(client_id: str, user_e164: str, fields: dict, summary: str) -> dict:
    logger.debug("lead_create_item: Creating lead item for client %s and user %s", client_id, user_e164)
    lead_id = _short_id()
    ts = now_iso()
    pk = f"CLIENT#{client_id}#USER#{user_e164}"
    sk = f"TS#{ts}#LEAD#{lead_id}"
    item = {
        "pk":{"S":pk},
        "sk":{"S":sk},
        "gsi1pk":{"S":f"CLIENT#{client_id}"},
        "gsi1sk":{"S":f"TS#{ts}"},
        "type":{"S":"lead"},
        "lead_id":{"S":lead_id},
        "status":{"S":"open"},
        "summary":{"S": summary[:1000]},
        "fields_json":{"S": json.dumps(fields)[:3500]},
        "ts":{"S":ts}
    }
    ddb().put_item(TableName=tbl_convos(), Item=item)
    # clear active session
    lead_state_clear(client_id, user_e164)
    return {"lead_id": lead_id, "ts": ts, "summary": summary, "fields": fields, "user_e164": user_e164}


def tool_create_lead(client_id: str, user_e164: str, summary: str, data: dict | None = None) -> dict:
    return lead_create_item(client_id, user_e164, data or {}, summary) | {"ok": True}

def _fields_from_args(args: dict) -> dict:
    logger.debug("_fields_from_args: Extracting fields from args")
    # normalize common fields
    f = {}
    for k in ["name","best_contact","zip_or_city","request_summary","urgency",
              "buy_or_sell","timeline","price_range","property_address",
              "service_type","address","availability_window","photos_link"]:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            f[k] = v.strip()
    
    logger.debug("_fields_from_args: extracted fields: %s", f)
    return f

def lead_agent_update(client: dict, user_e164: str, args: dict) -> dict:
    logger.debug("lead_agent_update: Updating lead agent state for client %s and user %s with args %s", client["client_id"], user_e164, args)
    """Merge provided fields, decide next question or finalize."""
    max_q = int(os.environ.get("LEAD_MAX_QUESTIONS","3"))
    dedupe_min = int(os.environ.get("LEAD_DEDUPE_MINUTES","120"))
    if lead_recent_exists(client["client_id"], user_e164, dedupe_min):
        return {"finalized": True, "lead_id": None, "summary": "duplicate within window", "message": "Thanks! We already have your details and will follow up shortly."}

    required = _parse_required_fields(client.get("lead_required_fields",""), client.get("lead_vertical","generic"))
    logger.debug("lead_agent_update: Required fields: %s", required)

    state = lead_state_get(client["client_id"], user_e164)
    logger.debug("lead_agent_update: Current lead state: %s", state)

    merged = state["fields"] | _fields_from_args(args)
    logger.debug("lead_agent_update: Merged fields: %s", merged)

    # Determine missing fields in order
    missing = [f for f in required if f not in merged or not str(merged.get(f,"")).strip()]

    logger.debug("lead_agent_update: Missing required fields: %s", missing)

    # If missing and under question budget: propose next question
    if missing and state["questions"] < max_q:
        next_f = missing[0]
        logger.debug("lead_agent_update: Proposing next question: %s", next_f)
        # simple question templates; keep SMS-friendly
        qmap = {
            "name": "Got it—what’s your name?",
            "best_contact": "What’s the best contact (this number or email)?",
            "request_summary": "Briefly describe what you need:",
            "urgency": "How urgent is this (low/medium/high)?",
            "zip_or_city": "What city or ZIP is this for?",
            "buy_or_sell": "Are you looking to buy or sell?",
            "timeline": "What’s your timeline?",
            "price_range": "Any price range in mind?",
            "property_address": "What’s the property address (optional)?",
            "service_type": "What type of service do you need?",
            "address": "What’s the service address or ZIP?",
            "availability_window": "When are you available?",
            "photos_link": "If you have photos, share a link (optional)."
        }
        state["fields"] = merged
        state["questions"] = int(state["questions"]) + 1
        lead_state_put(client["client_id"], user_e164, state)
        return {"finalized": False, "next_question": qmap.get(next_f, f"Please provide: {next_f}")}

    # Finalize
    summary_parts = []
    order = ["name","buy_or_sell","service_type","request_summary","zip_or_city","address","timeline","price_range","urgency"]
    for k in order:
        if k in merged:
            summary_parts.append(f"{k.replace('_',' ')}: {merged[k]}")
    if not summary_parts and merged:
        summary_parts = [f"{k}: {v}" for k,v in merged.items()][:6]
    summary = "; ".join(summary_parts) if summary_parts else "lead details provided"

    logger.debug("lead_agent_update: Finalizing lead with summary: %s", summary)

    created = lead_create_item(client["client_id"], user_e164, merged, summary)


    # Notify client (SMS) if enabled
    try:
        notify_lead_multi(client, created)
    except Exception:
        pass

    return {"finalized": True, "lead_id": created["lead_id"], "summary": summary}

# ---------------- Notifications ----------------
def _notify_dedupe_key(client_id: str, user_e164: str, lead_id: str, dest: str) -> Dict[str, Dict[str, str]]:
    logger.debug("_notify_dedupe_key: Creating dedupe key for client %s, user %s, lead %s, dest %s", client_id, user_e164, lead_id, dest)
    pk = f"CLIENT#{client_id}#USER#{user_e164}"
    sk = f"NOTIFY#LEAD#{lead_id}#{dest}"
    return {"pk":{"S":pk}, "sk":{"S":sk}}

def _notify_once(client_id: str, user_e164: str, lead_id: str, dest: str) -> bool:
    logger.debug("_notify_once: Attempting to create notify marker for client %s, user %s, lead %s, dest %s", client_id, user_e164, lead_id, dest)
    try:
        ddb().put_item(
            TableName=tbl_convos(),
            Item={
                "pk": _notify_dedupe_key(client_id, user_e164, lead_id, dest)["pk"],
                "sk": _notify_dedupe_key(client_id, user_e164, lead_id, dest)["sk"],
                "type": {"S":"lead_notify_marker"},
                "ts": {"S": now_iso()}
            },
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)"
        )

        logger.debug("_notify_once: Notification marker created successfully for client %s, user %s, lead %s, dest %s", client_id, user_e164, lead_id, dest)
        return True
    except ddb().exceptions.ConditionalCheckFailedException:
        logger.debug("_notify_once: Notification already sent for client %s, user %s, lead %s, dest %s", client_id, user_e164, lead_id, dest)
        return False

def _twilio_send_sms(msid: str, to_e164: str, body: str) -> dict:
    logger.debug("_twilio_send_sms: Sending SMS to %s via Messaging Service %s", to_e164, msid)
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

def notify_lead_sms(client: dict, lead: dict):
    logger.debug("notify_lead_sms: Notifying client %s about new lead %s via SMS", client["client_id"], lead["lead_id"])
    """Send a concise SMS to the client about a new lead."""
    if os.environ.get("LEAD_NOTIFY_CLIENT_SMS","false").lower() != "true":
        logger.debug("notify_lead_sms: SMS notifications are disabled")
        return
    
    to_e164 = client.get("lead_notify_sms_e164") or ""
    msid    = client.get("messaging_service_sid") or ""
    user_e164 = lead.get("user_e164","")
    if not (to_e164 and msid and user_e164):
        logger.warning("notify_lead_sms: Missing to_e164, msid, or user_e164; cannot send SMS")
        return
    if not _notify_once(client["client_id"], user_e164, lead["lead_id"], "sms"):
        return  # already notified

    brand = client.get("display_name") or "Your lead"
    summary = (lead.get("summary") or "").strip()
    if len(summary) > 220:
        summary = summary[:217].rstrip() + "…"

    msg = f"{brand}: New lead {lead['lead_id']} from {user_e164}. {summary}"
    if len(msg) > 300:
        msg = msg[:297] + "…"

    try:
        _twilio_send_sms(msid, to_e164, msg)
    except Exception as e:
        # keep marker written to avoid loops; logs available in CW
        logger.error("notify_lead_sms: Error sending SMS notification: %s", e) 
        pass

def notify_lead_multi(client: dict, created: dict):
    logger.debug("notify_lead_multi: Notifying client %s about new lead %s via multiple channels", client["client_id"], created["lead_id"])
    """Future: fan out to multiple destinations. For now, only SMS."""
    # Later, read client['lead_notify_destinations'] like ["sms","slack","crm:hubspot"].
    notify_lead_sms(client, created)

# ------------ OpenAI Chat (function calling) ------------
def openai_chat(messages, functions):
    logger.debug("openai_chat: calling OpenAI chat API with %d messages and %d functions", len(messages), len(functions))
    model = os.environ.get("MODEL_NAME", "gpt-4o-mini")
    key   = get_secret(os.environ["OPENAI_SECRET_ARN"])
    payload = {
        "model": model,
        "messages": messages,
        "functions": functions,
        "function_call": "auto",
        "temperature": 0.3,
    }

    logger.debug("openai_chat: OpenAI chat payload: %s", json.dumps(payload))

    r = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        data=json.dumps(payload), timeout=30
    )
    r.raise_for_status()
    return r.json()

def clamp_for_channel(text: str, channel: str, max_len: int) -> str:
    logger.debug("Clamping reply for channel %s to max length %d", channel, max_len)
    if channel == "sms":
        t = text.strip()
        if len(t) > max_len:
            t = t[:max_len - 1].rstrip() + "…"
        return t
    return text.strip()

def add_opt_out_notice(reply: str, channel: str, max_len: int) -> str:
    if channel == "sms" and not "Reply STOP to opt out".casefold() in reply.casefold():
        notice = "\n\nReply STOP to opt out"
        if len(reply) + len(notice) <= max_len:
            return reply + notice
    return reply

# ------------ Orchestrator ------------
def orchestrate(client_id: str, channel: str, user_e164: str, text: str, message_sid: str | None, event: str | None = None, transcript: str | None = None) -> dict:
    logger.debug("orchestrate: Orchestrating chat for client %s, channel %s, user %s", client_id, channel, user_e164)
    client = get_client(client_id)
    logger.debug("orchestrate: Client config: %s", json.dumps(client))

    persona = client["bot_persona"] or f"You are {client['display_name']}'s helpful assistant. Be brief and friendly."
    logger.debug("orchestrate: Using bot persona: %s", persona)

    max_reply_len = client["max_reply_len"] if channel == "sms" else max(600, client["max_reply_len"])
    logger.debug("orchestrate: Max reply length set to %d for channel %s", max_reply_len, channel)

    history_max_turns = int(os.environ.get("MAX_HISTORY_TURNS", "10"))
    logger.debug("orchestrate: Conversation history max turns is %s", history_max_turns)

    # If this is a missed-call kickoff, bias the system prompt accordingly
    missed_prelude = ""
    if (event or "").lower() == "missed_call":
        logger.debug("orchestrate: Adding missed call prelude to system prompt")
        missed_prelude = (
            "The user just called and we missed them. "
            "If a transcript is provided, use it to personalize your first text. "
            "Start friendly, acknowledge the call, and offer one clear next step. "
            "Keep very concise for SMS. Do not include links unless asked.\n"
        )
        if transcript:
            logger.debug("orchestrate: Adding voicemail transcript to missed call prelude")
            missed_prelude += f"Voicemail transcript (may be partial/noisy): {transcript}\n"


    lead_rules = ""
    if client.get("lead_agent_enabled", False):
        logger.debug("orchestrate: Adding lead agent rules to system prompt")
#        core, extra = _lead_defaults(client.get("lead_vertical","generic"))
        required = _parse_required_fields(client.get("lead_required_fields",""), client.get("lead_vertical","generic"))
        lead_rules = (
            "- If the user asks for a quote/estimate/appointment/sales contact/human or you are unsure after one turn, "
            "call the lead_agent_update function with any fields you can extract from chat history. "
            f"Required fields to capture (in order): {', '.join(required)}. "
            f"Ask at most one concise question at a time (<= 300 chars) and at most {os.environ.get("LEAD_MAX_QUESTIONS", "3")} questions total.\n"
        )

    system = (
        f"{persona}\n"
        f"{missed_prelude}"
        f"- When unsure, ask a brief clarifying question.\n"
        f"- For SMS, keep replies as informative as possible but concise; avoid long lists.\n"
        f"- If user asks a general question, use the knowledge base tool.\n"
        f"- If user asks about hours, use the business hours tool.\n"
        f"{lead_rules}"
        f"- If you cite info, reference the doc title when available.\n"
        f"- Reply language should match user's message language when possible.\n"
    )

    past_msgs, saw_current = fetch_recent_messages(client_id, user_e164, limit=history_max_turns, current_msg_sid=message_sid)
    msgs = [{"role": "system", "content": system}]
    msgs.extend(past_msgs)

    # For missed_call kickoff, the user didn't send a text yet; seed a virtual user cue
    if (event or "").lower() == "missed_call" and not text:
        logger.debug("orchestrate: Seeding missed call user message into chat history")
        seed = "We missed your call."
        msgs.append({"role": "user", "content": seed})
    elif not saw_current and text:
        logger.debug("orchestrate: Adding current user message to chat history")
        # Add the current user message if not already in history
        msgs.append({"role": "user", "content": text})


    functions = [
        {
            "name": "search_kb",
            "description": "Search the client's knowledge base for relevant answers.",
            "parameters": {"type": "object","properties":{
                "query":{"type":"string"},
                "k":{"type":"integer","minimum":1,"maximum":8,"default":5}
            },"required":["query"]}
        },
        {
            "name": "get_business_hours",
            "description": "Get the client's business hours string.",
            "parameters": {"type":"object","properties":{}}
        }
     ]

    if client.get("lead_agent_enabled", False):
        logger.debug("orchestrate: Adding lead_agent_update function to available tools")
        functions.append({
            "name":"lead_agent_update",
            "description":"Start/update lead capture with any fields you can extract. Keep values short.",
            "parameters":{"type":"object","properties":{
                "name":{"type":"string"},
                "best_contact":{"type":"string"},
                "request_summary":{"type":"string"},
                "urgency":{"type":"string","enum":["low","medium","high"]},
                "zip_or_city":{"type":"string"},
                "buy_or_sell":{"type":"string","enum":["buy","sell","both"]},
                "timeline":{"type":"string"},
                "price_range":{"type":"string"},
                "property_address":{"type":"string"},
                "service_type":{"type":"string"},
                "address":{"type":"string"},
                "availability_window":{"type":"string"},
                "photos_link":{"type":"string"}
            }}
        })


    logger.debug("orchestrate: Initial messages: %s", json.dumps(msgs))

    loops = int(os.environ.get("MAX_TOOL_LOOPS","2"))
    tool_results = {}

    for _ in range(loops):
        resp = openai_chat(msgs, functions)
        choice = resp["choices"][0]
        msg = choice["message"]

        logger.info("orchestrate: OpenAI response message: %s", msg)

        if msg.get("function_call"):
            logger.debug("orchestrate: Model requested tool call: %s", msg["function_call"])
            fn = msg["function_call"]["name"]
            args = json.loads(msg["function_call"].get("arguments") or "{}")

            if fn == "search_kb":
                q = args.get("query") or text
                k = int(args.get("k", 5))
                result = tool_search_kb(client_id, q, k)
                logger.debug("orchestrate: search_kb result: %s", result)
            elif fn == "get_business_hours":
                result = tool_get_business_hours(client)
                logger.debug("orchestrate: get_business_hours result: %s", result)
            elif fn == "lead_agent_update" and client.get("lead_agent_enabled", False):
                logger.debug("orchestrate: Calling lead_agent_update with args: %s", args)
                result = lead_agent_update(client, user_e164, args)
                logger.debug("orchestrate: lead_agent_update result: %s", result)
            else:
                logger.warning("orchestrate: Unknown tool requested: %s", fn)   
                result = {"ok": False, "error": f"unknown tool {fn}"}

            tool_results[fn] = result
            msgs.append({"role":"assistant","content":None,"function_call":msg["function_call"]})
            msgs.append({"role":"function","name":fn,"content":json.dumps(result)})
            continue

        # Model produced a final answer
        final = msg.get("content","").strip()
        logger.debug("orchestrate: Model produced final content: %s", final)
        if not final:
            break

        reply = add_opt_out_notice(final, channel, max_reply_len)
        reply = clamp_for_channel(reply, channel, max_reply_len)
        #reply = final.strip()
        logger.info("orchestrate: Final reply generated for client %s and user %s: %s", client_id, user_e164, reply)
        return {"ok": True, "reply": reply, "tools": tool_results}

    # If we exit loop without final content, backstop with a generic reply
    backstop = "Thanks for reaching out—can you share a bit more about what you need?"
    reply = add_opt_out_notice(backstop,channel,max_reply_len)
    logger.warning("orchestrate: No final reply generated; using backstop reply. Client: %s, User: %s", client_id, user_e164 )
    return {"ok": True, "reply": clamp_for_channel(reply, channel, max_reply_len), "tools": tool_results}

# ------------ Lambda entry ------------
def lambda_handler(event, context):
    logger.debug("lambda_handler: Received event: %s", json.dumps(event))
    try:
        body = event if isinstance(event, dict) and event.get("client_id") else json.loads(event.get("body") or "{}")
    except Exception:
        body = {}

    client_id = body.get("client_id")
    channel   = body.get("channel", "sms")
    user_e164 = body.get("user_e164") or body.get("from")
    text      = (body.get("text") or "").strip()
    message_sid = body.get("message_sid")
    event_name  = body.get("event")
    transcript  = body.get("transcript")
    
    if not client_id or not user_e164:
        logger.error("lambda_handler: Missing required parameters: client_id=%s, user_e164=%s", client_id, user_e164)
        return {"statusCode": 400, "headers": JSON, "body": json.dumps({"ok": False, "error": "client_id, user_e164, text required"})}

    result = orchestrate(client_id, channel, user_e164, text, message_sid, event=event_name, transcript=transcript)
    return {"statusCode": 200, "headers": JSON, "body": json.dumps(result)}
