import json
import os
import secrets
import time
import datetime as dt
import urllib.parse
from typing import Dict, Any, Tuple, List
from zoneinfo import ZoneInfo

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
        "messaging_service_sid": _S(item, "messaging_service_sid", ""),
        # scheduling
        "scheduling_enabled": _B(item, "scheduling_enabled", False),
        "sched_days_ahead": _S(item, "sched_days_ahead", 7),
        "sched_slot_minutes": _S(item, "sched_slot_minutes", 30),
        "sched_buffer_minutes": _S(item, "sched_buffer_minutes", 5),
        "sched_hold_minutes": _S(item, "sched_hold_minutes", 15),
        "scheduling_link": _S(item, "scheduling_link", ""),
        "sched_source": _S(item, "sched_source", "owner").lower()
    }

def _tz(name: str) -> ZoneInfo:
    try: return ZoneInfo(name)
    except Exception: return ZoneInfo("America/New_York")

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

# ---------------- Lead Notifications ----------------
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

# ------------- Availability storage (owner-driven) -------------
def _fmt_window_label_local(start_iso: str, end_iso: str, tz: ZoneInfo) -> str:
    logger.debug("_fmt_window_label_local: Formatting window label local for start %s and end %s", start_iso, end_iso)
    s_utc = dt.datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
    e_utc = dt.datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    s = s_utc.astimezone(tz)
    e = e_utc.astimezone(tz)
    abbr = s.tzname()
    day = s.strftime("%a %b %-d")
    s_str = s.strftime("%-I:%M")
    e_str = e.strftime("%-I:%M %p")
    return f"{day}, {s_str}–{e_str} {abbr}"

def _fmt_window_label_display(start_iso: str, end_iso: str, tz: ZoneInfo, now_local: dt.datetime) -> str:
    logger.debug("_fmt_window_label_display: Formatting window label display for start %s and end %s", start_iso, end_iso)
    s_utc = dt.datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
    e_utc = dt.datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    s = s_utc.astimezone(tz)
    e = e_utc.astimezone(tz)
    abbr = s.tzname()

    delta = (s.date() - now_local.date()).days
    if   delta == 0: prefix = "Today"
    elif delta == 1: prefix = "Tomorrow"
    else:            prefix = s.strftime("%a %b %-d")

    s_str = s.strftime("%-I:%M")
    e_str = e.strftime("%-I:%M %p")
    # For Today/Tomorrow, also include the calendar date to avoid ambiguity:
    if delta in (0, 1):
        date_str = s.strftime("%b %-d")
        return f"{prefix}, {date_str}, {s_str}–{e_str} {abbr}"
    return f"{prefix}, {s_str}–{e_str} {abbr}"

def sched_pk_client(client_id: str) -> Dict[str, Dict[str,str]]:
    return {"pk": {"S": f"SCHEDULE#CLIENT#{client_id}"}}

def avail_item_key(client_id: str, start_iso: str, end_iso: str) -> Dict[str, Dict[str,str]]:
    k = sched_pk_client(client_id)
    k["sk"] = {"S": f"AVAIL#{start_iso}#{end_iso}"}
    return k

def slot_marker_key(client_id: str, slot_start_iso: str) -> Dict[str, Dict[str,str]]:
    k = sched_pk_client(client_id)
    k["sk"] = {"S": f"SLOT#{slot_start_iso}"}
    return k

def availability_list(client: dict, days_ahead: int = 30) -> List[Tuple[str,str]]:
    logger.debug("availability_list: Listing availability for client %s for next %d days", client["client_id"], days_ahead)
    """Return future availability windows as list of (start_iso,end_iso) UTC."""
    """Improve this later to query by date range based on days_ahead."""
    pk = sched_pk_client(client["client_id"])
    """TODO Improve later by querying only relevant range.  Get AVAIL# from now to horizon."""
    resp = ddb().query(
        TableName=tbl_convos(),
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={":pk": pk["pk"], ":p": {"S": "AVAIL#"}},
        Limit=200, ScanIndexForward=True
    )
    now = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
    horizon = now + dt.timedelta(days=days_ahead)
    out=[]
    for it in resp.get("Items", []):
        sk = _S(it,"sk","")
        try:
            _, s, e = sk.split("#", 2)
            sdt = dt.datetime.fromisoformat(s.replace("Z","+00:00"))
            edt = dt.datetime.fromisoformat(e.replace("Z","+00:00"))
            if edt <= now: 
                continue
            if sdt > horizon: 
                continue
            out.append((s, e))
        except Exception:
            continue
    # merge overlaps on read
    out.sort()
    merged=[]
    for s,e in out:
        if not merged: 
            merged.append([s,e]); continue
        ps,pe = merged[-1]
        if s <= pe:  # overlap/adjacent
            merged[-1][1] = max(pe, e)
        else:
            merged.append([s,e])
    return [(a,b) for a,b in merged]

def availability_list_pretty(client: dict, days_ahead: int = 30) -> dict:
    tz = _tz(client.get("timezone") or "America/New_York")
    now_local = dt.datetime.now(dt.timezone.utc).astimezone(tz)
    windows = availability_list(client, days_ahead=days_ahead)
    out = []
    for s, e in windows:
        out.append({
            "start_iso": s,
            "end_iso": e,
            "label_local": _fmt_window_label_local(s, e, tz),
            "label_display": _fmt_window_label_display(s, e, tz, now_local)
        })
    # include timezone metadata for the model (if it wants to paraphrase)
    abbr = dt.datetime.now(dt.timezone.utc).astimezone(tz).tzname()
    return {"ok": True, "windows": out, "timezone": str(tz), "tz_abbr": abbr}

def availability_upsert(client: dict, blocks: List[Dict[str,str]], owner_text: str | None = None) -> dict:
    logger.debug("availability_upsert: Upserting availability for client %s", client["client_id"])
    """Write availability blocks as-is (merge happens on read)."""

    tz = _tz(client.get("timezone") or "America/New_York")
    now_utc = dt.datetime.now(dt.timezone.utc)
    now_local = now_utc.astimezone(tz)

    def _fix_if_relative_past(siso: str, eiso: str) -> Tuple[str, str]:
        """If the block is far in the past but looks like a 'today/tomorrow' intent, snap to current date."""
        """This is a guardrail in case the model returns a past date for 'today' or 'tomorrow'."""
        try:
            sdt = dt.datetime.fromisoformat(siso.replace("Z","+00:00"))
            edt = dt.datetime.fromisoformat(eiso.replace("Z","+00:00"))
        except Exception:
            return siso, eiso

        # if already future or within last day, keep as-is
        if edt >= now_utc - dt.timedelta(days=1):
            return siso, eiso

        text = (owner_text or "").lower()
        # Only auto-correct if the owner actually said "today" or "tomorrow"
        if "today" in text or "tomorrow" in text:
            # preserve local times; replace the date with today/tomorrow in LOCAL TZ, then convert to UTC
            which = 0 if "today" in text else 1
            # derive local times of day from the (incorrect) ISO
            s_local_time = sdt.astimezone(tz).time().replace(microsecond=0)
            e_local_time = edt.astimezone(tz).time().replace(microsecond=0)
            target_date = (now_local + dt.timedelta(days=which)).date()
            s_local = dt.datetime.combine(target_date, s_local_time, tzinfo=tz)
            e_local = dt.datetime.combine(target_date, e_local_time, tzinfo=tz)
            s_fixed = s_local.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
            e_fixed = e_local.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
            return s_fixed, e_fixed

        # Otherwise keep original; caller will drop if too old
        return siso, eiso

    added = 0
    errs = 0
    dropped_past = 0

    for b in blocks or []:
        s = b.get("start_iso",""); e = b.get("end_iso","")
        # guardrail: fix if obviously relative past
        s, e = _fix_if_relative_past(s, e)

        try:
            sdt = dt.datetime.fromisoformat(s.replace("Z","+00:00"))
            edt = dt.datetime.fromisoformat(e.replace("Z","+00:00"))
        except Exception:
            errs += 1
            continue

        # hard bounds: must be future and within 30 days
        if edt <= now_utc or sdt >= now_utc + dt.timedelta(days=30):
            dropped_past += 1
            continue

        item = {
            **avail_item_key(client["client_id"], s, e),
            "type": {"S":"availability"},
            "start_iso": {"S": s},
            "end_iso": {"S": e},
            "source": {"S":"owner_sms"},
            "created_ts": {"S": now_iso()}
        }
        try:
            ddb().put_item(
                TableName=tbl_convos(), Item=item,
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)"
            )
            added += 1
        except ddb().exceptions.ConditionalCheckFailedException:
            # duplicate block → ignore
            pass

    return {"ok": True, "added": added, "errors": errs, "dropped": dropped_past}

def availability_clear(client: dict, start_iso: str | None = None, end_iso: str | None = None, clear_all: bool = False) -> dict:
    logger.debug("availability_clear: Clearing availability for client %s, start_iso=%s, end_iso=%s, clear_all=%s", client["client_id"], start_iso, end_iso, clear_all)
    """Delete availability windows (all or intersecting a range)."""
    if clear_all:
        logger.debug("availability_clear: Clearing all availability for client %s", client["client_id"])
        # scan and delete all AVAIL# items under PK
        pk = sched_pk_client(client["client_id"])
        resp = ddb().query(
            TableName=tbl_convos(),
            KeyConditionExpression="pk = :pk AND begins_with(sk,:p)",
            ExpressionAttributeValues={":pk": pk["pk"], ":p":{"S":"AVAIL#"}},
            Limit=500
        )
        for it in resp.get("Items", []):
            ddb().delete_item(TableName=tbl_convos(), Key={"pk":it["pk"], "sk":it["sk"]})
        return {"ok": True, "cleared": len(resp.get("Items", []))}
    # range clear: delete any block that overlaps [start,end]
    if not (start_iso and end_iso):
        return {"ok": False, "error": "range_required"}
    
    logger.debug("availability_clear: Clearing availability for client %s in range %s to %s", client["client_id"], start_iso, end_iso)
    sdt = dt.datetime.fromisoformat(start_iso.replace("Z","+00:00"))
    edt = dt.datetime.fromisoformat(end_iso.replace("Z","+00:00"))
    pk = sched_pk_client(client["client_id"])
    """TODO Improve later by querying only relevant range."""
    resp = ddb().query(
        TableName=tbl_convos(),
        KeyConditionExpression="pk = :pk AND begins_with(sk,:p)",
        ExpressionAttributeValues={":pk": pk["pk"], ":p":{"S":"AVAIL#"}},
        Limit=500
    )
    cleared=0
    for it in resp.get("Items", []):
        sk = _S(it,"sk","")
        _, s, e = sk.split("#",2)
        a = dt.datetime.fromisoformat(s.replace("Z","+00:00"))
        b = dt.datetime.fromisoformat(e.replace("Z","+00:00"))
        if a < edt and b > sdt:  # overlap
            ddb().delete_item(TableName=tbl_convos(), Key={"pk":it["pk"], "sk":it["sk"]})
            cleared+=1
    return {"ok": True, "cleared": cleared}

# ------------- Slot proposal from availability -------------
def list_slot_blocks(client: dict, days_ahead: int) -> List[Tuple[str,str]]:
    logger.debug("list_slot_blocks: Listing slot blocks for client %s for next %d days", client["client_id"], days_ahead)
    """availability minus holds/confirmed -> free blocks."""
    avail = availability_list(client, days_ahead=days_ahead)
    # collect taken slots (holds & confirmed) to exclude the exact start times
    pk = sched_pk_client(client["client_id"])
    """TODO Improve later by querying only relevant range."""
    resp = ddb().query(TableName=tbl_convos(),
        KeyConditionExpression="pk = :pk AND begins_with(sk,:p)",
        ExpressionAttributeValues={":pk": pk["pk"], ":p":{"S":"SLOT#"}},
        Limit=500)
    taken_starts = set()
    for it in resp.get("Items", []):
        sk = _S(it,"sk","")
        try:
            _, s = sk.split("#",1)
            taken_starts.add(s)
        except: pass
    # We’ll filter out any slots exactly starting at taken_starts when we enumerate
    return avail, taken_starts

def next_slots_from_availability(client: dict, days_ahead: int, slot_minutes: int, buffer_minutes: int, count: int = 3) -> List[dict]:
    logger.debug("next_slots_from_availability: Finding next slots for client %s", client["client_id"])
    """From availability windows, find next N slots of slot_minutes length, applying buffer_minutes to immediate next slots."""
    tz = _tz(client.get("timezone") or "America/New_York")
    now_utc = dt.datetime.now(dt.timezone.utc)
    # compute options from availability
    windows, taken_starts = list_slot_blocks(client, days_ahead)
    options=[]
    for s_iso, e_iso in windows:
        sdt = dt.datetime.fromisoformat(s_iso.replace("Z","+00:00"))
        edt = dt.datetime.fromisoformat(e_iso.replace("Z","+00:00"))
        # apply buffer only to immediate next slots
        cur = max(sdt, now_utc + dt.timedelta(minutes=buffer_minutes))
        while cur + dt.timedelta(minutes=slot_minutes) <= edt:
            slot_start_iso = cur.replace(microsecond=0,tzinfo=dt.timezone.utc).isoformat().replace("+00:00","Z")
            if slot_start_iso not in taken_starts:
                end = cur + dt.timedelta(minutes=slot_minutes)
                label_local = _fmt_slot_local(cur, end, tz)
                options.append({
                    "start_iso": slot_start_iso, 
                    "end_iso": end.replace(tzinfo=dt.timezone.utc).isoformat().replace("+00:00","Z"), 
                    "label_local": label_local  
                })
                if len(options) >= count:
                    return options
            cur += dt.timedelta(minutes=slot_minutes)
    return options

def _fmt_slot_local(start_utc: dt.datetime, end_utc: dt.datetime, tz: ZoneInfo) -> str:
    s = start_utc.astimezone(tz); e = end_utc.astimezone(tz); abbr=s.tzname()
    return f"{s.strftime('%a %b %-d')}, {s.strftime('%-I:%M')}–{e.strftime('%-I:%M %p')} {abbr}"

# ------------- Holds / confirm using markers -------------
def write_slot_hold(client_id: str, slot_iso: str, hold_minutes: int) -> bool:
    logger.debug("write_slot_hold: Holding slot %s for client %s", slot_iso, client_id)
    expires = (dt.datetime.utcnow() + dt.timedelta(minutes=hold_minutes)).replace(microsecond=0).isoformat()+"Z"
    try:
        ddb().put_item(
            TableName=tbl_convos(),
            Item={**slot_marker_key(client_id, slot_iso),
                  "type":{"S":"slot_hold"}, "expires_at":{"S": expires}},
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)")
        return True
    except ddb().exceptions.ConditionalCheckFailedException:
        logger.info("write_slot_hold: Slot %s for client %s is already held or confirmed", slot_iso, client_id)
        return False

def confirm_slot_marker(client_id: str, slot_iso: str):
    logger.debug("confirm_slot_marker: Confirming slot %s for client %s", slot_iso, client_id)
    try:
        ddb().update_item(
            TableName=tbl_convos(),
            Key=slot_marker_key(client_id, slot_iso),
            UpdateExpression="SET #t = :v",
            ExpressionAttributeNames={"#t":"type"},
            ExpressionAttributeValues={":v":{"S":"slot_confirmed"}})
    except Exception as e:
        logger.error("confirm_slot_marker: Error confirming slot %s for client %s: %s", slot_iso, client_id, e) 
        pass

# ------------- Scheduling tool agent -------------
def schedule_propose(client: dict, user_e164: str, days_ahead: int | None = None) -> dict:
    logger.debug("schedule_propose: Proposing slots for client %s and user %s", client["client_id"], user_e164)
    """Generate proposed slots based on availability or business hours."""
    days = int(client.get("sched_days_ahead", os.environ.get("SCHED_DAYS_AHEAD","7"))) if days_ahead is None else days_ahead
    slot_m = int(client.get("sched_slot_minutes", os.environ.get("SCHED_SLOT_MINUTES","30")))
    buf_m = int(client.get("sched_buffer_minutes", os.environ.get("SCHED_BUFFER_MINUTES","5")))
    # If SCHED_SOURCE=owner, require availability; else fall back to business hours (not shown here)
    source = (client.get("sched_source", os.environ.get("SCHED_SOURCE","owner")) or "owner").lower()
    if source == "owner":
        options = next_slots_from_availability(client, days, slot_m, buf_m, count=3)
        if not options:
            # no availability -> encourage lead capture path
            return {"ok": True, "slots": [], "empty": True, "message": "No available times on file."}
        # store lightweight sched state with proposals for the user (optional)
        #st = {"proposed": options, "held_slot_iso": "", "updated": now_iso()}

        # attach indexes 1..N
        indexed = [{"index": i+1, **opt} for i, opt in enumerate(options)]

        ddb().put_item(TableName=tbl_convos(), Item={
            "pk":{"S":f"CLIENT#{client['client_id']}#USER#{user_e164}"},
            "sk":{"S":"SCHEDSTATE#ACTIVE"},
            "type":{"S":"sched_state"},
            "proposed_json":{"S": json.dumps(indexed)},
            "held_slot_iso":{"S":""},
            "updated":{"S": now_iso()}
        })
        return {"ok": True, "slots": options}
    else:
        # (legacy business_hours generator, omitted to keep this patch focused)
        return {"ok": True, "slots": []}

def _load_sched_state(client_id: str, user_e164: str) -> dict:
    r = ddb().get_item(TableName=tbl_convos(),
                       Key={"pk":{"S":f"CLIENT#{client_id}#USER#{user_e164}"},
                            "sk":{"S":"SCHEDSTATE#ACTIVE"}})
    it = r.get("Item", {})
    try:
        return {"proposed": json.loads(_S(it,"proposed_json","[]")), "held": _S(it,"held_slot_iso","")}
    except Exception:
        return {"proposed": [], "held": ""}

def _autocorrect_iso_from_proposals(bad_iso: str, proposals: List[dict]) -> str | None:
    """Fixes bad-year cases by matching month/day/time to a current proposal."""
    try:
        bad = dt.datetime.fromisoformat(bad_iso.replace("Z","+00:00"))
    except Exception:
        return None
    for opt in proposals:
        try:
            cand = dt.datetime.fromisoformat(opt["start_iso"].replace("Z","+00:00"))
            if (cand.month, cand.day, cand.hour, cand.minute) == (bad.month, bad.day, bad.hour, bad.minute):
                return opt["start_iso"]
        except Exception:
            continue
    return None

def _user_pk(client_id: str, user_e164: str) -> Dict[str, Dict[str,str]]:
    return {"pk": {"S": f"CLIENT#{client_id}#USER#{user_e164}"}}

def _list_user_appointments(client_id: str, user_e164: str) -> List[dict]:
    logger.debug("_list_user_appointments: Listing appointments for client %s and user %s", client_id, user_e164)
    """Return all appointment items (confirmed) for the user, oldest→newest."""
    resp = ddb().query(
        TableName=tbl_convos(),
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={":pk": _user_pk(client_id, user_e164)["pk"], ":p": {"S": "TS#"}},
        ScanIndexForward=True,
        Limit=200
    )
    out=[]
    for it in resp.get("Items", []):
        if _S(it, "type") != "appointment":
            continue
        out.append({
            "pk": it["pk"], "sk": it["sk"],
            "appointment_id": _S(it, "sk").split("#APPT#")[-1],
            "slot_start": _S(it, "slot_start"),
            "ts": _S(it, "ts"),
            "status": _S(it, "status","confirmed")
        })
    return out

def _next_upcoming_appt(appts: List[dict]) -> dict | None:
    logger.debug("_next_upcoming_appt: Finding next upcoming appointment from %d appointments", len(appts))
    now_utc = dt.datetime.now(dt.timezone.utc)
    best=None; best_dt=None
    for a in appts:
        try:
            sdt = dt.datetime.fromisoformat(a["slot_start"].replace("Z","+00:00"))
        except Exception:
            continue
        if sdt >= now_utc and (best_dt is None or sdt < best_dt):
            best, best_dt = a, sdt
    return best

def schedule_hold(client: dict, user_e164: str, slot_iso: str, 
                  service_type: str | None = None, notes: str | None = None,
                  slot_index: int | None = None) -> dict:
    logger.debug("schedule_hold: Holding slot %s for client %s and user %s", slot_iso, client["client_id"], user_e164)
    state = _load_sched_state(client["client_id"], user_e164)
    if slot_index:
        # preferred path: map index -> iso
        candidates = [opt for opt in state["proposed"] if int(opt.get("index",0)) == int(slot_index)]
        if not candidates:
            return {"ok": False, "error": "invalid_index"}
        slot_iso = candidates[0]["start_iso"]
    elif slot_iso:
        # legacy path: try to repair if it looks stale
        now_utc = dt.datetime.now(dt.timezone.utc)
        try:
            sdt = dt.datetime.fromisoformat(slot_iso.replace("Z","+00:00"))
            if sdt < now_utc - dt.timedelta(days=365) and state["proposed"]:
                fixed = _autocorrect_iso_from_proposals(slot_iso, state["proposed"])
                if fixed:
                    slot_iso = fixed
        except Exception:
            pass
    else:
        return {"ok": False, "error": "slot_required"}

    """Attempt to hold the selected slot for the user."""
    # Verify slot_iso lies within an availability window
    wins = availability_list(client, days_ahead=int(client.get("sched_days_ahead", os.environ.get("SCHED_DAYS_AHEAD","7"))))
    sdt = dt.datetime.fromisoformat(slot_iso.replace("Z","+00:00"))
    if not any(dt.datetime.fromisoformat(s.replace("Z","+00:00")) <= sdt <
               dt.datetime.fromisoformat(e.replace("Z","+00:00")) for s,e in wins):
        return {"ok": False, "error": "slot_not_available"}

    if not write_slot_hold(client["client_id"], slot_iso, int(client.get("sched_hold_minutes", os.environ.get("SCHED_HOLD_MINUTES","15")))):
        return {"ok": False, "conflict": True, "message": "That time was just taken. I can send new options."}

    # update state
    ddb().put_item(TableName=tbl_convos(), Item={
        "pk":{"S":f"CLIENT#{client['client_id']}#USER#{user_e164}"},
        "sk":{"S":"SCHEDSTATE#ACTIVE"},
        "type":{"S":"sched_state"},
        "proposed_json":{"S": json.dumps(state["proposed"])},
        "held_slot_iso":{"S": slot_iso},
        "service_type":{"S": service_type or ""},
        "notes":{"S": notes or ""},
        "updated":{"S": now_iso()}
    })
    return {"ok": True, "held_until_min": int(client.get("sched_hold_minutes", os.environ.get("SCHED_HOLD_MINUTES","15")))}

def schedule_confirm(client: dict, user_e164: str) -> dict:
    logger.debug("schedule_confirm: Confirming held slot for client %s and user %s", client["client_id"], user_e164)
    """Confirm the held slot into an appointment."""
    # fetch held slot
    r = ddb().get_item(TableName=tbl_convos(),
                       Key={"pk":{"S":f"CLIENT#{client['client_id']}#USER#{user_e164}"},
                            "sk":{"S":"SCHEDSTATE#ACTIVE"}})
    it = r.get("Item", {})
    slot_iso = _S(it, "held_slot_iso", "")
    if not slot_iso:
        return {"ok": False, "error": "no_held_slot"}
    appt_id = "appt-" + secrets.token_hex(6)
    ts = now_iso()
    # write appointment under user PK
    ddb().put_item(TableName=tbl_convos(), Item={
        "pk":{"S":f"CLIENT#{client['client_id']}#USER#{user_e164}"},
        "sk":{"S":f"TS#{ts}#APPT#{appt_id}"},
        "gsi1pk":{"S":f"CLIENT#{client['client_id']}"},
        "gsi1sk":{"S":f"TS#{ts}"},
        "type":{"S":"appointment"},
        "status":{"S":"confirmed"},
        "slot_start":{"S": slot_iso},
        "service_type":{"S": _S(it,"service_type","")},
        "notes":{"S": _S(it,"notes","")},
        "ts":{"S": ts}
    })
    confirm_slot_marker(client["client_id"], slot_iso)
    # clear sched state
    try: ddb().delete_item(TableName=tbl_convos(),
                           Key={"pk":{"S":f"CLIENT#{client['client_id']}#USER#{user_e164}"},
                                "sk":{"S":"SCHEDSTATE#ACTIVE"}})
    except Exception as e:
        logger.error("schedule_confirm: Error confirming held slot %s for client %s: %s", slot_iso, client["client_id"], e) 
        pass
    # notify client internally
    notify_appt_client_sms(client, user_e164, slot_iso, appt_id,
                           _S(it,"service_type",""), _S(it,"notes",""))
    return {"ok": True, "appointment_id": appt_id, "slot_start": slot_iso}

def schedule_cancel_hold(client: dict, user_e164: str) -> dict:
    logger.debug("schedule_cancel: Canceling held slot for client %s and user %s", client["client_id"], user_e164)
    """Cancel any held slot for the user."""
    r = ddb().get_item(TableName=tbl_convos(),
                       Key={"pk":{"S":f"CLIENT#{client['client_id']}#USER#{user_e164}"},
                            "sk":{"S":"SCHEDSTATE#ACTIVE"}})
    it = r.get("Item", {})
    logger.debug("schedule_cancel: Retrieved sched state item: %s", it)

    slot_iso = _S(it,"held_slot_iso","")
    if slot_iso:
        try: ddb().delete_item(TableName=tbl_convos(), Key=slot_marker_key(client["client_id"], slot_iso))
        except Exception as e:
            logger.error("schedule_cancel: Error deleting slot hold marker for client %s and user %s: %s", client["client_id"], user_e164, e)
            pass
    else:
        logger.debug("schedule_cancel: Slot ISO date not found for client %s and user %s", client["client_id"], user_e164)
        return {"ok": False, "error": "no_held_slot"}

    try: ddb().delete_item(TableName=tbl_convos(),
                           Key={"pk":{"S":f"CLIENT#{client['client_id']}#USER#{user_e164}"},
                                "sk":{"S":"SCHEDSTATE#ACTIVE"}})
    except Exception as e:
        logger.error("schedule_cancel: Error canceling held slot for client %s and user %s: %s", client["client_id"], user_e164, e)
        pass

    # notify_appt_client_sms(client, user_e164, slot_iso, appt_id="", service_type="", notes="canceled")
    return {"ok": True, "canceled": True}

def schedule_cancel_appointment(client: dict, user_e164: str, appointment_id: str | None = None) -> dict:
    logger.debug("schedule_cancel_appointment: Canceling appointment for client %s and user %s, appointment_id=%s", client["client_id"], user_e164, appointment_id)
    """Cancel an existing appointment by ID, or the next upcoming if no ID given."""
    appts = _list_user_appointments(client["client_id"], user_e164)
    target = None

    if appointment_id:
        for a in appts:
            if a["appointment_id"] == appointment_id:
                target = a
                break
    else:
        target = _next_upcoming_appt(appts)

    if not target:
        return {"ok": False, "error": "no_matching_appointment"}

    logger.debug("schedule_cancel_appointment: Found target appointment to cancel: %s", target)

    # delete SLOT marker (if present)
    slot_iso = target.get("slot_start","")
    if slot_iso:
        try:
            logger.debug("schedule_cancel_appointment: Deleting slot marker for client %s and user %s at slot %s", client["client_id"], user_e164, slot_iso)
            ddb().delete_item(TableName=tbl_convos(), Key=slot_marker_key(client["client_id"], slot_iso))
        except Exception:
            logger.error("schedule_cancel_appointment: Error deleting slot marker for client %s and user %s: %s", client["client_id"], user_e164, e)
            pass

    # delete the appointment record itself
    try:
        logger.debug("schedule_cancel_appointment: Deleting appointment record for client %s and user %s, appointment_id=%s", client["client_id"], user_e164, target["appointment_id"])
        ddb().delete_item(TableName=tbl_convos(), Key={"pk": target["pk"], "sk": target["sk"]})
    except Exception:
        logger.error("schedule_cancel_appointment: Error deleting appointment for client %s and user %s: %s", client["client_id"], user_e164, e)
        pass

    # notify owner via SMS
    try:
        logger.debug("schedule_cancel_appointment: Notifying client %s about canceled appointment %s", client["client_id"], target["appointment_id"])
        notify_appt_cancel_client_sms(client, user_e164, slot_iso, target["appointment_id"])
    except Exception:
        logger.error("schedule_cancel_appointment: Error notifying client %s about canceled appointment %s: %s", client["client_id"], target["appointment_id"], e)
        pass

    return {"ok": True, "canceled_appointment_id": target["appointment_id"], "slot_start": slot_iso}

def notify_appt_client_sms(client: dict, user_e164: str, slot_iso: str, appt_id: str, service_type: str, notes: str):
    logger.debug("notify_appt_client_sms: Notifying client %s about appointment %s via SMS", client["client_id"], appt_id)
    """Send SMS to client about confirmed/canceling appointment."""
    msid = client.get("messaging_service_sid") or ""
    to_e164 = client.get("lead_notify_sms_e164") or client.get("escalation_phone_e164") or ""
    if not (msid and to_e164): return
    tz = _tz(client.get("timezone") or "America/New_York")
    s = dt.datetime.fromisoformat(slot_iso.replace("Z","+00:00")).astimezone(tz) if slot_iso else None
    msg = f"{client.get('display_name')}: Appt {appt_id} with {user_e164} at {s.strftime('%a %b %-d, %-I:%M %p %Z')}" if s else f"{client.get('display_name')}: Appt {appt_id} with {user_e164}"
    if service_type: msg += f"; type: {service_type}"
    if notes: msg += f"; notes: {notes[:80]}"
    if len(msg)>300: msg = msg[:297]+"…"
    try: _twilio_send_sms(msid, to_e164, msg)
    except Exception as e:
        logger.error("notify_appt_client_sms: Error sending SMS to %s: %s", to_e164, e)
        pass

def notify_appt_cancel_client_sms(client: dict, user_e164: str, slot_iso: str, appt_id: str):
    msid = client.get("messaging_service_sid") or ""
    to_e164 = client.get("lead_notify_sms_e164") or client.get("escalation_phone_e164") or ""
    if not (msid and to_e164):
        return
    tz = _tz(client.get("timezone") or "America/New_York")
    when = ""
    if slot_iso:
        s = dt.datetime.fromisoformat(slot_iso.replace("Z","+00:00")).astimezone(tz)
        when = s.strftime('%a %b %-d, %-I:%M %p %Z')
    msg = f"{client.get('display_name')}: CANCELED appt {appt_id} with {user_e164}"
    if when:
        msg += f" at {when}"
    if len(msg)>300:
        msg = msg[:297]+"…"
    try:
        _twilio_send_sms(msid, to_e164, msg)
    except Exception:
        pass

# ------------- Twilio SMS sending -------------

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
def orchestrate_owner(client_id: str, channel: str, user_e164: str, text: str, message_sid: str | None, event: str | None = None) -> dict:
    logger.debug("orchestrate_owner: Orchestrating owner chat for client %s, channel %s, user %s", client_id, channel, user_e164)
    client = get_client(client_id)

    tz = _tz(client.get("timezone") or "America/New_York")
    now_utc = dt.datetime.now(dt.timezone.utc)
    now_local = now_utc.astimezone(tz)

    owner_now_anchor = (
        f"NOW_UTC: {now_utc.replace(microsecond=0).isoformat().replace('+00:00','Z')}\n"
        f"NOW_LOCAL: ({client['timezone']}): {now_local.replace(microsecond=0).isoformat()}\n"
        "Rules:\n"
        "- Interpret relative dates like 'today', 'tomorrow', 'this Friday' relative to NOW_LOCAL's calendar date.\n"
        "- When replying to the OWNER, display times in the BUSINESS TIMEZONE only; do NOT show 'Z' or UTC.\n"
        "- If a tool returns 'label_display', REPEAT IT VERBATIM (do not paraphrase or rewrite dates).\n"
        #"- Only return availability within the next 30 days and never in the past.\n"
        "- Do not return availability that is in the past.\n"
    )

    persona_owner = (
        f"You assist the owner of {client['display_name']}. "
        "They will text you availability like 'today 2-5', 'Tue 9-11', 'clear all', 'list'. "
        "Parse their message in the business timezone and call the availability tools. "
        "Confirm briefly. If unclear, ask for a concrete time window.\n\n"
        + owner_now_anchor
    )

    max_reply_len = client["max_reply_len"] if channel.startswith("sms") else max(600, client["max_reply_len"])
    #history_max_turns = int(os.environ.get("MAX_HISTORY_TURNS","10"))

    msgs=[{"role":"system","content": persona_owner}]

    logger.debug("orchestrate_owner: Fetching recent messages for context")
    # Read last 2 messages to capture context from owner and in case model asked a follow up question
    past_msgs, saw_current = fetch_recent_messages(client_id, user_e164, limit=2, current_msg_sid=message_sid)
    msgs.extend(past_msgs)

    #past, saw = fetch_recent_messages(client_id, user_e164, limit=history_max_turns, current_msg_sid=message_sid)
    # We do not include customer history for owner mode (keeps it clean) - add if needed later
    if not saw_current and text:
        logger.debug("orchestrate_owner: Adding current owner message to context")
        msgs.append({"role":"user","content": text})

    functions = [
        {
            "name":"availability_upsert",
            "description":"Store availability windows. Anchor relative dates to NOW_LOCAL in the system message. "
                          "Return only FUTURE intervals within 30 days. Output UTC ISO (Z).",
            "parameters":{"type":"object","properties":{
                "blocks":{"type":"array","items":{"type":"object","properties":{
                    "start_iso":{"type":"string","description":"UTC ISO8601 start, e.g., 2025-11-11T19:00:00Z"},
                    "end_iso":{"type":"string","description":"UTC ISO8601 end"}
                },"required":["start_iso","end_iso"]}}
            },"required":["blocks"]}
        },
        {
            "name":"availability_clear",
            "description":"List future availability windows. For OWNER replies, ALWAYS use each window’s 'label_display' as-is (do not restate or modify dates/times).",
            "parameters":{"type":"object","properties":{
                "clear_all":{"type":"boolean","default":False},
                "start_iso":{"type":"string"},
                "end_iso":{"type":"string"}
            }}
        },
        {
            "name":"availability_list",
            "description":"List future availability windows. For OWNER display, ALWAYS show each window’s label_local "
                      "(business timezone) instead of raw ISO times.",
            "parameters":{"type":"object","properties":{
                "days_ahead":{"type":"integer","default":30}
            }}
        }
    ]

    loops = int(os.environ.get("MAX_TOOL_LOOPS","2"))
    tool_results = {}

    for _ in range(loops):
        resp = openai_chat(msgs, functions)
        msg = resp["choices"][0]["message"]
        if msg.get("function_call"):
            fn = msg["function_call"]["name"]
            args = json.loads(msg["function_call"].get("arguments") or "{}")

            # Owner tools
            if fn == "availability_upsert":
                result = availability_upsert(client, args.get("blocks") or [], owner_text=text)
            elif fn == "availability_clear":
                result = availability_clear(client, args.get("start_iso"), args.get("end_iso"), bool(args.get("clear_all")))
            elif fn == "availability_list":
                result = availability_list_pretty(client, int(args.get("days_ahead", 30)))
            else:
                result = {"ok": False, "error": f"unknown or unauthorized tool {fn}"}

            tool_results[fn] = result
            msgs.append({"role":"assistant","content":None,"function_call":msg["function_call"]})
            msgs.append({"role":"function","name":fn,"content":json.dumps(result)})
            continue

        # final text
        final = (msg.get("content") or "").strip()
        if not final: break
        return {"ok": True, "reply": clamp_for_channel(final, channel, max_reply_len), "tools": tool_results}

    return {"ok": True, "reply": clamp_for_channel("Thanks—can you clarify?", channel, max_reply_len), "tools": tool_results}

def orchestrate_user(client_id: str, channel: str, user_e164: str, text: str, message_sid: str | None, 
                event: str | None = None, transcript: str | None = None, role: str | None = None) -> dict:
    logger.debug("orchestrate_user: Orchestrating chat for client %s, channel %s, user %s", client_id, channel, user_e164)
    client = get_client(client_id)
    logger.debug("orchestrate_user: Client config: %s", json.dumps(client))

    persona = client["bot_persona"] or f"You are {client['display_name']}'s helpful assistant. Be brief and friendly."
    logger.debug("orchestrate_user: Using bot persona: %s", persona)

    max_reply_len = client["max_reply_len"] if channel == "sms" else max(600, client["max_reply_len"])
    logger.debug("orchestrate_user: Max reply length set to %d for channel %s", max_reply_len, channel)

    history_max_turns = int(os.environ.get("MAX_HISTORY_TURNS", "10"))
    logger.debug("orchestrate_user: Conversation history max turns is %s", history_max_turns)

    # If this is a missed-call kickoff, bias the system prompt accordingly
    missed_prelude = ""
    if (event or "").lower() == "missed_call":
        logger.debug("orchestrate_user: Adding missed call prelude to system prompt")
        missed_prelude = (
            "The user just called and we missed them. "
            "If a transcript is provided, use it to personalize your first text. "
            "Start friendly, acknowledge the call, and offer one clear next step. "
            "Keep very concise for SMS. Do not include links unless asked.\n"
        )
        if transcript:
            logger.debug("orchestrate_user: Adding voicemail transcript to missed call prelude")
            missed_prelude += f"Voicemail transcript (may be partial/noisy): {transcript}\n"


    lead_rules = ""
    if client.get("lead_agent_enabled", False):
        logger.debug("orchestrate_user: Adding lead agent rules to system prompt")
#        core, extra = _lead_defaults(client.get("lead_vertical","generic"))
        required = _parse_required_fields(client.get("lead_required_fields",""), client.get("lead_vertical","generic"))
        lead_rules = (
            "- If the user asks for a quote/estimate/appointment/sales contact/human or you are unsure after one turn, "
            "call the lead_agent_update function with any fields you can extract from chat history. "
            f"Required fields to capture (in order): {', '.join(required)}. "
            f"Ask at most one concise question at a time (<= 300 chars) and at most {os.environ.get("LEAD_MAX_QUESTIONS", "3")} questions total.\n"
        )

    tz = _tz(client.get("timezone") or "America/New_York")
    now_utc = dt.datetime.now(dt.timezone.utc)
    now_local = now_utc.astimezone(tz)

    user_now_anchor = (
        f"NOW_UTC: {now_utc.replace(microsecond=0).isoformat().replace('+00:00','Z')}\n"
        f"NOW_LOCAL ({client['timezone']}): {now_local.replace(microsecond=0).isoformat()}\n"
    )

    sched_rules = ""
    if client.get("scheduling_enabled", False):
        sched_rules = (
            "- If the user asks to book/schedule/reschedule/cancel or requests specific times, "
            "use the scheduling functions: schedule_propose (to show 3 options), schedule_hold (to hold a chosen slot), "
            "schedule_confirm (to confirm), schedule_cancel_hold (to cancel a held slot), "
            "schedule_cancel_appointment (to cancel a confirmed appointment). "
            "Keep replies short. If no times are available, use the lead agent.\n"
            "Scheduling rules:\n"
            "- When proposing times, enumerate them as 1), 2), 3) with local dates/times.\n"
            "- When the user picks, call 'schedule_hold' with 'slot_index' from the most recent proposals (do NOT construct dates yourself).\n"
            "- After holding, prompt the user to confirm and call 'schedule_confirm'.\n"
            "- To cancel a tentative time that is only on hold, call 'schedule_cancel_hold'.\n"
            "- To cancel a confirmed appointment, call 'schedule_cancel_appointment'.\n"
            "(pass 'appointment_id' if you know it; otherwise cancel the next upcoming confirmed appointment for this user).\n"
        )

    system = (
        f"{user_now_anchor}"
        f"{persona}\n"
        f"{missed_prelude}"
        f"- When unsure, ask a brief clarifying question.\n"
        f"- For SMS, keep replies as informative as possible but concise; avoid long lists.\n"
        f"- If user asks a general question, use the knowledge base tool.\n"
        f"- If user asks about hours, use the business hours tool.\n"
        f"{lead_rules}"
        f"{sched_rules}"
        f"- If you cite info, reference the doc title when available.\n"
        f"- Reply language should match user's message language when possible.\n"
    )

    past_msgs, saw_current = fetch_recent_messages(client_id, user_e164, limit=history_max_turns, current_msg_sid=message_sid)
    msgs = [{"role": "system", "content": system}]
    msgs.extend(past_msgs)

    # For missed_call kickoff, the user didn't send a text yet; seed a virtual user cue
    if (event or "").lower() == "missed_call" and not text:
        logger.debug("orchestrate_user: Seeding missed call user message into chat history")
        seed = "We missed your call."
        msgs.append({"role": "user", "content": seed})
    elif not saw_current and text:
        logger.debug("orchestrate_user: Adding current user message to chat history")
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
        logger.debug("orchestrate_user: Adding lead_agent_update function to available tools")
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

    # customer scheduling functions
    if client.get("scheduling_enabled", False):
        functions.extend([
            {
                "name":"schedule_propose",
                "description":"Propose up to 3 free time slots from owner-provided availability. Enumerate 1..N for the user.",
                "parameters":{"type":"object",
                              "properties":{
                                  "days_ahead":{"type":"integer","minimum":1,"maximum":30}
                              }
                }
            },
            {
                "name":"schedule_hold",
                "description":"Hold a chosen slot. ALWAYS pass 'slot_index' from the most recent proposals instead of constructing a date.",
                "parameters":{
                    "type":"object",
                    "properties":{
                        "slot_index":{"type":"integer","minimum":1},
                        "slot_iso":{"type":"string"},  # legacy fallback
                        "service_type":{"type":"string"},
                        "notes":{"type":"string"}
                    }
                    # "anyOf":[{"required":["slot_index"]},{"required":["slot_iso"]}]
                }
            },
            {
                "name":"schedule_confirm",
                "description":"Confirm the held slot.",
                "parameters":{"type":"object","properties":{}}
            },
            {
                "name":"schedule_cancel_hold",
                "description":"Cancel a tentative hold (not a confirmed appointment). Use when a held slot should be released.",
                "parameters":{"type":"object","properties":{}}
            },
            {
                "name":"schedule_cancel_appointment",
                "description":"Cancel a confirmed appointment. If 'appointment_id' is omitted, cancel the next upcoming confirmed appointment for this user.",
                "parameters":{"type":"object","properties":{
                    "appointment_id":{"type":"string"}
                }}
            }
        ])

    logger.debug("orchestrate_user: Initial messages: %s", json.dumps(msgs))

    loops = int(os.environ.get("MAX_TOOL_LOOPS","2"))
    tool_results = {}

    for _ in range(loops):
        resp = openai_chat(msgs, functions)
        choice = resp["choices"][0]
        msg = choice["message"]

        logger.info("orchestrate_user: OpenAI response message: %s", msg)

        if msg.get("function_call"):
            logger.debug("orchestrate_user: Model requested tool call: %s", msg["function_call"])
            fn = msg["function_call"]["name"]
            args = json.loads(msg["function_call"].get("arguments") or "{}")

            if fn == "search_kb":
                q = args.get("query") or text
                k = int(args.get("k", 5))
                result = tool_search_kb(client_id, q, k)
                logger.debug("orchestrate_user: search_kb result: %s", result)
            elif fn == "get_business_hours":
                result = tool_get_business_hours(client)
                logger.debug("orchestrate_user: get_business_hours result: %s", result)
            elif fn == "lead_agent_update" and client.get("lead_agent_enabled", False):
                logger.debug("orchestrate_user: Calling lead_agent_update with args: %s", args)
                result = lead_agent_update(client, user_e164, args)
                logger.debug("orchestrate_user: lead_agent_update result: %s", result)
            elif fn == "schedule_propose" and client.get("scheduling_enabled", False):
                r = schedule_propose(client, user_e164, args.get("days_ahead"))
                # If empty availability, hint the model to switch to lead agent
                if r.get("empty"):
                    result = r
                else:
                    result = r
            elif fn == "schedule_hold" and client.get("scheduling_enabled", False):
                result = schedule_hold(client, user_e164, args.get("slot_iso",""), 
                                       args.get("service_type"), args.get("notes"),
                                       slot_index=args.get("slot_index"))
            elif fn == "schedule_confirm" and client.get("scheduling_enabled", False):
                result = schedule_confirm(client, user_e164)
            elif fn == "schedule_cancel_hold" and client.get("scheduling_enabled", False):
                result = schedule_cancel_hold(client, user_e164)
            elif fn == "schedule_cancel_appointment" and client.get("scheduling_enabled", False):
                result = schedule_cancel_appointment(client, user_e164, args.get("appointment_id"))
            # --- Back-compat: if model calls legacy name, route to hold-cancel ---
            elif fn == "schedule_cancel" and client.get("scheduling_enabled", False):
                result = schedule_cancel_hold(client, user_e164)
            else:
                logger.warning("orchestrate_user: Unknown tool requested: %s", fn)   
                result = {"ok": False, "error": f"unknown tool {fn}"}

            tool_results[fn] = result
            msgs.append({"role":"assistant","content":None,"function_call":msg["function_call"]})
            msgs.append({"role":"function","name":fn,"content":json.dumps(result)})
            continue

        # Model produced a final answer
        final = msg.get("content","").strip()
        logger.debug("orchestrate_user: Model produced final content: %s", final)
        if not final:
            break

        reply = add_opt_out_notice(final, channel, max_reply_len)
        reply = clamp_for_channel(reply, channel, max_reply_len)
        #reply = final.strip()
        logger.info("orchestrate_user: Final reply generated for client %s and user %s: %s", client_id, user_e164, reply)
        return {"ok": True, "reply": reply, "tools": tool_results}

    # If we exit loop without final content, backstop with a generic reply
    backstop = "Thanks for reaching out—can you share a bit more about what you need?"
    reply = add_opt_out_notice(backstop,channel,max_reply_len)
    logger.warning("orchestrate_user: No final reply generated; using backstop reply. Client: %s, User: %s", client_id, user_e164 )
    return {"ok": True, "reply": clamp_for_channel(reply, channel, max_reply_len), "tools": tool_results}

def orchestrate(client_id: str, channel: str, user_e164: str, text: str, message_sid: str | None, 
                event: str | None = None, transcript: str | None = None, role: str | None = None) -> dict:
    logger.debug("orchestrate: Orchestrating chat for client %s, channel %s, user %s", client_id, channel, user_e164)
    is_owner = (role or "").lower() == "owner" or channel == "sms_owner"

    if is_owner:
        logger.debug("orchestrate: Detected owner role or owner channel; routing to owner orchestrator")
        return orchestrate_owner(client_id, channel, user_e164, text, message_sid, event)
    else:
        logger.debug("orchestrate: Detected user role; routing to user orchestrator")
        return orchestrate_user(client_id, channel, user_e164, text, message_sid, event, transcript, role)
    
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
    role        = body.get("role")
    
    if not client_id or not user_e164:
        logger.error("lambda_handler: Missing required parameters: client_id=%s, user_e164=%s", client_id, user_e164)
        return {"statusCode": 400, "headers": JSON, "body": json.dumps({"ok": False, "error": "client_id, user_e164, text required"})}

    result = orchestrate(client_id, channel, user_e164, text, message_sid, event=event_name, transcript=transcript, role=role)
    return {"statusCode": 200, "headers": JSON, "body": json.dumps(result)}
