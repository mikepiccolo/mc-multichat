import json
import os
import time
import datetime as dt
import urllib.parse

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
        "max_reply_len": _N(item,"max_reply_len", 320)
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

def tool_create_lead(client_id: str, user_e164: str, summary: str) -> dict:
    logger.debug("Creating lead for client %s and user %s", client_id, user_e164)
    pk = f"CLIENT#{client_id}#USER#{user_e164}"
    ts = now_iso()
    ddb().put_item(
        TableName=tbl_convos(),
        Item={
            "pk": {"S": pk},
            "sk": {"S": f"LEAD#{ts}"},
            "gsi1pk": {"S": f"CLIENT#{client_id}"},
            "gsi1sk": {"S": f"TS#{ts}"},
            "type": {"S": "lead"},
            "summary": {"S": summary[:1000]},
            "ts": {"S": ts}
        }
    )
    return {"ok": True, "lead_created": True, "ts": ts}

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

# ------------ OpenAI Chat (function calling) ------------
def openai_chat(messages, functions):
    logger.debug("Calling OpenAI chat API with %d messages and %d functions", len(messages), len(functions))
    model = os.environ.get("MODEL_NAME", "gpt-4o-mini")
    key   = get_secret(os.environ["OPENAI_SECRET_ARN"])
    payload = {
        "model": model,
        "messages": messages,
        "functions": functions,
        "function_call": "auto",
        "temperature": 0.3,
    }

    logger.debug("OpenAI chat payload: %s", json.dumps(payload))

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
    logger.debug("Orchestrating chat for client %s, channel %s, user %s", client_id, channel, user_e164)
    client = get_client(client_id)
    logger.debug("Client config: %s", json.dumps(client))

    persona = client["bot_persona"] or f"You are {client['display_name']}'s helpful assistant. Be brief and friendly."
    logger.debug("Using bot persona: %s", persona)

    max_reply_len = client["max_reply_len"] if channel == "sms" else max(600, client["max_reply_len"])
    logger.debug("Max reply length set to %d for channel %s", max_reply_len, channel)

    history_max_turns = int(os.environ.get("MAX_HISTORY_TURNS", "10"))
    logger.debug("Conversation history max turns is %s", history_max_turns)

    # If this is a missed-call kickoff, bias the system prompt accordingly
    missed_prelude = ""
    if (event or "").lower() == "missed_call":
        logger.debug("Adding missed call prelude to system prompt")
        missed_prelude = (
            "The user just called and we missed them. "
            "If a transcript is provided, use it to personalize your first text. "
            "Start friendly, acknowledge the call, and offer one clear next step. "
            "Keep very concise for SMS. Do not include links unless asked.\n"
        )
        if transcript:
            logger.debug("Adding voicemail transcript to missed call prelude")
            missed_prelude += f"Voicemail transcript (may be partial/noisy): {transcript}\n"

    system = (
        f"{persona}\n"
        f"{missed_prelude}"
        f"- When unsure, ask a brief clarifying question.\n"
        f"- For SMS, keep replies as informative as possible but concise; avoid long lists.\n"
        f"- If user asks a general question, use the knowledge base tool.\n"
        f"- If user asks about hours, use the business hours tool.\n"
        f"- If user asks to talk to a human or leave details, call create_lead.\n"
        f"- If you cite info, reference the doc title when available.\n"
        f"- Reply language should match user's message language when possible.\n"
    )

    past_msgs, saw_current = fetch_recent_messages(client_id, user_e164, limit=history_max_turns, current_msg_sid=message_sid)
    msgs = [{"role": "system", "content": system}]
    msgs.extend(past_msgs)

    # For missed_call kickoff, the user didn't send a text yet; seed a virtual user cue
    if (event or "").lower() == "missed_call" and not text:
        logger.debug("Seeding missed call user message into chat history")
        seed = "We missed your call."
        msgs.append({"role": "user", "content": seed})
    elif not saw_current and text:
        logger.debug("Adding current user message to chat history")
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
        },
        {
            "name": "create_lead",
            "description": "Create a lead with a short summary of the user's need.",
            "parameters": {"type":"object","properties":{
                "summary":{"type":"string"}
            },"required":["summary"]}
        }
    ]

    logger.debug("Initial messages: %s", json.dumps(msgs))

    loops = int(os.environ.get("MAX_TOOL_LOOPS","2"))
    tool_results = {}

    for _ in range(loops):
        resp = openai_chat(msgs, functions)
        choice = resp["choices"][0]
        msg = choice["message"]

        logger.info("OpenAI response message: %s", msg)

        if msg.get("function_call"):
            logger.debug("Model requested tool call: %s", msg["function_call"])
            fn = msg["function_call"]["name"]
            args = json.loads(msg["function_call"].get("arguments") or "{}")

            if fn == "search_kb":
                q = args.get("query") or text
                k = int(args.get("k", 5))
                result = tool_search_kb(client_id, q, k)
                logger.debug("search_kb result: %s", result)
            elif fn == "get_business_hours":
                result = tool_get_business_hours(client)
                logger.debug("get_business_hours result: %s", result)
            elif fn == "create_lead":
                summary = (args.get("summary") or text)[:500]
                result = tool_create_lead(client_id, user_e164, summary)
                logger.debug("create_lead result: %s", result)
            else:
                logger.warning("Unknown tool requested: %s", fn)   
                result = {"ok": False, "error": f"unknown tool {fn}"}

            tool_results[fn] = result
            msgs.append({"role":"assistant","content":None,"function_call":msg["function_call"]})
            msgs.append({"role":"function","name":fn,"content":json.dumps(result)})
            continue

        # Model produced a final answer
        final = msg.get("content","").strip()
        logger.debug("Model produced final content: %s", final)
        if not final:
            break

        reply = add_opt_out_notice(final, channel, max_reply_len)
        reply = clamp_for_channel(reply, channel, max_reply_len)
        #reply = final.strip()
        logger.info("Final reply generated for client %s and user %s: %s", client_id, user_e164, reply)
        return {"ok": True, "reply": reply, "tools": tool_results}

    # If we exit loop without final content, backstop with a generic reply
    backstop = "Thanks for reaching out—can you share a bit more about what you need?"
    reply = add_opt_out_notice(backstop,channel,max_reply_len)
    logger.warning("No final reply generated; using backstop reply. Client: %s, User: %s", client_id, user_e164 )
    return {"ok": True, "reply": clamp_for_channel(reply, channel, max_reply_len), "tools": tool_results}

# ------------ Lambda entry ------------
def lambda_handler(event, context):
    logger.debug("Received event: %s", json.dumps(event))
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
        logger.error("Missing required parameters: client_id=%s, user_e164=%s", client_id, user_e164)
        return {"statusCode": 400, "headers": JSON, "body": json.dumps({"ok": False, "error": "client_id, user_e164, text required"})}

    result = orchestrate(client_id, channel, user_e164, text, message_sid, event=event_name, transcript=transcript)
    return {"statusCode": 200, "headers": JSON, "body": json.dumps(result)}
