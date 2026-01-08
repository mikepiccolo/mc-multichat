#!/usr/bin/env python3
"""
Provision a new client (or update the shared Studio Flow).

Features:
- --profile {aws_profile} to specify AWS CLI profile for secrets access (lower | prod)
- --flow-action {upsert|create|update|skip} controls Flow management (default: upsert)
- --flow-friendly-name sets the Flow FriendlyName (default: '{NAME_PREFIX}-missed-call')
- --flow-template sets the Flow template path (default: twilio/flow_missed_call.template.json)

Env:
  API_BASE_URL   = https://{rest_id}.execute-api.{region}.amazonaws.com/v1
  NAME_PREFIX    = mc-multichat-dev (terraform output -raw name_prefix)

Secrets (AWS Secrets Manager):
  {NAME_PREFIX}/twilio_account_sid
  {NAME_PREFIX}/twilio_auth_token
  {NAME_PREFIX}/studio_bearer

Flow upsert (update a flow if it exists or create flow if it does not exist):
  python scripts/manage_flow.py \
    --flow-action upsert \
    
Flow update (update existing flow):
  python scripts/manage_flow.py \
    --flow-action update \
    --flow-friendly-name mc-multichat-dev-missed-call \
    --flow-template twilio/flow_missed_call.template.json

Flow create (create new flow, error if exists):
    python scripts/manage_flow.py \
        --profile lower \
        --flow-action create \
        --flow-friendly-name mc-multichat-dev-missed-call \
        --flow-template twilio/flow_missed_call.template.json

"""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
import requests

def get_session(profile_name: str | None):
    if profile_name:
        return boto3.Session(profile_name=profile_name)
    return boto3.Session()

# ---------- Logging helpers ----------
def info(msg: str, **kv):
    line = {"level": "INFO", "msg": msg}
    if kv:
        line.update(kv)
    print(json.dumps(line))

def warn(msg: str, **kv):
    line = {"level": "WARN", "msg": msg}
    if kv:
        line.update(kv)
    print(json.dumps(line))

def error(msg: str, **kv):
    line = {"level": "ERROR", "msg": msg}
    if kv:
        line.update(kv)
    print(json.dumps(line), file=sys.stderr)


# ---------- Secrets helpers ----------
def get_secret(session, arn_or_name: str) -> str:
    sm = session.client("secretsmanager")
    return sm.get_secret_value(SecretId=arn_or_name)["SecretString"]


# ---------- Twilio REST helpers ----------
class TwilioClient:
    def __init__(self, account_sid: str, auth_token: str):
        self.sid = account_sid
        self.auth = (account_sid, auth_token)
        self.api_base = f"https://api.twilio.com/2010-04-01/Accounts/{self.sid}"
        self.studio_base = "https://studio.twilio.com/v2"

    # ---- Studio Flows ----
    def list_flows(self, page_size: int = 50, limit: int = 1000) -> List[Dict[str, Any]]:
        flows: List[Dict[str, Any]] = []
        url = f"{self.studio_base}/Flows"
        params = {"PageSize": page_size}
        while url and len(flows) < limit:
            r = requests.get(url, auth=self.auth, params=params, timeout=30)
            r.raise_for_status()
            data = r.json()
            flows.extend(data.get("flows", []))
            meta = data.get("meta", {})
            url = meta.get("next_page_url")
            params = None
        return flows

    def find_flow_by_friendly_name(self, name: str) -> Optional[Dict[str, Any]]:
        candidates = [f for f in self.list_flows() if f.get("friendly_name") == name]
        if not candidates:
            return None
        try:
            def sort_key(f):  # prefer most recently updated
                return (f.get("date_updated") or f.get("date_created") or "")
            candidates.sort(key=sort_key, reverse=True)
        except Exception:
            pass
        if len(candidates) > 1:
            warn("Multiple Studio Flows share FriendlyName; choosing most recently updated",
                 friendly_name=name, count=len(candidates), chosen_sid=candidates[0].get("sid"))
        return candidates[0]

    def create_flow(self, friendly_name: str, definition_json: str, status: str = "published") -> Dict[str, Any]:
        r = requests.post(
            f"{self.studio_base}/Flows",
            auth=self.auth,
            data={"FriendlyName": friendly_name, "Status": status, "Definition": definition_json},
            timeout=30,
        )
        if r.status_code >= 400:
            error("Create flow failed", status=r.status_code, text=r.text)
        r.raise_for_status()
        return r.json()

    def update_flow(self, flow_sid: str, definition_json: str, status: str = "published") -> Dict[str, Any]:
        r = requests.post(
            f"{self.studio_base}/Flows/{flow_sid}",
            auth=self.auth,
            data={"Status": status, "Definition": definition_json},
            timeout=30,
        )
        if r.status_code >= 400:
            error("Update flow failed", status=r.status_code, text=r.text)
        r.raise_for_status()
        return r.json()

    def studio_webhook_url(self, flow_sid: str) -> str:
        return f"https://webhooks.twilio.com/v1/Accounts/{self.sid}/Flows/{flow_sid}"


# ---------- Flow template helpers ----------
def render_flow_template(path: str, api_base_url: str, studio_bearer: str) -> str:
    raw = Path(path).read_text(encoding="utf-8")
    rendered = raw.replace("{{API_BASE_URL}}", api_base_url)\
                  .replace("{{STUDIO_BEARER}}", studio_bearer)
    try:
        parsed = json.loads(rendered)
    except json.JSONDecodeError as e:
        error("Flow template invalid after substitution", error=str(e))
        raise
    return json.dumps(parsed, separators=(",", ":"))


# ---------- CLI ----------
def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flow-template", default="twilio/flow_missed_call.template.json")
    ap.add_argument(
        "--flow-action",
        choices=["upsert", "create", "update", "skip"],
        default="upsert",
        help="How to manage the shared Studio Flow (default: upsert)",
    )
    ap.add_argument(
        "--flow-friendly-name",
        default=None,
        help="Studio Flow FriendlyName (default: '{NAME_PREFIX}-missed-call')",
    )
    ap.add_argument(
        "--profile",
        default=None,
        required=True,
        choices=["lower", "prod"],
        help="AWS CLI profile to use for secrets access (default: current environment)",
    )
    return ap.parse_args()


def main() -> int:
    args = parse_args()

    # Env
    api_base = os.environ.get("API_BASE_URL")
    name_prefix = os.environ.get("NAME_PREFIX")

    if not api_base:
        error("Missing env API_BASE_URL"); return 2
    
    if not name_prefix:
        error("Missing env NAME_PREFIX"); return 2
    
    info("Env loaded", API_BASE_URL=api_base, NAME_PREFIX=name_prefix, flow_action=args.flow_action)

    flow_name = args.flow_friendly_name or f"{name_prefix}-missed-call"
    
    # Flow FriendlyName
    info("Flow target", friendly_name=flow_name)

    session = get_session(args.profile)

    # Secrets
    try:
        twilio_sid = get_secret(session,f"{name_prefix}/twilio_account_sid")
        twilio_tok = get_secret(session,f"{name_prefix}/twilio_auth_token")
        studio_bearer = get_secret(session,f"{name_prefix}/studio_bearer")
        info("Secrets loaded")
    except Exception as e:
        error("Failed to load secrets", error=str(e)); return 2

    tw = TwilioClient(twilio_sid, twilio_tok)

    # ---- Flow management ----
    flow_sid: Optional[str] = None
    if args.flow_action != "skip":
        # Render definition
        try:
            definition_json = render_flow_template(args.flow_template, api_base, studio_bearer)
        except Exception:
            return 2

        existing = tw.find_flow_by_friendly_name(flow_name)
        info("Flow existence check", exists=bool(existing), existing_sid=(existing or {}).get("sid"))

        if args.flow_action == "create":
            if existing:
                error("Flow already exists; use --flow-action update/upsert", existing_sid=existing["sid"])
                return 2
            created = tw.create_flow(flow_name, definition_json)
            flow_sid = created["sid"]
            info("Flow created", flow_sid=flow_sid)

        elif args.flow_action == "update":
            if not existing:
                error("Flow not found; use --flow-action create/upsert")
                return 2
            updated = tw.update_flow(existing["sid"], definition_json)
            flow_sid = updated["sid"]
            info("Flow updated", flow_sid=flow_sid)

        else:  # upsert
            if existing:
                updated = tw.update_flow(existing["sid"], definition_json)
                flow_sid = updated["sid"]
                info("Flow upsert (updated)", flow_sid=flow_sid)
            else:
                created = tw.create_flow(flow_name, definition_json)
                flow_sid = created["sid"]
                info("Flow upsert (created)", flow_sid=flow_sid)
    else:
        existing = tw.find_flow_by_friendly_name(flow_name)
        if not existing:
            error("--flow-action skip but flow not found", friendly_name=flow_name)
            return 2
        flow_sid = existing["sid"]
        info("Using existing flow (skip mode)", flow_sid=flow_sid)

    if not flow_sid:
        error("Could not determine Flow SID (flow management failed)")
        return 2

    # Final output
    print(json.dumps({
        "ok": True,
        "flow_friendly_name": flow_name,
        "flow_sid": flow_sid,
        "flow_action": args.flow_action,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
