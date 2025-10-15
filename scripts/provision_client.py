#!/usr/bin/env python3
"""
Provision a new client (or update the shared Studio Flow).

Features:
- --action {buy|attach|update|skip} controls phone nuumber action (skip)
-    buy: purchase a new number in the specified area code and attach to the flow
-    attach: attach an existing Twilio number (+E164) to the flow
-    update: update client record only with twilio number.  No twilio action. 
-    skip: no number action, no twilio action
-
- --client-template sets the client template path with DDB client details (default: config/client_pack.example.json)
- --flow-friendly-name sets the Flow FriendlyName (default: '{NAME_PREFIX}-missed-call')
- --area-code sets area code for new number purchase (default: 973)
- --country country for phone number, default 'US'
- --number sets existing Twilio number to attach or update (+E164)

Env:
  NAME_PREFIX    = mc-multichat-dev (terraform output -raw name_prefix)

Secrets (AWS Secrets Manager):
  {NAME_PREFIX}/twilio_account_sid
  {NAME_PREFIX}/twilio_auth_token

Usage (buy number):
  python scripts/provision_client.py \
    --action buy
    --client-template config/client_pack.example.json \
    --area-code 973 \
 
Update number (no number purchase):
  python scripts/provision_client.py \
    --client-id demo-realtor \
    --display-name "Sunrise Realty" \
    --area-code 973 \
    --forward-to +15557654321 \
    --flow-action update \
    --skip-buy-number

Attach an existing number:
  python scripts/provision_client.py \
    --action attach \
    --number +15551234567

 Update an existing number:
  python scripts/provision_client.py \
    --action update \
    --number +15551234567
   
"""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
import requests


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
def get_secret(arn_or_name: str) -> str:
    sm = boto3.client("secretsmanager")
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

    def studio_webhook_url(self, flow_sid: str) -> str:
        return f"https://webhooks.twilio.com/v1/Accounts/{self.sid}/Flows/{flow_sid}"

    # ---- Phone numbers ----
    def search_local_number(self, country: str, area_code: int) -> str:
        if not country or len(country) != 2:
            raise ValueError("Country must be a 2-letter ISO country code")
        if not (100 <= area_code <= 999):
            raise ValueError("Area code must be a 3-digit integer")
        
        r = requests.get(
            f"{self.api_base}/AvailablePhoneNumbers/{country}/Local.json",
            auth=self.auth,
            params={"AreaCode": area_code, "SmsEnabled": "true", "VoiceEnabled": "true"},
            timeout=30,
        )
        r.raise_for_status()
        payload = r.json()
        arr = payload.get("available_phone_numbers") or []
        if not arr:
            raise SystemExit(f"No available numbers found for +{country} area code {area_code}")
        return arr[0]["phone_number"]

    def buy_number(self, phone_number: str, voice_url: str) -> Dict[str, Any]:
        r = requests.post(
            f"{self.api_base}/IncomingPhoneNumbers.json",
            auth=self.auth,
            data={"PhoneNumber": phone_number, "VoiceUrl": voice_url, "VoiceMethod": "POST"},
            timeout=30,
        )
        if r.status_code >= 400:
            error("Buy number failed", status=r.status_code, text=r.text)
        r.raise_for_status()
        return r.json()

    def find_incoming_number_by_e164(self, phone_e164: str) -> Optional[Dict[str, Any]]:
        r = requests.get(
            f"{self.api_base}/IncomingPhoneNumbers.json",
            auth=self.auth,
            params={"PhoneNumber": phone_e164},
            timeout=30,
        )
        r.raise_for_status()
        nums = r.json().get("incoming_phone_numbers", [])
        return nums[0] if nums else None

    def update_incoming_number_voice_url(self, number_sid: str, voice_url: str, method: str = "POST") -> Dict[str, Any]:
        r = requests.post(
            f"{self.api_base}/IncomingPhoneNumbers/{number_sid}.json",
            auth=self.auth,
            data={"VoiceUrl": voice_url, "VoiceMethod": method},
            timeout=30,
        )
        if r.status_code >= 400:
            error("Update number VoiceUrl failed", status=r.status_code, text=r.text, sid=number_sid)
        r.raise_for_status()
        return r.json()


# ---------- Client template helpers ----------
def render_client_template(path: str, twilio_number_e164: str) -> str:
    raw = Path(path).read_text(encoding="utf-8")
    rendered = raw.replace("{{twilio_number_e164}}", twilio_number_e164)

    try:
        parsed = json.loads(rendered)
    except json.JSONDecodeError as e:
        error("Client template invalid after substitution", error=str(e))
        raise
    return parsed #json.dumps(parsed, separators=(",", ":"))

# ---------- DynamoDB upserts ----------
def upsert_ddb_records(name_prefix: str, item: Any):
    ddb = boto3.client("dynamodb")
    clients_tbl = f"{name_prefix}-clients"
    phone_tbl = f"{name_prefix}-phone-routes"

    if not item:
        error("Item is required")
        raise Exception("Item is required in order to update dynamodb")
    
    if item["client_id"] is None or item["client_id"]["S"] is None:
        error("client_id attribute is required in Item in order to update dynamodb")
        raise Exception("client_id attribute is required in Item in order to update dynamodb")
    
    client_id = item["client_id"]["S"]

    if item["twilio_number_e164"] is None or item["twilio_number_e164"]["S"] is None:
        error("twilio_number_e164 attribute is required in Item in order to update dynamodb")
        raise Exception("twilio_number_e164 attribute is required in Item in order to update dynamodb")
    
    twilio_number = item["twilio_number_e164"]["S"]

    if item["escalation_phone_e164"] is None or item["escalation_phone_e164"]["S"] is None:
        error("escalation_phone_e164 attribute is required in Item in order to update dynamodb")
        raise Exception("escalation_phone_e164 attribute is required in Item in order to update dynamodb") 
    
    forward_to = item["escalation_phone_e164"]["S"]

    ddb.put_item(TableName=clients_tbl, Item=item)
    info("Upserted clients row", table=clients_tbl, client_id=client_id, has_number=bool(twilio_number))

    ddb.put_item(
        TableName=phone_tbl,
        Item={
            "phone_e164": {"S": twilio_number}, 
            "client_id": {"S": client_id},
            "escalation_phone_e164": {"S": forward_to}
        }
    )

    info("Upserted phone_routes row", table=phone_tbl, phone_e164=twilio_number)


# ---------- CLI ----------
def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-template", required=False, default="config/client_pack.example.json")
    ap.add_argument("--area-code", type=int, required=False)
    ap.add_argument(
        "--action",
        choices=["buy", "attach", "update", "skip"],
        default="skip",
        help="How to manage the client provisioning: default - skip",
    )
    ap.add_argument(
        "--flow-friendly-name",
        default=None,
        required=False,
        help="Studio Flow FriendlyName (default: '{NAME_PREFIX}-missed-call')",
    )
    ap.add_argument(
        "--number",
        default=None,
        help="Attach an existing Twilio number (+E164) to the Flow or update the number on client record instead of buying",
    )
    ap.add_argument(
        "--country",
        required=False,
        default="US",
        help="Country for phone number (default: US)",
    )
    return ap.parse_args()

def convert_to_e164(number: str, country: str) -> str:
    info("Converting number to E164", number=number, country=country)
    if number.startswith("+") and len(number) == 12 and number[1:].isdigit():
        return number
    # For simplicity, assume US country code if not provided
    if country == "US" and len(number) == 10 and number.isdigit():
        return f"+1{number}"
    elif country == "US" and len(number) == 11 and number.startswith("1") and number[1:].isdigit():
        return f"+{number}"
    else:
        raise ValueError("Number must be in E164 format or a 10-digit US number")

def main() -> int:
    args = parse_args()

    # Env
    name_prefix = os.environ.get("NAME_PREFIX")
 
    if not name_prefix:
        error("Missing env NAME_PREFIX"); return 2
    
    info("Env loaded", NAME_PREFIX=name_prefix)

    # Secrets
    try:
        twilio_sid = get_secret(f"{name_prefix}/twilio_account_sid")
        twilio_tok = get_secret(f"{name_prefix}/twilio_auth_token")
        info("Secrets loaded")
    except Exception as e:
        error("Failed to load secrets", error=str(e)); return 2

    tw = TwilioClient(twilio_sid, twilio_tok)

    # Flow FriendlyName
    flow_name = args.flow_friendly_name or f"{name_prefix}-missed-call"
    info("Flow target", friendly_name=flow_name)

    country = args.country or "US"

    # ---- Flow management ----
    flow_sid: Optional[str] = None

    if args.action == "skip":
        info("Skipping flow management as requested (--action skip).  No action taken.")
        return 0
    
    if args.action == "update":
        if not args.number:
            error("--number is required with --action update")
            return 2
        
        twilio_number = convert_to_e164(args.number, country)
        client_item = render_client_template(args.client_template, twilio_number )
        
        info("Client record prepared for update", client_id=client_item.get("client_id").get("S"), has_number=bool(args.number))
        try:
            info("Updating client record with new number", number=args.number)

            upsert_ddb_records(
                name_prefix=name_prefix,
                item=client_item
            )
        except Exception as e:
            error("DynamoDB upsert failed", error=str(e))
            return 2
        
        info("Client record updated with new number")
    else:
        existing = tw.find_flow_by_friendly_name(flow_name)
        if not existing:
            error("Flow not found; use --flow-action create/upsert")
            return 2
        
        info("Flow existence check", exists=bool(existing), existing_sid=(existing or {}).get("sid"))

        flow_sid = existing["sid"]

        info("Using existing flow for number attach/buy", flow_sid=flow_sid)

        if args.action == "buy":
            info("Buy-new-number requested", area_code=args.area_code, country=country)
            
            try:
                candidate = tw.search_local_number(country, args.area_code)
                purchased = tw.buy_number(candidate, voice_url=tw.studio_webhook_url(flow_sid))
                assigned_number = purchased["phone_number"]
                info("Bought and attached number", number=assigned_number, flow_sid=flow_sid)
            except Exception as e:
                error("Number purchase failed", error=str(e))
                return 2

            assigned_number = convert_to_e164(assigned_number.strip(), country)
            info("Converted assigned number to E164", assigned=assigned_number)
            client_item = render_client_template(args.client_template, assigned_number ) 
            info("Client record prepared for new number", client_id=client_item.get("client_id").get("S"), has_number=bool(assigned_number))
            
            try:
                info("Updating client record with new number ", number=assigned_number)
                upsert_ddb_records(
                    name_prefix=name_prefix,
                    item=client_item
                )
            except Exception as e:
                error("DynamoDB upsert failed", error=str(e))
                return 2
        elif args.action == "attach":
            info("Attach-existing-number requested", number=args.number)

            if not args.number:
                error("--number is required with --action attach")
                return 2

            num = tw.find_incoming_number_by_e164(args.number)
            if not num:
                error("Existing number not found in Twilio account", phone=args.number)
                return 2
            
            updated = tw.update_incoming_number_voice_url(num["sid"], tw.studio_webhook_url(flow_sid))
            assigned_number = updated.get("phone_number") or args.number
            info("Attached existing number to flow", number=assigned_number, flow_sid=flow_sid)

            try:
                assigned_number = convert_to_e164(assigned_number.strip(), country)
                info("Converted assigned number to E164", assigned=assigned_number)
                client_item = render_client_template(args.client_template, assigned_number ) 
                info("Client record prepared for new number", client_id=client_item.get("client_id").get("S"), has_number=bool(assigned_number))
                
                info("Updating client record with new number ", number=assigned_number)
                upsert_ddb_records(
                    name_prefix=name_prefix,
                    item=client_item
                )
            except Exception as e:
                error("DynamoDB upsert failed", error=str(e))
                return 2
        else:
            error("Unknown action", action=args.action)
            return 2

     # Final output
    print(json.dumps({
        "ok": True,
        "action": args.action,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
