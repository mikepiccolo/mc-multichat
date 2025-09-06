#!/usr/bin/env python3
"""
Provision a new client (or update the shared Studio Flow).

- Loads the flow template (JSON) and injects API_BASE_URL + STUDIO_BEARER
- Creates OR updates the shared Studio Flow (controlled by --flow-action)
- Searches & buys a Twilio number
- Assigns VoiceUrl to the Studio Flow webhook
- Upserts DynamoDB clients & phone_routes

Usage:
  export API_BASE_URL=$(terraform output -raw api_base_url)
  export NAME_PREFIX=$(terraform output -raw name_prefix)
  python scripts/provision_client.py \
    --client-id acme-hvac \
    --display-name "ACME HVAC" \
    --area-code 973 \
    --forward-to +15556667777 \
    --flow-action upsert

Notes:
- Twilio credentials + Studio bearer are read from AWS Secrets Manager:
    {NAME_PREFIX}/twilio_account_sid
    {NAME_PREFIX}/twilio_auth_token
    {NAME_PREFIX}/studio_bearer
- flow FriendlyName defaults to:  "{NAME_PREFIX}-missed-call"
"""
import argparse, json, os, sys, time
from pathlib import Path

import boto3, requests

def get_secret(arn: str) -> str:
    print(f"Fetching secret from ARN: {arn}", file=sys.stdout)
    sm = boto3.client("secretsmanager")
    return sm.get_secret_value(SecretId=arn)["SecretString"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--display-name", required=True)
    ap.add_argument("--area-code", type=int, required=True)
    ap.add_argument("--country", default="US")
    ap.add_argument("--forward-to", required=True, help="Client's real phone to forward calls to")
    ap.add_argument("--flow-template", default="twilio/flow_missed_call.template.json")
    args = ap.parse_args()

    # Terraform outputs to compose URLs
    # cf = boto3.client("cloudformation")  # optional if using CF; else get from 'terraform output'
    # We'll rely on env vars for simplicity:
    API_BASE = os.environ.get("API_BASE_URL")  # e.g., https://{rest_id}.execute-api.{region}.amazonaws.com/v1
    if not API_BASE:
        print("Set API_BASE_URL env to your API Gateway stage URL (…/v1)", file=sys.stderr); sys.exit(2)

    # Secrets
    print("Fetching secrets...", file=sys.stdout)
    region = os.environ.get("AWS_REGION","us-east-1")
    name_prefix = os.environ.get("NAME_PREFIX","mc-multichat-dev")
    sid = get_secret(f"{name_prefix}/twilio_account_sid")
    tok = get_secret(f"{name_prefix}/twilio_auth_token")
    studio_bearer = get_secret(f"{name_prefix}/studio_bearer")
    # API key for Gateway
    apigw_api_key = os.environ.get("APIGW_API_KEY")
    if not apigw_api_key:
        print("Set APIGW_API_KEY env from `terraform output -raw api_key_value`", file=sys.stderr); sys.exit(2)

    # 1) Create/Update Studio Flow
    print("Creating/Updating Studio Flow...", file=sys.stdout)
    tmpl = json.loads(Path(args.flow_template).read_text())
    flow_def = json.dumps(tmpl).replace("{{API_BASE_URL}}", API_BASE)\
                               .replace("{{API_KEY}}", apigw_api_key)\
                               .replace("{{STUDIO_BEARER}}", studio_bearer)

    print("Flow definition: %s", json.dumps(flow_def,indent=4), file=sys.stdout)
    # Create flow
    flow_api = f"https://studio.twilio.com/v2/Flows"
    r = requests.post(flow_api, auth=(sid, tok), data={
        "FriendlyName": f"{name_prefix}-missed-call",
        "Status": "published",
        "Definition": flow_def,
    }, timeout=20)

    resp = json.loads(r.text);

    # print("Response message: %s", resp["message"], file=sys.stdout)
    # print("Response details: %s", json.dumps(resp["details"],indent=4), file=sys.stdout)

    if r.status_code == 409:
        # update existing (fetch FlowSid)
        print("Flow exists, updating...", file=sys.stdout)
        listr = requests.get(flow_api, auth=(sid,tok), params={"PageSize": 1, "FriendlyName": f"{name_prefix}-missed-call"})
        flow_sid = listr.json()["flows"][0]["sid"]
        upr = requests.post(f"{flow_api}/{flow_sid}", auth=(sid,tok), data={
            "Status": "published",
            "Definition": flow_def,
        }, timeout=20)
        upr.raise_for_status()
        flow_sid = upr.json()["sid"]
        print("Flow updated. %s", flow_sid, file=sys.stdout)
    else:
        r.raise_for_status()
        flow_sid = r.json()["sid"]
        print("Flow created. %s", flow_sid, file=sys.stdout)
    
    flow_webhook = f"https://webhooks.twilio.com/v1/Accounts/{sid}/Flows/{flow_sid}"

    # 2) Search & buy a number
    print("Searching & buying phone number...", file=sys.stdout)
    search = requests.get(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}/AvailablePhoneNumbers/{args.country}/Local.json",
        auth=(sid,tok), params={"AreaCode": args.area_code, "SmsEnabled": "true", "VoiceEnabled": "true"}, timeout=20
    ).json()
    cand = search["available_phone_numbers"][0]["phone_number"]
    print(f"Buying number: {cand}", file=sys.stdout);
    buy = requests.post(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}/IncomingPhoneNumbers.json",
        auth=(sid,tok),
        data={
            "PhoneNumber": cand,
            # Route voice directly to Studio Flow
            "VoiceUrl": flow_webhook,
            "VoiceMethod": "POST",
            # (Optional) You can set SmsUrl later when we wire SMS chat webhook.
        },
        timeout=20
    ).json()
    twilio_number = buy["phone_number"]

    # 3) Upsert DynamoDB rows
    print("Updating DynamoDB tables...", file=sys.stdout)
    ddb = boto3.client("dynamodb")
    clients_tbl = f"{name_prefix}-clients"
    phone_tbl   = f"{name_prefix}-phone-routes"
    ddb.put_item(
        TableName=clients_tbl,
        Item={
            "client_id": {"S": args.client_id},
            "display_name": {"S": args.display_name},
            "twilio_number_e164": {"S": twilio_number},
            "escalation_phone_e164": {"S": args.forward_to},
            "timezone": {"S": "America/New_York"}
        }
    )
    ddb.put_item(
        TableName=phone_tbl,
        Item={
            "phone_e164": {"S": twilio_number},
            "client_id": {"S": args.client_id}
        }
    )

    print(json.dumps({"ok": True, "client_id": args.client_id, "twilio_number": twilio_number, "flow_sid": flow_sid}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
