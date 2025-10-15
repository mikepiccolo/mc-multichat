# """
# Provision a new client (or update the shared Studio Flow).

# Features:
# - --action {buy|attach|update|skip} controls phone nuumber action (skip)
# -    buy: purchase a new number in the specified area code and attach to the flow
# -    attach: attach an existing Twilio number (+E164) to the flow
# -    update: update client record only with twilio number.  No twilio action. 
# -    skip: no number action, no twilio action
# -
# - --client-template sets the client template path with DDB client details (default: config/client_pack.example.json)
# - --flow-friendly-name sets the Flow FriendlyName (default: '{NAME_PREFIX}-missed-call')
# - --area-code sets area code for new number purchase (default: 973)
# - --country country for phone number, default 'US'
# - --number sets existing Twilio number to attach or update (+E164)

# Env:
#   NAME_PREFIX    = mc-multichat-dev (terraform output -raw name_prefix)

# Secrets (AWS Secrets Manager):
#   {NAME_PREFIX}/twilio_account_sid
#   {NAME_PREFIX}/twilio_auth_token
#   {NAME_PREFIX}/studio_bearer

# Usage (upsert flow + buy number):
#   python scripts/provision_client.py \
#     --client-id demo-realtor \
#     --display-name "Sunrise Realty" \
#     --area-code 973 \
#     --forward-to +15557654321

# Flow-only update (no number ops):
#   python scripts/provision_client.py \
#     --client-id demo-realtor \
#     --display-name "Sunrise Realty" \
#     --area-code 973 \
#     --forward-to +15557654321 \
#     --flow-action update \
#     --skip-buy-number

# Attach an existing number:
#   python scripts/provision_client.py \
#     --client-id demo-realtor \
#     --display-name "Sunrise Realty" \
#     --area-code 973 \
#     --forward-to +15557654321 \
#     --flow-action skip \
#     --attach-number +15551234567
# """
export API_BASE_URL=$(terraform output -raw api_base_url)
export APIGW_API_KEY=$(terraform output -raw api_key_value)
export NAME_PREFIX=$(terraform output -raw name_prefix)
export TWILIO_ACCOUNT_SID=$(terraform output -raw twilio_account_sid_arn)
export TWILIO_AUTH_TOKEN=$(terraform output -raw twilio_auth_token_arn)
export STUDIO_BEARER=$(terraform output -raw twilio_studio_bearer_arn)

# python scripts/provision_client.py \
#   --client-id demo-realtor \
#   --display-name "Sunrise Realty" \
#   --area-code 862 \
#   --forward-to +12014106922 \
#   --flow-action "upsert" \
#   --skip-buy-number

python scripts/provision_client.py \
  --action update \
  --client-template config/client_pack.example.json \
  --area-code 862 \
#  --flow-friendly-name mc-multichat-dev-missed-call  \
