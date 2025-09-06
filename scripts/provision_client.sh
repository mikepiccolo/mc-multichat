export API_BASE_URL=$(terraform output -raw api_base_url)
export APIGW_API_KEY=$(terraform output -raw api_key_value)
export NAME_PREFIX=$(terraform output -raw name_prefix)
export TWILIO_ACCOUNT_SID=$(terraform output -raw twilio_account_sid_arn)
export TWILIO_AUTH_TOKEN=$(terraform output -raw twilio_auth_token_arn)
export STUDIO_BEARER=$(terraform output -raw twilio_studio_bearer_arn)

python scripts/provision_client.py \
  --client-id demo-realtor \
  --display-name "Sunrise Realty" \
  --area-code 862 \
  --forward-to +12014106922
