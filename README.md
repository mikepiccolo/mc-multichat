# mc-multichat
Multi‑Channel Chatbot — Step 1 (AWS + Terraform + Python 3.13)

This step deploys:

HTTP API (API Gateway v2) with GET /health → Lambda (Python 3.13)

DynamoDB tables: clients, conversations, phone-routes

Secrets Manager placeholders: openai_api_key, twilio_auth_token

Prereqs

Terraform >= 1.6

AWS CLI configured with permissions to create IAM, Lambda, API Gateway, DynamoDB, Secrets Manager

Deploy

cd infra/terraform
terraform init
terraform apply -auto-approve \
  -var "project=mc-multichat" \
  -var "env=dev" \
  -var "aws_region=us-east-1"

Test

# Print the health URL
terraform output -raw health_url
# Call it
curl -s $(terraform output -raw health_url) | jq .

Expected response:

{
  "ok": true,
  "service": "health",
  "ts": 1730000000,
  "region": "us-east-1",
  "runtime": "python3.13"
}

Seed a sample client (optional)

export CLIENTS_TBL=$(terraform output -raw dynamodb_table_clients)
aws dynamodb put-item \
  --table-name "$CLIENTS_TBL" \
  --item '{
    "client_id": {"S": "demo-realtor"},
    "display_name": {"S": "Sunrise Realty"},
    "timezone": {"S": "America/New_York"},
    "business_hours": {"S": "Mon-Fri 9:00-17:00"},
    "twilio_number_e164": {"S": "+15551234567"}
  }'

  