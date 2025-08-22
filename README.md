# mc-multichat
This step deploys:

REST API (API Gateway v1) with GET /health → Lambda (Python 3.13), secured with API Key (Usage Plan).

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

# Print the URL and the generated API key value (sensitive)
terraform output -raw health_url
terraform output -raw api_key_value

# Call with x-api-key header
curl -s -H "x-api-key: $(terraform output -raw api_key_value)" \
  "$(terraform output -raw health_url)"

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