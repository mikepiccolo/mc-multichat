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


Step 2 — Postgres RDS + pgvector (dev sizing)

This step creates a PostgreSQL RDS instance (dev-friendly sizing), a security group, a subnet group, and a Secrets Manager secret with connection details. You’ll enable pgvector and load the base KB schema.

Deploy / Update

cd infra/terraform
# Override any of these for prod later: db_instance_class, db_publicly_accessible, db_multi_az, backup, engine version
terraform apply -auto-approve \
  -var "db_instance_class=db.t4g.micro" \
  -var "db_allocated_storage_gb=20" \
  -var "db_engine_version=16.3" \
  -var "db_publicly_accessible=true" \
  -var "db_backup_retention_days=0"

⚠️ Dev default allows 0.0.0.0/0 on port 5432. Tighten by setting:

terraform apply -auto-approve -var 'db_allow_cidrs=["YOUR.IP.ADDR.XX/32"]'

Get connection details from Secrets Manager

SECRET_ARN=$(terraform output -raw rds_secret_arn)
aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" \
  --query SecretString --output text | jq .

Enable pgvector & create schema (requires psql)

# Export env vars for psql from the secret
CREDS=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query SecretString --output text)
export PGHOST=$(echo "$CREDS" | jq -r .host)
export PGPORT=$(echo "$CREDS" | jq -r .port)
export PGDATABASE=$(echo "$CREDS" | jq -r .dbname)
export PGUSER=$(echo "$CREDS" | jq -r .username)
export PGPASSWORD=$(echo "$CREDS" | jq -r .password)

# 1) Create extension
psql -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS vector;"

# 2) Create base KB schema
psql -v ON_ERROR_STOP=1 -f ../../db/schema.sql

# 3) Verify
psql -c "\dx" | grep vector || echo "vector extension not found"


Step 2b — KB ingestion stub + search endpoint

This adds:

A local ingestion CLI (services/kb_ingest/ingest.py) to parse a URL or file, chunk, embed with OpenAI, and write rows into Postgres/pgvector.

A search Lambda (GET /kb/search) that embeds the query, runs a similarity search over kb.chunks, and returns top‑k results. Secured by API key.

1) Set your OpenAI key in Secrets Manager (one time)

# Use the same name_prefix output from Terraform
NAME_PREFIX=$(terraform output -raw name_prefix)
aws secretsmanager put-secret-value \
  --secret-id "$NAME_PREFIX/openai_api_key" \
  --secret-string "$OPENAI_API_KEY"

2) Deploy the search Lambda + API route

cd infra/terraform
terraform apply -auto-approve

3) Ingest content (dev/local)

# Install deps locally for the ingestion script
pip install -r services/kb_ingest/requirements.txt

# Fetch DB creds JSON
SECRET_ARN=$(terraform output -raw rds_secret_arn)
CREDS=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query SecretString --output text)
export PGHOST=$(echo "$CREDS" | jq -r .host)
export PGPORT=$(echo "$CREDS" | jq -r .port)
export PGDATABASE=$(echo "$CREDS" | jq -r .dbname)
export PGUSER=$(echo "$CREDS" | jq -r .username)
export PGPASSWORD=$(echo "$CREDS" | jq -r .password)

# Also make OPENAI key available for local CLI
export OPENAI_API_KEY=$(aws secretsmanager get-secret-value --secret-id "$(terraform output -raw name_prefix)/openai_api_key" --query SecretString --output text)

# Example: ingest a web FAQ for the demo-realtor tenant
python services/kb_ingest/ingest.py \
  --client-id demo-realtor \
  --source url --input https://example.com/faq \
  --title "Example FAQ" \
  --embed-dim 1536

4) Test search via API

API_KEY=$(terraform output -raw api_key_value)
SEARCH_URL="$(terraform output -raw api_base_url)/kb/search?q=how%20do%20I%20list%20my%20home&client_id=demo-realtor&k=5"

curl -s -H "x-api-key: $API_KEY" "$SEARCH_URL" | jq .

Expected (shape):
{
  "ok": true,
  "hits": [
    {"document_id": 1, "title": "Example FAQ", "uri": "https://example.com/faq", "score": 0.09, "snippet": "…"}
  ]
}