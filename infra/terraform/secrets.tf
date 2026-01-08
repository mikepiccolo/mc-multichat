# -- Create these manually in the AWS console for security reasons, or use Terraform if you prefer. ---
# resource "aws_secretsmanager_secret" "openai_api_key" {
#     name = "${local.name_prefix}/openai_api_key"
#     tags = local.tags
# }
#
# resource "aws_secretsmanager_secret" "twilio_auth_token" {
#     name = "${local.name_prefix}/twilio_auth_token"
#     tags = local.tags
# }


# Store RDS connection details as a JSON secret (dev convenience)

resource "aws_secretsmanager_secret" "rds_credentials" {
  name = "${local.name_prefix}/rds"
  tags = local.tags
}

resource "aws_secretsmanager_secret_version" "rds_credentials_v" {
  secret_id = aws_secretsmanager_secret.rds_credentials.id
  secret_string = jsonencode({
    host     = aws_db_instance.pg.address,
    port     = aws_db_instance.pg.port,
    dbname   = var.db_name,
    username = var.db_master_username,
    password = random_password.rds_master.result
  })

  depends_on = [aws_db_instance.pg]

  lifecycle {
    create_before_destroy = true
  }
}

# Twilio credentials
resource "aws_secretsmanager_secret" "twilio_account_sid" {
  name = "${local.name_prefix}/twilio_account_sid"
  tags = local.tags
}

# Shared Bearer token used by Studio HTTP Request -> our API
resource "aws_secretsmanager_secret" "studio_bearer" {
  name = "${local.name_prefix}/studio_bearer"
  tags = local.tags
}

# Will be set manually for security from Twilio console
# Generate a random bearer value for convenience (you can overwrite later)
#resource "random_password" "studio_bearer" {
#  length  = 48
#  special = false
#}

#resource "aws_secretsmanager_secret_version" "studio_bearer_v" {
#  secret_id     = aws_secretsmanager_secret.studio_bearer.id
#  secret_string = random_password.studio_bearer.result
#}
