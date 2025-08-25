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
}
