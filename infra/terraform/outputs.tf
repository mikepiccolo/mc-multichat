output "dynamodb_table_clients" {
  value = aws_dynamodb_table.clients.name
}

output "dynamodb_table_conversations" {
  value = aws_dynamodb_table.conversations.name
}

output "dynamodb_table_phone_routes" {
  value = aws_dynamodb_table.phone_routes.name
}

# postgres outputs
output "rds_endpoint" {
  value = aws_db_instance.pg.address
}

output "rds_port" {
  value = aws_db_instance.pg.port
}

output "rds_db_name" {
  value = var.db_name
}

output "rds_secret_arn" {
  value = aws_secretsmanager_secret.rds_credentials.arn
}

output "twilio_account_sid_arn" {
  value = aws_secretsmanager_secret.twilio_account_sid.arn
}

output "twilio_studio_bearer_arn" {
  value = aws_secretsmanager_secret.studio_bearer.arn
}

output "twilio_auth_token_arn" {
  value = local.twilio_auth_token_arn
}