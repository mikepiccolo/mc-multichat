output "dynamodb_table_clients" {
    value = aws_dynamodb_table.clients.name
}

output "dynamodb_table_conversations" {
  value = aws_dynamodb_table.conversations.name
}

output "dynamodb_table_phone_routes" {
  value = aws_dynamodb_table.phone_routes.name
}
