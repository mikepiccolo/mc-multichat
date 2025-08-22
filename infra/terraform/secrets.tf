# resource "aws_secretsmanager_secret" "openai_api_key" {
#     name = "${local.name_prefix}/openai_api_key"
#     tags = local.tags
# }
#
# resource "aws_secretsmanager_secret" "twilio_auth_token" {
#     name = "${local.name_prefix}/twilio_auth_token"
#     tags = local.tags
# }