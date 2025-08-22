locals {
    name_prefix = "${var.project}-${var.env}"
    tags = {
        Project = var.project
        Env     = var.env
    }
}

data "aws_secretsmanager_secret" "openai_api_key" {
    name = "${local.name_prefix}/openai_api_key"
}
data "aws_secretsmanager_secret" "twilio_auth_token" {
    name = "${local.name_prefix}/twilio_auth_token"
}

#Lambda artifact path for local zips
locals {
    artifacts_dir = "${path.module}/.terraform/artifacts"
    openai_api_key_arn = data.aws_secretsmanager_secret.openai_api_key.arn
    twilio_auth_token_arn = data.aws_secretsmanager_secret.twilio_auth_token.arn
}

output "name_prefix" {
    value = local.name_prefix
}
