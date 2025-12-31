# Vendor pure-Python deps for the Studio webhook handler
resource "null_resource" "twilio_studio_vendor" {
  triggers = {
    req_sha = filesha1("${path.module}/../../services/twilio_studio/requirements.txt"),
    handler_sha = filesha1("${path.module}/../../services/twilio_studio/handler.py")
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail
      mkdir -p ${path.module}/../../services/twilio_studio/package
      cp ${path.module}/../../services/twilio_studio/handler.py ${path.module}/../../services/twilio_studio/package
      # clean common vendored dirs
      find ${path.module}/../../services/twilio_studio/package -maxdepth 1 -type d \( -name "requests*" -o -name "urllib3*" -o -name "certifi*" -o -name "charset_normalizer*" -o -name "idna*" \) -exec rm -rf {} + || true
      pip install -r ${path.module}/../../services/twilio_studio/requirements.txt -t ${path.module}/../../services/twilio_studio/package
    EOT
    interpreter = ["/bin/bash","-c"]
  }
}

data "archive_file" "twilio_studio_zip" {
  depends_on = [null_resource.twilio_studio_vendor]
  type        = "zip"
  source_dir  = "${path.module}/../../services/twilio_studio/package"
  output_path = "${local.artifacts_dir}/twilio_studio.zip"
}

resource "aws_lambda_function" "twilio_studio" {
  function_name = "${local.name_prefix}-twilio-studio"
  role          = aws_iam_role.lambda_exec.arn
  filename      = data.archive_file.twilio_studio_zip.output_path
  handler       = "handler.lambda_handler"
  runtime       = "python3.13"
  architectures = ["arm64"]
  source_code_hash = data.archive_file.twilio_studio_zip.output_base64sha256
  timeout = 30
  
  environment {
    variables = {
      API_STAGE          = var.api_stage
      RDS_SECRET_ARN     = aws_secretsmanager_secret.rds_credentials.arn
      OPENAI_SECRET_ARN  = local.openai_api_key_arn
      TWILIO_SID_ARN     = aws_secretsmanager_secret.twilio_account_sid.arn
      TWILIO_TOKEN_ARN   = local.twilio_auth_token_arn
      STUDIO_BEARER_ARN  = aws_secretsmanager_secret.studio_bearer.arn
      EMBED_DIM          = tostring(1536)
      LOG_LEVEL          = var.log_level
      TWILIO_SID_REQUIRED= tostring(var.twilio_sid_required)
      DDB_PHONE_ROUTES   = aws_dynamodb_table.phone_routes.name
      DDB_CLIENTS        = aws_dynamodb_table.clients.name
      DDB_CONVERSATIONS  = aws_dynamodb_table.conversations.name
      DEFAULT_GREETING_MESSAGE = var.default_greeting_message
      DEFAULT_CONSENT_MESSAGE = var.default_consent_message
      ORCHESTRATOR_FN    = aws_lambda_function.chat_orchestrator.function_name 
      AUTO_REPLY_COOLDOWN_MIN = "45"    # optional; we dedupe by CallSid anyway

    }
  }

  vpc_config {
    subnet_ids         = [for s in aws_subnet.private : s.id]
    security_group_ids = [aws_security_group.lambda.id]
  }
  
  tags = local.tags
}
