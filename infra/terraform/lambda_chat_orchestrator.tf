# Package the chat_orchestrator Lambda
resource "null_resource" "chat_orchestrator_vendor" {
  triggers = {
    req_sha     = filesha1("${path.module}/../../services/chat_orchestrator/requirements.txt"),
    handler_sha = filesha1("${path.module}/../../services/chat_orchestrator/handler.py")
  }

  provisioner "local-exec" {
    command     = <<-EOT
      set -euo pipefail
      mkdir -p ${path.module}/../../services/chat_orchestrator/package
      cp ${path.module}/../../services/chat_orchestrator/handler.py ${path.module}/../../services/chat_orchestrator/package
      # clean common vendored dirs
      find ${path.module}/../../services/chat_orchestrator/package -maxdepth 1 -type d \( -name "requests*" -o -name "urllib3*" -o -name "certifi*" -o -name "charset_normalizer*" -o -name "idna*" \) -exec rm -rf {} + || true
      pip install -r ${path.module}/../../services/chat_orchestrator/requirements.txt -t ${path.module}/../../services/chat_orchestrator/package
    EOT
    interpreter = ["/bin/bash", "-c"]
  }
}

data "archive_file" "chat_orchestrator_zip" {
  depends_on  = [null_resource.chat_orchestrator_vendor]
  type        = "zip"
  source_dir  = "${path.module}/../../services/chat_orchestrator/package"
  output_path = "${local.artifacts_dir}/chat_orchestrator.zip"
}

resource "aws_lambda_function" "chat_orchestrator" {
  function_name    = "${local.name_prefix}-chat-orchestrator"
  role             = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.chat_orchestrator_zip.output_path
  source_code_hash = data.archive_file.chat_orchestrator_zip.output_base64sha256
  handler          = "handler.lambda_handler"
  runtime          = "python3.13"
  architectures    = ["arm64"]
  timeout          = 30

  environment {
    variables = {
      LOG_LEVEL            = var.log_level
      OPENAI_SECRET_ARN    = local.openai_api_key_arn # aws_secretsmanager_secret.openai_api_key.arn
      APIGW_KEY_SECRET_ARN = aws_secretsmanager_secret.apigw_api_key.arn
      API_REST_ID          = aws_api_gateway_rest_api.rest.id # OK to depend on Rest API
      API_STAGE_NAME       = var.api_stage                    # plain string (e.g., "v1")
      DDB_CLIENTS          = aws_dynamodb_table.clients.name
      DDB_CONVERSATIONS    = aws_dynamodb_table.conversations.name
      MODEL_NAME           = var.model_name
      MAX_TOOL_LOOPS       = var.max_tool_loops
      MAX_HISTORY_TURNS    = var.max_history_turns

      # --- Lead agent (preview) ---
      LEAD_MAX_QUESTIONS        = "3"     # max additional questions to ask
      LEAD_DEDUPE_MINUTES       = "120"   # dedupe window for repeated leads from same user
      LEAD_NOTIFY_CLIENT_SMS    = "true" # set "true" to allow SMS notify to client (uses Twilio creds)

      # --- Client notifications (now only SMS; more later) ---
      TWILIO_SID_ARN          = aws_secretsmanager_secret.twilio_account_sid.arn
      TWILIO_TOKEN_ARN        = local.twilio_auth_token_arn
    }
  }

  tags = local.tags
}
