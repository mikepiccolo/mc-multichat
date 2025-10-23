# Vendor pure-Python deps for the Studio webhook handler
resource "null_resource" "twilio_sms_vendor" {
  triggers = {
    req_sha     = filesha1("${path.module}/../../services/twilio_sms/requirements.txt"),
    handler_sha = filesha1("${path.module}/../../services/twilio_sms/handler.py")
  }

  provisioner "local-exec" {
    command     = <<-EOT
      set -euo pipefail
      mkdir -p ${path.module}/../../services/twilio_sms/package
      cp ${path.module}/../../services/twilio_sms/handler.py ${path.module}/../../services/twilio_sms/package
      # clean common vendored dirs
      find ${path.module}/../../services/twilio_sms/package -maxdepth 1 -type d \( -name "requests*" -o -name "urllib3*" -o -name "certifi*" -o -name "charset_normalizer*" -o -name "idna*" \) -exec rm -rf {} + || true
      pip install -r ${path.module}/../../services/twilio_sms/requirements.txt -t ${path.module}/../../services/twilio_sms/package
    EOT
    interpreter = ["/bin/bash", "-c"]
  }
}

# Package the twilio_sms Lambda
data "archive_file" "twilio_sms_zip" {
  depends_on  = [null_resource.twilio_sms_vendor]
  type        = "zip"
  source_dir  = "${path.module}/../../services/twilio_sms/package"
  output_path = "${local.artifacts_dir}/twilio_sms.zip"
}

resource "aws_lambda_function" "twilio_sms" {
  function_name    = "${local.name_prefix}-twilio-sms"
  role             = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.twilio_sms_zip.output_path
  handler          = "handler.lambda_handler"
  runtime          = "python3.13"
  architectures    = ["arm64"]
  source_code_hash = data.archive_file.twilio_sms_zip.output_base64sha256
  timeout          = 15

  environment {
    variables = {
      LOG_LEVEL         = var.log_level
      DDB_CLIENTS       = aws_dynamodb_table.clients.name
      DDB_PHONE_ROUTES  = aws_dynamodb_table.phone_routes.name
      DDB_CONVERSATIONS = aws_dynamodb_table.conversations.name
      TWILIO_SID_ARN    = aws_secretsmanager_secret.twilio_account_sid.arn
      TWILIO_TOKEN_ARN  = local.twilio_auth_token_arn
    }
  }

  tags = local.tags
}

