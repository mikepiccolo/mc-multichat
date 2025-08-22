# Package the health Lambda from services/health

data "archive_file" "health_zip" {
    type        = "zip"
    source_dir  = "${path.module}/../../services/health"
    output_path = "${local.artifacts_dir}/health.zip"
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}-health"
  retention_in_days = 14
  tags              = local.tags
}

resource "aws_lambda_function" "health" {
    function_name = "${local.name_prefix}-health"
    role          = aws_iam_role.lambda_exec.arn
    filename      = data.archive_file.health_zip.output_path
    source_code_hash = data.archive_file.health_zip.output_base64sha256
    handler       = "handler.lambda_handler"
    runtime       = "python3.13"
    architectures = ["arm64"]
    
    logging_config {
      log_group = aws_cloudwatch_log_group.lambda.name
      log_format = "JSON"
    }

    environment {
        variables = {
            LOG_LEVEL = "INFO"
        }
    }

    tags = local.tags
}