# Package the kb_search Lambda

resource "aws_cloudwatch_log_group" "lambda_kb_search" {
  name              = "/aws/lambda/${local.name_prefix}-kb-search"
  retention_in_days = 14
  tags              = local.tags
}

resource "null_resource" "package_lambda" {
  triggers = {
    requirements_hash = sha256(file("${path.module}/../../services/kb_search/requirements.txt"))
    handler_hash = sha256(file("${path.module}/../../services/kb_search/handler.py"))
  }

  provisioner "local-exec" {
    command = <<-EOT
          rm -Rf ${path.module}/../../services/kb_search/package/
          mkdir ${path.module}/../../services/kb_search/package/
          cp ${path.module}/../../services/kb_search/handler.py ${path.module}/../../services/kb_search/package/
          pip install -r ${path.module}/../../services/kb_search/requirements.txt -t ${path.module}/../../services/kb_search/package/
        EOT
  }
}

data "archive_file" "kb_search_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../services/kb_search/package"
  output_path = "${local.artifacts_dir}/kb_search.zip"
  depends_on = [ null_resource.package_lambda ]
}

resource "aws_lambda_function" "kb_search" {
  function_name    = "${local.name_prefix}-kb-search"
  role             = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.kb_search_zip.output_path
  handler          = "handler.lambda_handler"
  runtime          = "python3.13"
  architectures    = ["arm64"]
  source_code_hash = data.archive_file.kb_search_zip.output_base64sha256

  logging_config {
    log_group  = aws_cloudwatch_log_group.lambda_kb_search.name
    log_format = "JSON"
  }

  environment {
    variables = {
      RDS_SECRET_ARN    = aws_secretsmanager_secret.rds_credentials.arn
      OPENAI_SECRET_ARN = local.openai_api_key_arn
      EMBED_DIM         = tostring(1536)
      LOG_LEVEL         = "INFO"
    }
  }

  tags = local.tags
}
