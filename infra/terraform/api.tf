# API Gateway REST (v1) secured via API Key (Usage Plan)
#
#- Method requires API key
#
# - Minimal Usage Plan created and associated with stage
#
# - Default API key generated (Terraform) and attached to plan

resource "aws_api_gateway_rest_api" "rest" {
  name = "${local.name_prefix}-api"

  endpoint_configuration { types = ["REGIONAL"] }
  api_key_source = "HEADER"
  tags           = local.tags
}

# /health resource

resource "aws_api_gateway_resource" "health" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_rest_api.rest.root_resource_id
  path_part   = "health"
}

# Require API key (no IAM auth)

resource "aws_api_gateway_method" "health_get" {
  rest_api_id      = aws_api_gateway_rest_api.rest.id
  resource_id      = aws_api_gateway_resource.health.id
  http_method      = "GET"
  authorization    = "NONE"
  api_key_required = true
}

# Lambda proxy integration

resource "aws_api_gateway_integration" "health_get" {
  rest_api_id             = aws_api_gateway_rest_api.rest.id
  resource_id             = aws_api_gateway_resource.health.id
  http_method             = aws_api_gateway_method.health_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.health.invoke_arn
}

# Deploy and stage (var.api_stage)

resource "aws_api_gateway_deployment" "rest_deploy" {
  rest_api_id = aws_api_gateway_rest_api.rest.id

  triggers = {
    redeploy_hash = sha1(jsonencode({
      method      = aws_api_gateway_method.health_get.id,
      integration = aws_api_gateway_integration.health_get.id
    }))
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_api_gateway_stage" "stage" {
  rest_api_id   = aws_api_gateway_rest_api.rest.id
  deployment_id = aws_api_gateway_deployment.rest_deploy.id
  stage_name    = var.api_stage
  tags          = local.tags
}

# Allow API Gateway to invoke the Lambda

resource "aws_lambda_permission" "apigw_invoke_health" {
  statement_id  = "AllowInvokeByAPIGatewayRestHealth"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.health.arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.rest.execution_arn}/*/*/health"
}

# ---- API Key + Usage Plan ----

resource "random_password" "api_key" {
  length  = 40
  special = false
}

resource "aws_api_gateway_api_key" "default" {
  name        = "${local.name_prefix}-default-key"
  description = "Default API key for ${local.name_prefix}"
  enabled     = true
  value       = random_password.api_key.result
  tags        = local.tags
}

resource "aws_api_gateway_usage_plan" "default" {
  name = "${local.name_prefix}-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.rest.id
    stage  = aws_api_gateway_stage.stage.stage_name
  }

  tags = local.tags
}

resource "aws_api_gateway_usage_plan_key" "default" {
  key_id        = aws_api_gateway_api_key.default.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.default.id
}

output "api_base_url" {
  value = "https://${aws_api_gateway_rest_api.rest.id}.execute-api.${var.aws_region}.amazonaws.com/${aws_api_gateway_stage.stage.stage_name}"
}

output "health_url" {
  value = "https://${aws_api_gateway_rest_api.rest.id}.execute-api.${var.aws_region}.amazonaws.com/${aws_api_gateway_stage.stage.stage_name}/health"
}

output "rest_api_id" {
  value = aws_api_gateway_rest_api.rest.id
}

output "api_key_value" {
  value     = aws_api_gateway_api_key.default.value
  sensitive = true
}

output "api_key_id" {
  value = aws_api_gateway_api_key.default.id
}

resource "aws_cloudwatch_log_group" "api_gw" {
  name              = "/aws/apigateway/${aws_api_gateway_rest_api.rest.name}"
  retention_in_days = 14
  tags              = local.tags
}

