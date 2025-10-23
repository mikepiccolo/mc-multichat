# API Gateway REST (v1) secured via API Key (Usage Plan)
#
#- Method requires API key
#
# - Minimal Usage Plan created and associated with stage
#
# - Default API key generated (Terraform) and attached to plan
#resource "aws_api_gateway_account" "api_gateway_account" {
#  cloudwatch_role_arn = aws_iam_role.api_gateway_cloudwatch_role.arn
#}

resource "aws_api_gateway_rest_api" "rest" {
  name = "${local.name_prefix}-api"

  endpoint_configuration { types = ["REGIONAL"] }
  api_key_source = "HEADER"
  tags           = local.tags
}

resource "aws_cloudwatch_log_group" "api_gw" {
  name              = "/aws/apigateway/${aws_api_gateway_rest_api.rest.name}"
  retention_in_days = 14
  tags              = local.tags
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

# Allow API Gateway to invoke the Lambda

resource "aws_lambda_permission" "apigw_invoke_health" {
  statement_id  = "AllowInvokeByAPIGatewayRestHealth"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.health.arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.rest.execution_arn}/*/*"
}

# /kb/search route (GET)

resource "aws_api_gateway_resource" "kb" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_rest_api.rest.root_resource_id
  path_part   = "kb"
}

resource "aws_api_gateway_resource" "kb_search" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_resource.kb.id
  path_part   = "search"
}

resource "aws_api_gateway_method" "kb_search_get" {
  rest_api_id      = aws_api_gateway_rest_api.rest.id
  resource_id      = aws_api_gateway_resource.kb_search.id
  http_method      = "GET"
  authorization    = "NONE"
  api_key_required = true
}

resource "aws_api_gateway_integration" "kb_search_get" {
  rest_api_id             = aws_api_gateway_rest_api.rest.id
  resource_id             = aws_api_gateway_resource.kb_search.id
  http_method             = aws_api_gateway_method.kb_search_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.kb_search.invoke_arn
}

resource "aws_lambda_permission" "apigw_invoke_kb_search" {
  statement_id  = "AllowInvokeByAPIGatewayRestHealth"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.kb_search.arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.rest.execution_arn}/*/*"
}

# /twilio/studio routes (API key required)
resource "aws_api_gateway_resource" "twilio" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_rest_api.rest.root_resource_id
  path_part   = "twilio"
}

resource "aws_api_gateway_resource" "studio" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_resource.twilio.id
  path_part   = "studio"
}

# GET /twilio/studio/lookup
resource "aws_api_gateway_resource" "studio_lookup" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_resource.studio.id
  path_part   = "lookup"
}
resource "aws_api_gateway_method" "studio_lookup_get" {
  rest_api_id      = aws_api_gateway_rest_api.rest.id
  resource_id      = aws_api_gateway_resource.studio_lookup.id
  http_method      = "GET"
  authorization    = "NONE"
  api_key_required = false
}
resource "aws_api_gateway_integration" "studio_lookup_get" {
  rest_api_id             = aws_api_gateway_rest_api.rest.id
  resource_id             = aws_api_gateway_resource.studio_lookup.id
  http_method             = aws_api_gateway_method.studio_lookup_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.twilio_studio.invoke_arn
}

# POST /twilio/studio/voicemail
resource "aws_api_gateway_resource" "studio_voicemail" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_resource.studio.id
  path_part   = "voicemail"
}
resource "aws_api_gateway_method" "studio_voicemail_post" {
  rest_api_id      = aws_api_gateway_rest_api.rest.id
  resource_id      = aws_api_gateway_resource.studio_voicemail.id
  http_method      = "POST"
  authorization    = "NONE"
  api_key_required = false
}
resource "aws_api_gateway_integration" "studio_voicemail_post" {
  rest_api_id             = aws_api_gateway_rest_api.rest.id
  resource_id             = aws_api_gateway_resource.studio_voicemail.id
  http_method             = aws_api_gateway_method.studio_voicemail_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.twilio_studio.invoke_arn
}

# POST /twilio/studio/no-voicemail
resource "aws_api_gateway_resource" "studio_novoicemail" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_resource.studio.id
  path_part   = "no-voicemail"
}
resource "aws_api_gateway_method" "studio_novoicemail_post" {
  rest_api_id      = aws_api_gateway_rest_api.rest.id
  resource_id      = aws_api_gateway_resource.studio_novoicemail.id
  http_method      = "POST"
  authorization    = "NONE"
  api_key_required = false
}
resource "aws_api_gateway_integration" "studio_novoicemail_post" {
  rest_api_id             = aws_api_gateway_rest_api.rest.id
  resource_id             = aws_api_gateway_resource.studio_novoicemail.id
  http_method             = aws_api_gateway_method.studio_novoicemail_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.twilio_studio.invoke_arn
}

# POST /twilio/studio/consent
resource "aws_api_gateway_resource" "studio_consent" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_resource.studio.id
  path_part   = "consent"
}

resource "aws_api_gateway_method" "studio_consent_post" {
  rest_api_id      = aws_api_gateway_rest_api.rest.id
  resource_id      = aws_api_gateway_resource.studio_consent.id
  http_method      = "POST"
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "studio_consent_post" {
  rest_api_id             = aws_api_gateway_rest_api.rest.id
  resource_id             = aws_api_gateway_resource.studio_consent.id
  http_method             = aws_api_gateway_method.studio_consent_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.twilio_studio.invoke_arn
}

resource "aws_lambda_permission" "apigw_invoke_twilio_studio" {
  statement_id  = "AllowInvokeByAPIGatewayTwilioStudio"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.twilio_studio.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.rest.execution_arn}/*/*"
}

# Inbound SMS webhook: POST /twilio/sms/inbound
resource "aws_api_gateway_resource" "sms_root" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_resource.twilio.id
  path_part   = "sms"
}

resource "aws_api_gateway_resource" "sms_inbound" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_resource.sms_root.id
  path_part   = "inbound"
}

resource "aws_api_gateway_method" "sms_inbound_post" {
  rest_api_id      = aws_api_gateway_rest_api.rest.id
  resource_id      = aws_api_gateway_resource.sms_inbound.id
  http_method      = "POST"
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "sms_inbound_post" {
  rest_api_id             = aws_api_gateway_rest_api.rest.id
  resource_id             = aws_api_gateway_resource.sms_inbound.id
  http_method             = aws_api_gateway_method.sms_inbound_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.twilio_sms.invoke_arn
}

# Status callback webhook: POST /twilio/sms/status
resource "aws_api_gateway_resource" "sms_status" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  parent_id   = aws_api_gateway_resource.sms_root.id
  path_part   = "status"
}

resource "aws_api_gateway_method" "sms_status_post" {
  rest_api_id      = aws_api_gateway_rest_api.rest.id
  resource_id      = aws_api_gateway_resource.sms_status.id
  http_method      = "POST"
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "sms_status_post" {
  rest_api_id             = aws_api_gateway_rest_api.rest.id
  resource_id             = aws_api_gateway_resource.sms_status.id
  http_method             = aws_api_gateway_method.sms_status_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.twilio_sms.invoke_arn
}

# Allow API Gateway to invoke the Lambda
resource "aws_lambda_permission" "apigw_invoke_twilio_sms" {
  statement_id  = "AllowInvokeByAPIGatewayTwilioSMS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.twilio_sms.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.rest.execution_arn}/*/*"
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

# Redeploy to pick up the new routes
resource "aws_api_gateway_deployment" "rest_deploy" {
  rest_api_id = aws_api_gateway_rest_api.rest.id
  triggers = {
    redeploy_hash = sha1(jsonencode({
      health_method      = aws_api_gateway_method.health_get.id,
      health_integration = aws_api_gateway_integration.health_get.id,
      search_method      = aws_api_gateway_method.kb_search_get.id,
      search_integration = aws_api_gateway_integration.kb_search_get.id,
      lookup_method      = aws_api_gateway_method.studio_lookup_get.id,
      lookup_integration = aws_api_gateway_integration.studio_lookup_get.id,
      vm_method          = aws_api_gateway_method.studio_voicemail_post.id,
      vm_integration     = aws_api_gateway_integration.studio_voicemail_post.id,
      nvm_method         = aws_api_gateway_method.studio_novoicemail_post.id,
      nvm_integration    = aws_api_gateway_integration.studio_novoicemail_post.id
      consent_method     = aws_api_gateway_method.studio_consent_post.id,
      consent_integration= aws_api_gateway_integration.studio_consent_post.id
      inbound_method     = aws_api_gateway_method.sms_inbound_post.id,
      inbound_integ      = aws_api_gateway_integration.sms_inbound_post.id,
      status_method      = aws_api_gateway_method.sms_status_post.id,
      status_integ       = aws_api_gateway_integration.sms_status_post.id

    }))
  }
  lifecycle { create_before_destroy = true }
}

resource "aws_api_gateway_stage" "stage" {
  rest_api_id   = aws_api_gateway_rest_api.rest.id
  deployment_id = aws_api_gateway_deployment.rest_deploy.id
  stage_name    = var.api_stage

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw.arn
    format = jsonencode({ # Example JSON format for access logs
      requestId      = "$context.requestId",
      ip             = "$context.identity.sourceIp",
      httpMethod     = "$context.httpMethod",
      path           = "$context.path",
      status         = "$context.status",
      responseLength = "$context.responseLength"
    })
  }


  tags = local.tags
}
# Outputs
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
