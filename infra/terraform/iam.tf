# Assume role policy for Lambda

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${local.name_prefix}-lambda-execute"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

# Inline policy: CloudWatch logs, DynamoDB access to our tables, SecretsManager read

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${local.name_prefix}-lambda-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # logs + dynamodb + secrets (existing)
      {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "dynamodb:PutItem","dynamodb:GetItem","dynamodb:UpdateItem",
          "dynamodb:Query","dynamodb:Scan","dynamodb:BatchWriteItem",
          "dynamodb:DeleteItem"
        ],
        "Resource": [
          aws_dynamodb_table.clients.arn,
          aws_dynamodb_table.conversations.arn,
          aws_dynamodb_table.phone_routes.arn
        ]
      },
      {
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue"],
        "Resource": [
          local.openai_api_key_arn,
          local.twilio_auth_token_arn,
          aws_secretsmanager_secret.twilio_account_sid.arn,
          aws_secretsmanager_secret.studio_bearer.arn,
          aws_secretsmanager_secret.rds_credentials.arn,
          aws_secretsmanager_secret.apigw_api_key.arn 
        ]
      },
      {
        Effect = "Allow",
        Action = ["lambda:InvokeFunction"],               # <-- allow inter-lambda calls (chat_orchestrator)
        Resource = "*"                                   # tighten later with specific ARNs after stabilization
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# --- RDS monitoring role for enhanced monitoring ---

data "aws_iam_policy_document" "rds_monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "${local.name_prefix}-rds-monitoring"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring_attach" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
