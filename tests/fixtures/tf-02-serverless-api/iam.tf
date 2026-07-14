# IAM role for Lambda execution
resource "aws_iam_role" "lambda_exec" {
  name               = "${var.project_name}-${var.environment}-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Name = "${var.project_name}-${var.environment}-lambda-exec"
  }
}

# SECURITY FLAW #1: Overly permissive DynamoDB policy
# Using dynamodb:* instead of specific actions like PutItem, GetItem, Query, etc.
resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${var.project_name}-${var.environment}-lambda-dynamodb"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:*"  # SECURITY FLAW: Wildcard permissions on DynamoDB
        ]
        Resource = [
          aws_dynamodb_table.main.arn,
          "${aws_dynamodb_table.main.arn}/index/*"
        ]
      }
    ]
  })
}

# CloudWatch Logs policy for Lambda
resource "aws_iam_role_policy" "lambda_logs" {
  name = "${var.project_name}-${var.environment}-lambda-logs"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_name}-${var.environment}-*:*"
      }
    ]
  })
}

# X-Ray tracing policy for Lambda
resource "aws_iam_role_policy" "lambda_xray" {
  count = var.enable_xray_tracing ? 1 : 0

  name = "${var.project_name}-${var.environment}-lambda-xray"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      }
    ]
  })
}

# VPC execution policy (if Lambda needs VPC access in the future)
# Commented out for now as Lambda is not in VPC
# resource "aws_iam_role_policy_attachment" "lambda_vpc" {
#   role       = aws_iam_role.lambda_exec.name
#   policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
# }
