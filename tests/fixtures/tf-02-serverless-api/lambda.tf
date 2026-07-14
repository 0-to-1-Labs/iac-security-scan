# CloudWatch Log Groups for Lambda Functions
resource "aws_cloudwatch_log_group" "create_item" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}-create-item"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-${var.environment}-create-item-logs"
  }
}

resource "aws_cloudwatch_log_group" "get_item" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}-get-item"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-${var.environment}-get-item-logs"
  }
}

resource "aws_cloudwatch_log_group" "list_items" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}-list-items"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-${var.environment}-list-items-logs"
  }
}

resource "aws_cloudwatch_log_group" "update_item" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}-update-item"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-${var.environment}-update-item-logs"
  }
}

resource "aws_cloudwatch_log_group" "delete_item" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}-delete-item"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-${var.environment}-delete-item-logs"
  }
}

# Lambda function for creating items
resource "aws_lambda_function" "create_item" {
  filename         = data.archive_file.lambda_create_item.output_path
  function_name    = "${var.project_name}-${var.environment}-create-item"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.lambda_create_item.output_base64sha256
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout

  # SECURITY FLAW #5: Environment variables with sensitive values not encrypted with KMS
  # Database credentials and API keys are stored in plain text
  environment {
    variables = {
      TABLE_NAME        = aws_dynamodb_table.main.name
      REGION            = data.aws_region.current.name
      ENVIRONMENT       = var.environment
      DB_PASSWORD       = "super-secret-password-123"
      API_KEY           = "sk-prod-1234567890abcdef"
      ENCRYPTION_SECRET = "my-encryption-key-hardcoded"
    }
  }

  tracing_config {
    mode = var.enable_xray_tracing ? "Active" : "PassThrough"
  }

  depends_on = [
    aws_cloudwatch_log_group.create_item
  ]

  tags = {
    Name = "${var.project_name}-${var.environment}-create-item"
  }
}

# Lambda function for getting a single item
resource "aws_lambda_function" "get_item" {
  filename         = data.archive_file.lambda_get_item.output_path
  function_name    = "${var.project_name}-${var.environment}-get-item"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.lambda_get_item.output_base64sha256
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout

  environment {
    variables = {
      TABLE_NAME  = aws_dynamodb_table.main.name
      REGION      = data.aws_region.current.name
      ENVIRONMENT = var.environment
    }
  }

  tracing_config {
    mode = var.enable_xray_tracing ? "Active" : "PassThrough"
  }

  depends_on = [
    aws_cloudwatch_log_group.get_item
  ]

  tags = {
    Name = "${var.project_name}-${var.environment}-get-item"
  }
}

# Lambda function for listing items
resource "aws_lambda_function" "list_items" {
  filename         = data.archive_file.lambda_list_items.output_path
  function_name    = "${var.project_name}-${var.environment}-list-items"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.lambda_list_items.output_base64sha256
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout

  environment {
    variables = {
      TABLE_NAME  = aws_dynamodb_table.main.name
      REGION      = data.aws_region.current.name
      ENVIRONMENT = var.environment
    }
  }

  tracing_config {
    mode = var.enable_xray_tracing ? "Active" : "PassThrough"
  }

  depends_on = [
    aws_cloudwatch_log_group.list_items
  ]

  tags = {
    Name = "${var.project_name}-${var.environment}-list-items"
  }
}

# Lambda function for updating items
resource "aws_lambda_function" "update_item" {
  filename         = data.archive_file.lambda_update_item.output_path
  function_name    = "${var.project_name}-${var.environment}-update-item"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.lambda_update_item.output_base64sha256
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout

  environment {
    variables = {
      TABLE_NAME  = aws_dynamodb_table.main.name
      REGION      = data.aws_region.current.name
      ENVIRONMENT = var.environment
    }
  }

  tracing_config {
    mode = var.enable_xray_tracing ? "Active" : "PassThrough"
  }

  depends_on = [
    aws_cloudwatch_log_group.update_item
  ]

  tags = {
    Name = "${var.project_name}-${var.environment}-update-item"
  }
}

# Lambda function for deleting items
resource "aws_lambda_function" "delete_item" {
  filename         = data.archive_file.lambda_delete_item.output_path
  function_name    = "${var.project_name}-${var.environment}-delete-item"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.lambda_delete_item.output_base64sha256
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout

  environment {
    variables = {
      TABLE_NAME  = aws_dynamodb_table.main.name
      REGION      = data.aws_region.current.name
      ENVIRONMENT = var.environment
    }
  }

  tracing_config {
    mode = var.enable_xray_tracing ? "Active" : "PassThrough"
  }

  depends_on = [
    aws_cloudwatch_log_group.delete_item
  ]

  tags = {
    Name = "${var.project_name}-${var.environment}-delete-item"
  }
}

# Archive files for Lambda functions
data "archive_file" "lambda_create_item" {
  type        = "zip"
  output_path = "${path.module}/lambda_functions/create_item.zip"

  source {
    content  = file("${path.module}/lambda_functions/create_item.js")
    filename = "index.js"
  }
}

data "archive_file" "lambda_get_item" {
  type        = "zip"
  output_path = "${path.module}/lambda_functions/get_item.zip"

  source {
    content  = file("${path.module}/lambda_functions/get_item.js")
    filename = "index.js"
  }
}

data "archive_file" "lambda_list_items" {
  type        = "zip"
  output_path = "${path.module}/lambda_functions/list_items.zip"

  source {
    content  = file("${path.module}/lambda_functions/list_item.js")
    filename = "index.js"
  }
}

data "archive_file" "lambda_update_item" {
  type        = "zip"
  output_path = "${path.module}/lambda_functions/update_item.zip"

  source {
    content  = file("${path.module}/lambda_functions/update_item.js")
    filename = "index.js"
  }
}

data "archive_file" "lambda_delete_item" {
  type        = "zip"
  output_path = "${path.module}/lambda_functions/delete_item.zip"

  source {
    content  = file("${path.module}/lambda_functions/delete_item.js")
    filename = "index.js"
  }
}
