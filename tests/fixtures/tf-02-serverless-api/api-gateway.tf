# API Gateway REST API
resource "aws_api_gateway_rest_api" "main" {
  name        = "${var.project_name}-${var.environment}"
  description = "Serverless API for ${var.project_name} (${var.environment})"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  binary_media_types = ["application/octet-stream"]
}

# API Gateway Authorizer (Cognito)
resource "aws_api_gateway_authorizer" "cognito" {
  name            = "${var.project_name}-cognito-authorizer"
  rest_api_id     = aws_api_gateway_rest_api.main.id
  type            = "COGNITO_USER_POOLS"
  provider_arns   = [aws_cognito_user_pool.main.arn]
  identity_source = "method.request.header.Authorization"
}

# /items resource
resource "aws_api_gateway_resource" "items" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "items"
}

# /items/{id} resource
resource "aws_api_gateway_resource" "item" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.items.id
  path_part   = "{id}"
}

# POST /items - Create item
resource "aws_api_gateway_method" "create_item" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.items.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.header.Authorization" = true
  }
}

resource "aws_api_gateway_integration" "create_item" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.items.id
  http_method             = aws_api_gateway_method.create_item.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.create_item.invoke_arn
}

# GET /items - List items
resource "aws_api_gateway_method" "list_items" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.items.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.header.Authorization" = true
  }
}

resource "aws_api_gateway_integration" "list_items" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.items.id
  http_method             = aws_api_gateway_method.list_items.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.list_items.invoke_arn
}

# GET /items/{id} - Get item
resource "aws_api_gateway_method" "get_item" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.item.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.header.Authorization" = true
    "method.request.path.id"              = true
  }
}

resource "aws_api_gateway_integration" "get_item" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.item.id
  http_method             = aws_api_gateway_method.get_item.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.get_item.invoke_arn
}

# PUT /items/{id} - Update item
resource "aws_api_gateway_method" "update_item" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.item.id
  http_method   = "PUT"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.header.Authorization" = true
    "method.request.path.id"              = true
  }
}

resource "aws_api_gateway_integration" "update_item" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.item.id
  http_method             = aws_api_gateway_method.update_item.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.update_item.invoke_arn
}

# DELETE /items/{id} - Delete item
resource "aws_api_gateway_method" "delete_item" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.item.id
  http_method   = "DELETE"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.header.Authorization" = true
    "method.request.path.id"              = true
  }
}

resource "aws_api_gateway_integration" "delete_item" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.item.id
  http_method             = aws_api_gateway_method.delete_item.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.delete_item.invoke_arn
}

# API Gateway Deployment
resource "aws_api_gateway_deployment" "main" {
  rest_api_id = aws_api_gateway_rest_api.main.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.items.id,
      aws_api_gateway_resource.item.id,
      aws_api_gateway_method.create_item.id,
      aws_api_gateway_method.list_items.id,
      aws_api_gateway_method.get_item.id,
      aws_api_gateway_method.update_item.id,
      aws_api_gateway_method.delete_item.id,
      aws_api_gateway_integration.create_item.id,
      aws_api_gateway_integration.list_items.id,
      aws_api_gateway_integration.get_item.id,
      aws_api_gateway_integration.update_item.id,
      aws_api_gateway_integration.delete_item.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

# API Gateway Stage
resource "aws_api_gateway_stage" "main" {
  deployment_id = aws_api_gateway_deployment.main.id
  rest_api_id   = aws_api_gateway_rest_api.main.id
  stage_name    = var.api_stage_name

  # SECURITY FLAW #3: Access logging is NOT enabled (missing access_log_settings block)
  # This means API access patterns, errors, and security events are not logged

  xray_tracing_enabled = var.enable_xray_tracing

  variables = {
    environment = var.environment
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-stage"
  }
}

# API Gateway Method Settings
resource "aws_api_gateway_method_settings" "main" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  stage_name  = aws_api_gateway_stage.main.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled      = true
    logging_level        = "INFO"
    data_trace_enabled   = true
    throttling_burst_limit = 5000
    throttling_rate_limit  = 10000
  }
}

# WAF Association (if enabled)
resource "aws_wafv2_web_acl_association" "main" {
  count = var.enable_waf ? 1 : 0

  resource_arn = aws_api_gateway_stage.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main[0].arn

  depends_on = [
    aws_api_gateway_stage.main,
    aws_wafv2_web_acl.main
  ]
}

# Lambda Permissions for API Gateway
resource "aws_lambda_permission" "create_item" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.create_item.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "list_items" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.list_items.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "get_item" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.get_item.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "update_item" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.update_item.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "delete_item" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.delete_item.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}
