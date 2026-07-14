output "api_gateway_url" {
  description = "API Gateway invoke URL"
  value       = "${aws_api_gateway_deployment.main.invoke_url}${var.api_stage_name}/"
}

output "api_gateway_id" {
  description = "API Gateway REST API ID"
  value       = aws_api_gateway_rest_api.main.id
}

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.main.id
}

output "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN"
  value       = aws_cognito_user_pool.main.arn
}

output "cognito_app_client_id" {
  description = "Cognito App Client ID"
  value       = aws_cognito_user_pool_client.main.id
  sensitive   = true
}

output "cognito_domain" {
  description = "Cognito User Pool domain"
  value       = aws_cognito_user_pool_domain.main.domain
}

output "dynamodb_table_name" {
  description = "DynamoDB table name"
  value       = aws_dynamodb_table.main.name
}

output "dynamodb_table_arn" {
  description = "DynamoDB table ARN"
  value       = aws_dynamodb_table.main.arn
}

output "lambda_function_names" {
  description = "Lambda function names"
  value = {
    create_item = aws_lambda_function.create_item.function_name
    get_item    = aws_lambda_function.get_item.function_name
    list_items  = aws_lambda_function.list_items.function_name
    update_item = aws_lambda_function.update_item.function_name
    delete_item = aws_lambda_function.delete_item.function_name
  }
}

output "waf_web_acl_arn" {
  description = "WAF Web ACL ARN"
  value       = var.enable_waf ? aws_wafv2_web_acl.main[0].arn : null
}

output "waf_web_acl_id" {
  description = "WAF Web ACL ID"
  value       = var.enable_waf ? aws_wafv2_web_acl.main[0].id : null
}
