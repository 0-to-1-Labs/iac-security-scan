variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource naming and tagging"
  type        = string
  default     = "serverless-api"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "api_stage_name" {
  description = "API Gateway deployment stage name"
  type        = string
  default     = "v1"
}

variable "lambda_runtime" {
  description = "Lambda function runtime"
  type        = string
  default     = "nodejs18.x"
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 512
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

variable "dynamodb_billing_mode" {
  description = "DynamoDB billing mode"
  type        = string
  default     = "PAY_PER_REQUEST"
}

variable "cognito_password_minimum_length" {
  description = "Minimum password length for Cognito users"
  type        = number
  default     = 12
}

variable "enable_waf" {
  description = "Enable WAF for API Gateway"
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "WAF rate limit for requests per 5 minutes"
  type        = number
  default     = 2000
}

variable "enable_xray_tracing" {
  description = "Enable X-Ray tracing for Lambda functions"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 7
}
