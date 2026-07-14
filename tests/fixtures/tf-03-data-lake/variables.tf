variable "aws_region" {
  description = "AWS region for data lake resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "datalake"
}

variable "owner_tag" {
  description = "Owner tag for resources"
  type        = string
  default     = "data-engineering-team"
}

variable "raw_zone_retention_days" {
  description = "Number of days to retain objects in raw zone before transitioning to IA"
  type        = number
  default     = 90
}

variable "processed_zone_retention_days" {
  description = "Number of days to retain objects in processed zone before transitioning to IA"
  type        = number
  default     = 180
}

variable "curated_zone_retention_days" {
  description = "Number of days to retain objects in curated zone before transitioning to IA"
  type        = number
  default     = 365
}

variable "glue_crawler_schedule" {
  description = "Cron expression for Glue crawler schedule"
  type        = string
  default     = "cron(0 2 * * ? *)" # Daily at 2 AM UTC
}

variable "athena_query_result_retention_days" {
  description = "Number of days to retain Athena query results"
  type        = number
  default     = 30
}

variable "enable_lake_formation" {
  description = "Enable AWS Lake Formation for fine-grained access control"
  type        = bool
  default     = true
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access Athena workgroup"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "data_classification" {
  description = "Data classification level"
  type        = string
  default     = "confidential"
}
