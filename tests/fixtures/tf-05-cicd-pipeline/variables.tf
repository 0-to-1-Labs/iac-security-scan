variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "myapp"
}

variable "repository_name" {
  description = "CodeCommit repository name"
  type        = string
  default     = "myapp-repo"
}

variable "repository_branch" {
  description = "Branch to use for pipeline"
  type        = string
  default     = "main"
}

variable "build_compute_type" {
  description = "CodeBuild compute type"
  type        = string
  default     = "BUILD_GENERAL1_SMALL"
}

variable "build_image" {
  description = "CodeBuild Docker image"
  type        = string
  default     = "aws/codebuild/standard:7.0"
}

variable "deployment_config_name" {
  description = "CodeDeploy deployment configuration"
  type        = string
  default     = "CodeDeployDefault.AllAtOnce"
}

variable "deployment_instances" {
  description = "EC2 instances to deploy to (by tag)"
  type = object({
    key   = string
    value = string
    type  = string
  })
  default = {
    key   = "Environment"
    value = "dev"
    type  = "KEY_AND_VALUE"
  }
}

variable "notification_email" {
  description = "Email address for pipeline notifications"
  type        = string
  default     = "devops@example.com"
}

variable "buildspec_path" {
  description = "Path to buildspec.yml in repository"
  type        = string
  default     = "buildspec.yml"
}

variable "artifact_retention_days" {
  description = "Number of days to retain artifacts"
  type        = number
  default     = 30
}

variable "enable_approval_stage" {
  description = "Enable manual approval before deploy"
  type        = bool
  default     = false
}
