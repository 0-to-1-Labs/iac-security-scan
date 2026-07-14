variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "containerplatform"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}

variable "container_insights_enabled" {
  description = "Enable CloudWatch Container Insights for ECS cluster"
  type        = bool
  default     = true
}

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "webapp"
}

variable "app_image" {
  description = "Docker image for the application"
  type        = string
  default     = "nginx:latest"
}

variable "app_port" {
  description = "Port the application listens on"
  type        = number
  default     = 80
}

variable "app_cpu" {
  description = "CPU units for the application task (1024 = 1 vCPU)"
  type        = number
  default     = 512
}

variable "app_memory" {
  description = "Memory for the application task in MB"
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Desired number of tasks to run"
  type        = number
  default     = 2
}

variable "ecr_repositories" {
  description = "List of ECR repository names to create"
  type        = list(string)
  default     = ["webapp", "api", "worker"]
}

variable "alb_health_check_path" {
  description = "Health check path for ALB target group"
  type        = string
  default     = "/"
}

variable "service_discovery_namespace" {
  description = "Service discovery namespace"
  type        = string
  default     = "local"
}
