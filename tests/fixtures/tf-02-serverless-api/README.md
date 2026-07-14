# Serverless API - Production Terraform Workload

This Terraform configuration deploys a production-grade serverless API using AWS services including API Gateway, Lambda, DynamoDB, Cognito, and WAF.

## Architecture

The infrastructure consists of:

- **API Gateway REST API** - Regional API with multiple endpoints for CRUD operations
- **Lambda Functions** (5 total) - Node.js 18.x runtime for business logic
  - `create-item` - POST /items
  - `get-item` - GET /items/{id}
  - `list-items` - GET /items
  - `update-item` - PUT /items/{id}
  - `delete-item` - DELETE /items/{id}
- **DynamoDB Table** - NoSQL database with GSIs for efficient queries
  - Primary key: `id` (hash), `created_at` (range)
  - GSIs: UserIndex, StatusIndex, CategoryIndex
  - Point-in-time recovery enabled
  - TTL enabled for automatic item expiration
  - DynamoDB Streams enabled
- **Cognito User Pool** - User authentication and authorization
  - Email-based authentication
  - Password policy enforcement
  - Advanced security mode enabled
  - Identity pool for federated access
- **CloudWatch Logs** - Centralized logging for all components
  - Lambda function logs (7-day retention)
  - API Gateway execution logs
  - WAF logs
- **X-Ray Tracing** - Distributed tracing for Lambda functions
- **WAF Web ACL** - API protection with managed rule sets
  - Rate limiting (2000 requests per 5 minutes)
  - AWS Managed Core Rule Set
  - Known Bad Inputs protection
  - SQL Injection protection
  - Geo-blocking (only US, CA, GB, DE, FR allowed)

## Files

- `main.tf` - Provider configuration and data sources
- `variables.tf` - Input variables with validation
- `outputs.tf` - Output values for API endpoints and resources
- `api-gateway.tf` - API Gateway REST API, resources, methods, integrations
- `lambda.tf` - Lambda functions and CloudWatch log groups
- `dynamodb.tf` - DynamoDB table with GSIs and alarms
- `cognito.tf` - Cognito User Pool, App Client, Identity Pool
- `iam.tf` - IAM roles and policies for Lambda execution
- `waf.tf` - WAF Web ACL with managed rules and logging
- `lambda_functions/` - Lambda function source code (Node.js)

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with appropriate credentials
- AWS account with sufficient permissions

## Usage

### Initialize Terraform

```bash
terraform init
```

### Plan the deployment

```bash
terraform plan
```

### Apply the configuration

```bash
terraform apply
```

### Destroy the infrastructure

```bash
terraform destroy
```

## Configuration

Key variables can be customized in `terraform.tfvars`:

```hcl
aws_region         = "us-east-1"
project_name       = "serverless-api"
environment        = "dev"
lambda_memory_size = 512
lambda_timeout     = 30
enable_waf         = true
waf_rate_limit     = 2000
```

## API Endpoints

After deployment, the API will be available at:

```
https://{api-id}.execute-api.{region}.amazonaws.com/v1/
```

Endpoints:
- `POST /items` - Create a new item (requires authentication)
- `GET /items` - List items (requires authentication)
  - Query parameters: `limit`, `status`, `category`
- `GET /items/{id}` - Get a specific item (requires authentication)
- `PUT /items/{id}` - Update an item (requires authentication)
- `DELETE /items/{id}` - Delete an item (requires authentication)

## Authentication

All API endpoints require authentication via Cognito User Pool. Clients must:

1. Sign up/sign in via Cognito User Pool
2. Obtain an ID token
3. Include the token in the `Authorization` header for API requests

## Security Features

- **Cognito Authentication** - All endpoints protected by Cognito authorizer
- **WAF Protection** - Rate limiting, SQL injection prevention, geo-blocking
- **CloudWatch Alarms** - Monitoring for DynamoDB throttling and WAF blocked requests
- **X-Ray Tracing** - Distributed tracing for performance monitoring
- **Encryption** - DynamoDB encryption at rest (AWS owned key)
- **IAM Least Privilege** - Lambda execution role with minimal required permissions
- **VPC** - Lambda functions can optionally be deployed in VPC (commented out)

## Monitoring

CloudWatch dashboards and alarms are configured for:

- DynamoDB read/write throttling
- WAF blocked requests
- Lambda function errors and duration
- API Gateway 4xx/5xx errors

## Costs

Estimated monthly costs (AWS us-east-1 region):

- Lambda: ~$0.20 per 1M requests (512MB, 30s timeout)
- DynamoDB: Pay-per-request pricing (~$1.25 per million writes, $0.25 per million reads)
- API Gateway: $3.50 per million requests
- Cognito: Free tier includes 50,000 MAUs
- WAF: $5.00 per Web ACL + $1.00 per rule + $0.60 per million requests
- CloudWatch Logs: $0.50 per GB ingested + $0.03 per GB stored

Total estimated cost for light usage: **$10-50/month**

## Embedded Security Flaws (For Testing)

This infrastructure intentionally contains the following security issues for testing security scanning tools:

1. **Overly Permissive IAM Policy** - Lambda execution role has `dynamodb:*` wildcard permissions instead of specific actions
2. **DynamoDB Encryption** - Table uses AWS owned key instead of customer-managed KMS key
3. **API Gateway Logging** - Access logging is not enabled on API Gateway stage
4. **Cognito MFA** - Multi-factor authentication is disabled (`mfa_configuration = "OFF"`)
5. **Lambda Environment Variables** - Sensitive values stored without KMS encryption

## License

This is a test workload for security scanning purposes.
