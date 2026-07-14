# InfraBot Test Data - Embedded Security Flaws

This document catalogs all intentionally embedded security flaws across the 15 test workloads. These flaws are designed to be **detectable but not obvious** - they represent common real-world misconfigurations that security scanning tools should identify.

> **WARNING**: This document is for testing purposes only. Do NOT use these patterns in production environments.

---

## Summary Statistics

| Category | Total Flaws | Critical | High | Medium | Low |
|----------|-------------|----------|------|--------|-----|
| Terraform | 25 | 3 | 10 | 9 | 3 |
| CloudFormation | 25 | 4 | 11 | 7 | 3 |
| CDK | 25 | 5 | 10 | 8 | 2 |
| **Total** | **75** | **12** | **31** | **24** | **8** |

---

## Terraform Workloads (5)

### TF-01: Three-Tier Web Application

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | RDS instance without storage encryption | HIGH | 2.3.1 | rds_instance_storage_encrypted | `rds.tf` |
| 2 | EC2 instances without IMDSv2 enforcement | HIGH | 5.6 | ec2_instance_metadata_service_v2 | `asg.tf` |
| 3 | ALB access logging disabled | MEDIUM | 3.1 | elbv2_logging_enabled | `alb.tf` |
| 4 | Security group allowing 0.0.0.0/0 on port 443 | LOW | 5.2 | ec2_securitygroup_allow_ingress_from_internet | `security-groups.tf` |
| 5 | RDS without deletion protection | MEDIUM | 2.3 | rds_instance_deletion_protection | `rds.tf` |

**Detection Difficulty**: Medium - Flaws are spread across multiple files and some rely on omission rather than explicit misconfiguration.

---

### TF-02: Serverless API Platform

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | Lambda execution role with overly permissive DynamoDB policy (dynamodb:*) | HIGH | 1.16 | iam_policy_no_statements_with_admin_access | `iam.tf` |
| 2 | DynamoDB without customer-managed KMS encryption | MEDIUM | 2.3 | dynamodb_tables_kms_cmk_encryption_enabled | `dynamodb.tf` |
| 3 | API Gateway without access logging | MEDIUM | 3.1 | apigateway_restapi_logging_enabled | `api-gateway.tf` |
| 4 | Cognito user pool without MFA enforcement | HIGH | 1.2 | cognito_user_pool_mfa_enabled | `cognito.tf` |
| 5 | Lambda environment variables without KMS encryption | MEDIUM | 2.3 | lambda_function_not_using_kms_cmk | `lambda.tf` |

**Detection Difficulty**: Medium - IAM overly permissive policies require understanding of least privilege principles.

---

### TF-03: Data Lake Platform

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | S3 bucket using AES256 instead of aws:kms CMK | MEDIUM | 2.1.1 | s3_bucket_default_encryption_kms | `s3.tf` |
| 2 | S3 bucket without access logging | MEDIUM | 3.1 | s3_bucket_logging_enabled | `s3.tf` |
| 3 | Glue job with overly permissive IAM role (s3:* on all resources) | HIGH | 1.16 | iam_policy_no_statements_with_full_access | `iam.tf` |
| 4 | S3 raw zone bucket without versioning | MEDIUM | 2.1.3 | s3_bucket_versioning_enabled | `s3.tf` |
| 5 | Athena workgroup without query result encryption | MEDIUM | 2.3 | athena_workgroup_encryption_enabled | `athena.tf` |

**Detection Difficulty**: Medium - S3 encryption flaw is subtle (AES256 vs KMS CMK).

---

### TF-04: Container Platform (ECS Fargate)

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | ECR repository without image scanning on push | MEDIUM | 5.1 | ecr_repositories_scan_images_on_push_enabled | `ecr.tf` |
| 2 | ECS task definition without read-only root filesystem | MEDIUM | 5.12 | ecs_task_definitions_readonly_root_filesystem | `services.tf` |
| 3 | Task execution role with overly permissive Secrets Manager access | HIGH | 1.16 | iam_policy_no_statements_with_full_access | `iam.tf` |
| 4 | ALB not configured with drop_invalid_header_fields | LOW | 9.2 | elbv2_drop_invalid_header_fields_enabled | `alb.tf` |
| 5 | CloudWatch log group without KMS encryption | MEDIUM | 2.3 | cloudwatch_log_group_kms_encryption_enabled | `cloudwatch.tf` |

**Detection Difficulty**: Medium-High - Container security settings require specialized knowledge.

---

### TF-05: CI/CD Pipeline

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | CodeBuild project with privileged mode enabled unnecessarily | HIGH | 5.4 | codebuild_project_privileged_mode_disabled | `codebuild.tf` |
| 2 | S3 artifact bucket without versioning | MEDIUM | 2.1.3 | s3_bucket_versioning_enabled | `s3.tf` |
| 3 | CodeBuild environment variables with plaintext secrets | CRITICAL | 2.1 | codebuild_project_plaintext_credentials | `codebuild.tf` |
| 4 | Pipeline IAM role with overly broad permissions | HIGH | 1.16 | iam_policy_no_statements_with_full_access | `iam.tf` |
| 5 | SNS topic without server-side encryption | MEDIUM | 2.3 | sns_topics_kms_encryption_at_rest_enabled | `sns.tf` |

**Detection Difficulty**: High - CI/CD misconfigurations often require understanding of the entire pipeline.

---

## CloudFormation Workloads (5)

### CFN-01: WordPress on EC2/RDS

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | RDS instance publicly accessible | CRITICAL | 2.3.3 | rds_instance_publicly_accessible | `template.yaml` |
| 2 | EC2 security group with SSH (port 22) open to 0.0.0.0/0 | CRITICAL | 5.2.2 | ec2_securitygroup_allow_ssh_from_internet | `template.yaml` |
| 3 | Database credentials as plaintext parameters | CRITICAL | 2.1 | cloudformation_template_hardcoded_credentials | `template.yaml` |
| 4 | EBS volumes without encryption | HIGH | 2.2.1 | ec2_ebs_volume_encryption_enabled | `template.yaml` |
| 5 | ALB HTTP listener without HTTPS redirect | MEDIUM | 9.1 | elbv2_listener_ssl_policy | `template.yaml` |

**Detection Difficulty**: Low-Medium - Some flaws are obvious (SSH open), others require parameter inspection.

---

### CFN-02: ML Platform (SageMaker)

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | SageMaker notebook with direct internet access | HIGH | 5.1 | sagemaker_notebook_instance_without_direct_internet_access | `template.yaml` |
| 2 | S3 model bucket without versioning | MEDIUM | 2.1.3 | s3_bucket_versioning_enabled | `template.yaml` |
| 3 | SageMaker execution role with overly permissive S3 access | HIGH | 1.16 | iam_policy_no_statements_with_full_access | `template.yaml` |
| 4 | Notebook instance with root access enabled | HIGH | 5.3 | sagemaker_notebook_instance_root_access_disabled | `template.yaml` |
| 5 | KMS key without automatic rotation | MEDIUM | 2.8 | kms_cmk_rotation_enabled | `template.yaml` |

**Detection Difficulty**: Medium - SageMaker-specific checks require specialized scanning.

---

### CFN-03: IoT Data Ingestion

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | IoT policy with overly permissive actions (iot:*) | HIGH | 1.16 | iot_policy_no_statements_with_wildcard_actions | `template.yaml` |
| 2 | Kinesis stream without server-side encryption | HIGH | 2.3 | kinesis_stream_encrypted_at_rest | `template.yaml` |
| 3 | S3 bucket without default encryption | HIGH | 2.1.1 | s3_bucket_default_encryption | `template.yaml` |
| 4 | Lambda function with overly permissive IAM role | HIGH | 1.16 | iam_policy_no_statements_with_full_access | `template.yaml` |
| 5 | Firehose delivery stream without S3 encryption | MEDIUM | 2.3 | firehose_delivery_stream_encrypted_at_rest | `template.yaml` |

**Detection Difficulty**: Medium - IoT policies require understanding of IoT-specific permissions.

---

### CFN-04: Event-Driven Architecture

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | SQS queue without server-side encryption | HIGH | 2.3 | sqs_queues_server_side_encryption_enabled | `template.yaml` |
| 2 | SQS queue without dead-letter queue | MEDIUM | 7.1 | sqs_queues_dlq_enabled | `template.yaml` |
| 3 | Lambda without reserved concurrency (DoS risk) | LOW | 6.1 | lambda_function_throttling_configured | `template.yaml` |
| 4 | SNS topic without server-side encryption | HIGH | 2.3 | sns_topics_kms_encryption_at_rest_enabled | `template.yaml` |
| 5 | EventBridge rule without DLQ for failed invocations | MEDIUM | 7.1 | eventbridge_rule_dlq_configured | `template.yaml` |

**Detection Difficulty**: Medium - Event-driven patterns have many components to check.

---

### CFN-05: Static Website (CloudFront/S3)

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | CloudFront with minimum TLS version TLSv1 (not TLSv1.2) | HIGH | 9.1 | cloudfront_distribution_minimum_tls_version | `template.yaml` |
| 2 | S3 bucket without access logging | MEDIUM | 3.1 | s3_bucket_logging_enabled | `template.yaml` |
| 3 | CloudFront distribution without access logging | MEDIUM | 3.1 | cloudfront_distribution_logging_enabled | `template.yaml` |
| 4 | WAF WebACL missing comprehensive OWASP rules | MEDIUM | 9.3 | waf_webacl_rule_count | `template.yaml` |
| 5 | S3 bucket with public read access (no OAI restriction) | CRITICAL | 2.1.5 | s3_bucket_public_access | `template.yaml` |

**Detection Difficulty**: Medium - CloudFront TLS settings are often overlooked.

---

## CDK Workloads (5)

### CDK-01: EKS Kubernetes Platform

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | EKS cluster public endpoint with 0.0.0.0/0 access | CRITICAL | 5.4.1 | eks_cluster_endpoint_public_access | `lib/eks-stack.ts` |
| 2 | EKS without envelope encryption for secrets | HIGH | 2.3 | eks_cluster_secrets_encryption_enabled | `lib/eks-stack.ts` |
| 3 | Node group with SSH open to 0.0.0.0/0 | CRITICAL | 5.2.2 | eks_nodegroup_ssh_access | `lib/eks-stack.ts` |
| 4 | ECR repository without image scanning | MEDIUM | 5.1 | ecr_repositories_scan_images_on_push_enabled | `lib/ecr-stack.ts` |
| 5 | EKS cluster logging disabled (api, audit, authenticator) | HIGH | 3.1 | eks_cluster_logging_enabled | `lib/eks-stack.ts` |

**Detection Difficulty**: High - EKS security requires deep Kubernetes knowledge.

---

### CDK-02: Real-Time Analytics (OpenSearch/Kinesis)

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | OpenSearch domain with public access (not in VPC) | CRITICAL | 5.1 | opensearch_domain_vpc_enabled | `lib/search-stack.ts` |
| 2 | OpenSearch without node-to-node encryption | HIGH | 2.3 | opensearch_domain_node_to_node_encryption_enabled | `lib/search-stack.ts` |
| 3 | Kinesis stream without KMS CMK encryption | MEDIUM | 2.3 | kinesis_stream_encrypted_with_cmk | `lib/ingestion-stack.ts` |
| 4 | Lambda with overly permissive OpenSearch access | HIGH | 1.16 | iam_policy_no_statements_with_full_access | `lib/processing-stack.ts` |
| 5 | API Gateway without authorization | HIGH | 1.11 | apigateway_rest_api_authorizers_configured | `lib/api-stack.ts` |

**Detection Difficulty**: High - OpenSearch security configuration is complex.

---

### CDK-03: Multi-Region Disaster Recovery

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | S3 bucket without versioning (breaks CRR) | HIGH | 2.1.3 | s3_bucket_versioning_enabled | `lib/storage-stack.ts` |
| 2 | S3 cross-region replication without encryption | HIGH | 2.3 | s3_bucket_replication_encryption_enabled | `lib/storage-stack.ts` |
| 3 | DynamoDB without point-in-time recovery | HIGH | 2.3.2 | dynamodb_table_pitr_enabled | `lib/database-stack.ts` |
| 4 | SNS topic without server-side encryption | HIGH | 2.3 | sns_topics_kms_encryption_at_rest_enabled | `lib/monitoring-stack.ts` |
| 5 | Route 53 health check using HTTP instead of HTTPS | MEDIUM | 9.1 | route53_health_check_https_enabled | `lib/dns-stack.ts` |

**Detection Difficulty**: Medium-High - DR patterns have subtle security requirements.

---

### CDK-04: Microservices Mesh (App Mesh/ECS)

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | App Mesh virtual node without TLS enforcement | HIGH | 9.1 | appmesh_virtual_node_tls_enabled | `lib/mesh-stack.ts` |
| 2 | ECS task definition without read-only root filesystem | MEDIUM | 5.12 | ecs_task_definitions_readonly_root_filesystem | `lib/services-stack.ts` |
| 3 | Service mesh with TLS mode PERMISSIVE (not STRICT) | HIGH | 9.1 | appmesh_virtual_node_mtls_enabled | `lib/mesh-stack.ts` |
| 4 | X-Ray daemon with overly permissive IAM role | MEDIUM | 1.16 | iam_policy_no_statements_with_full_access | `lib/observability-stack.ts` |
| 5 | CloudWatch log group without KMS encryption | MEDIUM | 2.3 | cloudwatch_log_group_kms_encryption_enabled | `lib/observability-stack.ts` |

**Detection Difficulty**: High - Service mesh security is an advanced topic.

---

### CDK-05: Batch Processing (AWS Batch/Step Functions)

| # | Flaw | Severity | CIS Control | Prowler Check | Location |
|---|------|----------|-------------|---------------|----------|
| 1 | Batch compute environment with unencrypted EBS | HIGH | 2.2.1 | ec2_ebs_volume_encryption_enabled | `lib/batch-stack.ts` |
| 2 | Batch job role with overly permissive S3 access (s3:*) | HIGH | 1.16 | iam_policy_no_statements_with_full_access | `lib/batch-stack.ts` |
| 3 | S3 bucket without KMS CMK encryption | MEDIUM | 2.1.1 | s3_bucket_default_encryption_kms | `lib/storage-stack.ts` |
| 4 | Step Functions without CloudWatch logging | MEDIUM | 3.1 | stepfunctions_state_machine_logging_enabled | `lib/workflow-stack.ts` |
| 5 | EventBridge rule without DLQ | MEDIUM | 7.1 | eventbridge_rule_dlq_configured | `lib/scheduling-stack.ts` |

**Detection Difficulty**: Medium - Batch processing security is often overlooked.

---

## Security Flaw Categories

### By CIS Control Category

| CIS Control | Count | Description |
|-------------|-------|-------------|
| 1.x (IAM) | 15 | Identity and Access Management |
| 2.x (Storage/Encryption) | 35 | Encryption at rest and storage security |
| 3.x (Logging) | 12 | Logging and monitoring |
| 5.x (Networking) | 8 | Network security and access controls |
| 7.x (Resilience) | 3 | Error handling and resilience |
| 9.x (Data Protection) | 2 | Data protection in transit |

### By AWS Service

| Service | Flaw Count |
|---------|------------|
| S3 | 14 |
| IAM | 12 |
| RDS/DynamoDB | 7 |
| CloudWatch/Logging | 6 |
| ECS/EKS | 6 |
| Lambda | 5 |
| API Gateway | 4 |
| KMS | 4 |
| SNS/SQS | 5 |
| EC2/Security Groups | 5 |
| Other | 7 |

---

## Testing Recommendations

### For InfraBot Testing

1. **Run full scan** against each workload directory
2. **Verify detection rate** - aim for >90% flaw detection
3. **Check false positive rate** - valid configurations should not be flagged
4. **Test remediation generation** - ensure fixes are valid and address the flaws

### Expected Scan Results

```bash
# Example expected output for tf-01-three-tier-webapp
infrabot scan --path test-data/tf-01-three-tier-webapp --format json

Expected findings:
- rds_instance_storage_encrypted: FAIL
- ec2_instance_metadata_service_v2: FAIL
- elbv2_logging_enabled: FAIL
- ec2_securitygroup_allow_ingress_from_internet: FAIL (LOW)
- rds_instance_deletion_protection: FAIL
```

### Validation Commands

```bash
# Terraform validation
cd test-data/tf-01-three-tier-webapp
terraform init
terraform validate

# CloudFormation validation
cd test-data/cfn-01-wordpress-ec2-rds
aws cloudformation validate-template --template-body file://template.yaml

# CDK validation
cd test-data/cdk-01-eks-platform
npm install
npx cdk synth
```

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2024-XX-XX | 1.0 | Initial creation with 75 embedded flaws |

---

*This document is auto-generated and maintained for InfraBot test data integrity.*
