# ML Platform CloudFormation Workload

## Overview

This CloudFormation template deploys a production-grade Machine Learning platform on AWS using Amazon SageMaker, S3, VPC, and supporting services. The architecture is designed to support the complete ML lifecycle from data preparation and model training to deployment and monitoring.

## Architecture

### Core Components

1. **SageMaker Studio Domain**
   - Fully managed development environment for ML
   - IAM authentication mode
   - VPC-only network access for enhanced security
   - Integrated with KMS for encryption at rest

2. **SageMaker Notebook Instances**
   - Development notebook: Public subnet with internet access
   - Production notebook: Private subnet with VPC endpoints
   - Lifecycle configurations for automated setup
   - Custom kernel support

3. **Storage (S3)**
   - Training data bucket with versioning and lifecycle policies
   - Model artifacts bucket with tiered storage (S3 Standard -> IA -> Glacier)
   - Notebooks bucket for code and outputs
   - All buckets encrypted with KMS

4. **Network Infrastructure**
   - Custom VPC with public and private subnets across 2 AZs
   - NAT Gateways for private subnet internet access
   - VPC endpoints for SageMaker API and Runtime
   - S3 Gateway endpoint for efficient data access
   - Security groups with least-privilege access

5. **IAM Roles**
   - SageMaker execution role for training jobs and endpoints
   - SageMaker Studio role for user profiles
   - Scoped permissions for S3, KMS, CloudWatch, and ECR

6. **Encryption**
   - KMS customer-managed key for all data encryption
   - S3 bucket encryption at rest
   - CloudWatch Logs encryption
   - ECR repository encryption

7. **Monitoring & Logging**
   - CloudWatch Log Groups for SageMaker activities
   - CloudWatch Alarms for notebook instance health
   - SNS topic for notifications
   - Centralized logging for training jobs and endpoints

8. **Container Registry**
   - ECR repository for custom ML containers
   - Image scanning on push enabled
   - Lifecycle policies for image retention

9. **Source Control**
   - CodeCommit repository for ML code
   - Integrated with SageMaker notebooks

### Network Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         VPC (10.0.0.0/16)                   │
│                                                              │
│  ┌──────────────────────┐    ┌──────────────────────┐      │
│  │  Public Subnet 1     │    │  Public Subnet 2     │      │
│  │  (10.0.101.0/24)     │    │  (10.0.102.0/24)     │      │
│  │  ┌────────────────┐  │    │  ┌────────────────┐  │      │
│  │  │ NAT Gateway 1  │  │    │  │ NAT Gateway 2  │  │      │
│  │  └────────────────┘  │    │  └────────────────┘  │      │
│  │  ┌────────────────┐  │    │                      │      │
│  │  │ Dev Notebook   │  │    │                      │      │
│  │  │ (Internet)     │  │    │                      │      │
│  │  └────────────────┘  │    │                      │      │
│  └──────────────────────┘    └──────────────────────┘      │
│              │                          │                   │
│              │  Internet Gateway        │                   │
│              └──────────┬───────────────┘                   │
│                         │                                   │
│  ┌──────────────────────┐    ┌──────────────────────┐      │
│  │  Private Subnet 1    │    │  Private Subnet 2    │      │
│  │  (10.0.1.0/24)       │    │  (10.0.2.0/24)       │      │
│  │  ┌────────────────┐  │    │  ┌────────────────┐  │      │
│  │  │ Prod Notebook  │  │    │  │ SageMaker      │  │      │
│  │  └────────────────┘  │    │  │ Studio Domain  │  │      │
│  │  ┌────────────────┐  │    │  └────────────────┘  │      │
│  │  │ VPC Endpoints  │  │    │  ┌────────────────┐  │      │
│  │  │ (SageMaker)    │  │    │  │ VPC Endpoints  │  │      │
│  │  └────────────────┘  │    │  └────────────────┘  │      │
│  └──────────────────────┘    └──────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Deployment

### Prerequisites

- AWS CLI configured with appropriate credentials
- Permissions to create VPC, SageMaker, S3, IAM, and KMS resources
- Sufficient service quotas for SageMaker notebook instances

### Quick Deploy

```bash
# Deploy the stack
aws cloudformation create-stack \
  --stack-name ml-platform \
  --template-body file://template.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM

# Monitor deployment
aws cloudformation wait stack-create-complete \
  --stack-name ml-platform

# Get outputs
aws cloudformation describe-stacks \
  --stack-name ml-platform \
  --query 'Stacks[0].Outputs'
```

### Custom Deployment

You can override parameters during deployment:

```bash
aws cloudformation create-stack \
  --stack-name ml-platform-staging \
  --template-body file://template.yaml \
  --parameters \
    ParameterKey=EnvironmentName,ParameterValue=staging \
    ParameterKey=NotebookInstanceType,ParameterValue=ml.t3.large \
    ParameterKey=DataRetentionDays,ParameterValue=30 \
  --capabilities CAPABILITY_NAMED_IAM
```

### Update Stack

```bash
aws cloudformation update-stack \
  --stack-name ml-platform \
  --template-body file://template.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM
```

### Delete Stack

```bash
# Empty S3 buckets first
aws s3 rm s3://production-ml-training-data-<account-id> --recursive
aws s3 rm s3://production-ml-models-<account-id> --recursive
aws s3 rm s3://production-ml-notebooks-<account-id> --recursive

# Delete stack
aws cloudformation delete-stack --stack-name ml-platform
```

## Usage

### Accessing SageMaker Studio

1. Navigate to SageMaker in the AWS Console
2. Select "Domains" from the left menu
3. Click on the domain created by the stack
4. Select the "data-scientist" user profile
5. Click "Open Studio"

### Using Notebook Instances

#### Development Notebook

```bash
# Get notebook URL
aws sagemaker describe-notebook-instance \
  --notebook-instance-name production-dev-notebook \
  --query 'Url' --output text

# Start notebook if stopped
aws sagemaker start-notebook-instance \
  --notebook-instance-name production-dev-notebook

# Stop notebook
aws sagemaker stop-notebook-instance \
  --notebook-instance-name production-dev-notebook
```

#### Production Notebook

```bash
# Access through SageMaker console or AWS CLI
aws sagemaker create-presigned-notebook-instance-url \
  --notebook-instance-name production-prod-notebook
```

### Uploading Training Data

```bash
# Upload data to training bucket
aws s3 cp local-dataset/ \
  s3://production-ml-training-data-<account-id>/datasets/ \
  --recursive

# Upload to specific project folder
aws s3 cp data.csv \
  s3://production-ml-training-data-<account-id>/projects/project1/
```

### Running a Training Job

Example Python code in notebook:

```python
import sagemaker
from sagemaker.estimator import Estimator

# Get role and session
role = sagemaker.get_execution_role()
sess = sagemaker.Session()

# Define estimator
estimator = Estimator(
    image_uri='<ecr-uri>/ml-containers:latest',
    role=role,
    instance_count=1,
    instance_type='ml.m5.xlarge',
    output_path='s3://production-ml-models-<account-id>/outputs/',
    sagemaker_session=sess,
    encrypt_inter_container_traffic=True,
    enable_network_isolation=False
)

# Start training
estimator.fit({
    'training': 's3://production-ml-training-data-<account-id>/datasets/train',
    'validation': 's3://production-ml-training-data-<account-id>/datasets/val'
})
```

## Configuration

### Parameters

| Parameter | Description | Default | Allowed Values |
|-----------|-------------|---------|----------------|
| EnvironmentName | Environment tag | production | development, staging, production |
| VpcCIDR | VPC CIDR block | 10.0.0.0/16 | Valid CIDR |
| PrivateSubnet1CIDR | Private subnet 1 CIDR | 10.0.1.0/24 | Valid CIDR |
| PrivateSubnet2CIDR | Private subnet 2 CIDR | 10.0.2.0/24 | Valid CIDR |
| PublicSubnet1CIDR | Public subnet 1 CIDR | 10.0.101.0/24 | Valid CIDR |
| PublicSubnet2CIDR | Public subnet 2 CIDR | 10.0.102.0/24 | Valid CIDR |
| NotebookInstanceType | Instance type for notebooks | ml.t3.medium | ml.t3.*, ml.m5.* |
| DomainName | SageMaker Studio domain name | ml-platform-domain | String |
| DataRetentionDays | S3 lifecycle retention | 90 | Integer |

### Outputs

| Output | Description |
|--------|-------------|
| VPCId | VPC identifier |
| SageMakerDomainId | Studio domain ID |
| SageMakerDomainUrl | Studio access URL |
| TrainingDataBucketName | Training data S3 bucket |
| ModelArtifactsBucketName | Model storage S3 bucket |
| NotebooksBucketName | Notebooks S3 bucket |
| SageMakerExecutionRoleArn | Execution role ARN |
| DevelopmentNotebookInstanceName | Dev notebook name |
| ProductionNotebookInstanceName | Prod notebook name |
| MLEncryptionKeyId | KMS key ID |
| MLCodeRepositoryName | CodeCommit repo name |
| ECRRepositoryUri | Container registry URI |
| NotificationTopicArn | SNS topic ARN |

## Security Considerations

### Embedded Security Issues

This template intentionally contains security misconfigurations for testing purposes:

1. **Development Notebook Internet Access**
   - The development notebook instance has `DirectInternetAccess: Enabled`
   - Best Practice: Disable direct internet access and use VPC endpoints
   - Risk: Exposed to internet-based attacks, data exfiltration risk

2. **Model Artifacts Bucket Without Versioning**
   - The model artifacts bucket lacks versioning configuration
   - Best Practice: Enable versioning to protect against accidental deletion
   - Risk: Permanent data loss if models are accidentally deleted

3. **Overly Permissive S3 IAM Policy**
   - SageMaker execution role has `s3:*` permissions on buckets
   - Best Practice: Use least-privilege permissions (GetObject, PutObject, ListBucket)
   - Risk: Potential for unauthorized data access or deletion

4. **Root Access Enabled on Development Notebook**
   - Development notebook has `RootAccess: Enabled`
   - Best Practice: Disable root access to prevent unauthorized modifications
   - Risk: Users can install unauthorized software, modify security settings

5. **KMS Key Without Rotation**
   - The KMS encryption key doesn't have automatic rotation enabled
   - Best Practice: Enable automatic key rotation annually
   - Risk: Increased exposure window if key is compromised

### Security Best Practices

#### Recommendations for Production Use

1. **Network Security**
   - Use VPC-only mode for all SageMaker resources
   - Implement VPC endpoints for all AWS services
   - Enable VPC Flow Logs for network monitoring
   - Use private subnets for all compute resources

2. **Data Protection**
   - Enable S3 bucket versioning on all buckets
   - Implement S3 Object Lock for compliance requirements
   - Enable MFA Delete on critical buckets
   - Use S3 Access Points for fine-grained access control

3. **Identity & Access**
   - Implement least-privilege IAM policies
   - Use IAM roles instead of long-term credentials
   - Enable MFA for sensitive operations
   - Regular access reviews and credential rotation

4. **Encryption**
   - Enable KMS key rotation
   - Use separate keys for different data classifications
   - Encrypt all data in transit and at rest
   - Implement key usage auditing

5. **Monitoring & Compliance**
   - Enable AWS Config for compliance tracking
   - Configure CloudTrail for audit logging
   - Set up security monitoring with CloudWatch
   - Implement automated compliance checks

6. **Notebook Security**
   - Disable root access on all notebook instances
   - Disable direct internet access
   - Implement notebook lifecycle policies
   - Use IAM authentication for Studio

## Cost Optimization

### Estimated Monthly Costs (us-east-1)

| Resource | Configuration | Estimated Cost |
|----------|--------------|----------------|
| SageMaker Studio Domain | 1 domain + 1 user | $0 (pay-per-use) |
| Notebook Instances | 2 x ml.t3.medium (730 hrs) | ~$150 |
| NAT Gateways | 2 x NAT Gateway | ~$65 |
| S3 Storage | 100 GB (mixed tiers) | ~$2-5 |
| KMS | 1 key + API calls | ~$1 |
| VPC Endpoints | 3 endpoints | ~$22 |
| ECR Storage | 10 GB images | ~$1 |
| CloudWatch Logs | 10 GB/month | ~$5 |

**Total Estimated Cost: ~$246-250/month**

### Cost Reduction Strategies

1. **Stop notebook instances when not in use**
   ```bash
   aws sagemaker stop-notebook-instance \
     --notebook-instance-name production-dev-notebook
   ```

2. **Use lifecycle configurations for auto-stop**
   - Configure notebooks to auto-stop after idle period
   - Implement scheduled start/stop

3. **Optimize S3 storage**
   - Leverage lifecycle policies (already configured)
   - Use S3 Intelligent-Tiering for unpredictable access patterns
   - Clean up old training data regularly

4. **Right-size notebook instances**
   - Start with smaller instances (ml.t3.medium)
   - Scale up only when needed for training
   - Use on-demand for development, reserved for production

5. **Use Spot Instances for training**
   - Configure SageMaker training jobs to use managed spot training
   - Can reduce training costs by up to 90%

## Monitoring

### Key Metrics to Monitor

1. **SageMaker Notebook**
   - CPUUtilization
   - MemoryUtilization
   - DiskUtilization
   - NotebookInstanceStatusCheckFailed

2. **Training Jobs**
   - TrainingJobStatus
   - TrainingJobDuration
   - ResourceUtilization

3. **S3 Buckets**
   - BucketSizeBytes
   - NumberOfObjects
   - AllRequests
   - 4xxErrors

4. **KMS**
   - NumberOfApiCalls
   - KeyAge
   - EncryptionDuration

### CloudWatch Dashboard

Create a custom dashboard:

```bash
aws cloudwatch put-dashboard \
  --dashboard-name ml-platform-monitoring \
  --dashboard-body file://dashboard-config.json
```

## Troubleshooting

### Common Issues

1. **Stack creation fails with "Insufficient capacity"**
   - Try a different availability zone
   - Change notebook instance type
   - Check service quotas

2. **Cannot access Studio domain**
   - Verify IAM permissions
   - Check VPC security group rules
   - Ensure VPC endpoints are active

3. **Training job fails with S3 access denied**
   - Verify execution role permissions
   - Check S3 bucket policies
   - Ensure KMS key permissions

4. **VPC endpoint connection issues**
   - Verify security group allows HTTPS (443)
   - Check route table configurations
   - Ensure DNS resolution is enabled

### Debug Commands

```bash
# Check stack status
aws cloudformation describe-stack-events \
  --stack-name ml-platform \
  --max-items 20

# Verify SageMaker resources
aws sagemaker list-notebook-instances
aws sagemaker list-domains

# Check S3 buckets
aws s3 ls | grep ml

# Test KMS key
aws kms describe-key --key-id <key-id>

# Verify VPC endpoints
aws ec2 describe-vpc-endpoints \
  --filters Name=vpc-id,Values=<vpc-id>
```

## References

- [Amazon SageMaker Documentation](https://docs.aws.amazon.com/sagemaker/)
- [SageMaker Studio Documentation](https://docs.aws.amazon.com/sagemaker/latest/dg/studio.html)
- [SageMaker Security Best Practices](https://docs.aws.amazon.com/sagemaker/latest/dg/security.html)
- [AWS CloudFormation Best Practices](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html)

## License

This template is provided as-is for testing and educational purposes.
