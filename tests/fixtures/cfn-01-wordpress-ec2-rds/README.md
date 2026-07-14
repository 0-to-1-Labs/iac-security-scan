# WordPress on EC2 with RDS - CloudFormation Template

## Overview

This CloudFormation template deploys a production-grade WordPress application on AWS using a highly available, scalable architecture. The infrastructure includes EC2 instances in an Auto Scaling Group behind an Application Load Balancer, with RDS MySQL for the database and EFS for shared file storage.

## Architecture Components

### Network Infrastructure
- **VPC**: Custom VPC with CIDR 10.0.0.0/16
- **Subnets**:
  - 2 Public Subnets (10.0.1.0/24, 10.0.2.0/24) across 2 Availability Zones
  - 2 Private Subnets (10.0.11.0/24, 10.0.12.0/24) across 2 Availability Zones
- **Internet Gateway**: For public internet access
- **NAT Gateway**: For private subnet outbound internet access
- **Route Tables**: Separate routing for public and private subnets

### Compute Resources
- **EC2 Instances**: WordPress application servers in private subnets
- **Auto Scaling Group**:
  - Min: 2 instances
  - Max: 6 instances
  - Desired: 2 instances
  - Health check via ALB
- **Launch Template**: Defines instance configuration with user data for WordPress installation

### Database
- **RDS MySQL 8.0.35**:
  - Multi-AZ deployment (Production environment)
  - Automated backups (7 days retention for Production)
  - CloudWatch Logs integration
  - Subnet group spanning multiple AZs

### Load Balancing
- **Application Load Balancer**:
  - Internet-facing in public subnets
  - HTTP listener on port 80
  - Health checks on /health.php
  - Target group with EC2 instances

### Storage
- **EFS File System**:
  - Shared storage for WordPress wp-content directory
  - Mounted on all EC2 instances
  - Encrypted at rest
  - Mount targets in private subnets

### Security
- **Security Groups**:
  - ALB SG: Allows HTTP/HTTPS from internet
  - WebServer SG: Allows traffic from ALB, SSH access
  - RDS SG: Allows MySQL from web servers
  - EFS SG: Allows NFS from web servers

### Monitoring & Auto Scaling
- **CloudWatch Alarms**:
  - High CPU utilization (>70%) → Scale up
  - Low CPU utilization (<30%) → Scale down
  - Unhealthy host count monitoring
  - Database connection monitoring
- **CloudWatch Agent**: Collects custom metrics and logs from EC2 instances
- **Auto Scaling Policies**: Dynamic scaling based on CPU metrics

### IAM
- **EC2 Instance Role**:
  - CloudWatch Agent permissions
  - Systems Manager permissions
  - EFS access permissions

## Deployment

### Prerequisites
1. AWS CLI configured with appropriate credentials
2. An existing EC2 key pair in your target region
3. Sufficient AWS service quotas for the resources

### Deploy the Stack

```bash
# Validate the template
aws cloudformation validate-template \
  --template-body file://template.yaml

# Create the stack
aws cloudformation create-stack \
  --stack-name wordpress-production \
  --template-body file://template.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_IAM \
  --region us-east-1

# Monitor stack creation
aws cloudformation describe-stack-events \
  --stack-name wordpress-production \
  --region us-east-1

# Wait for stack completion
aws cloudformation wait stack-create-complete \
  --stack-name wordpress-production \
  --region us-east-1
```

### Access the WordPress Site

After successful deployment:

```bash
# Get the ALB DNS name
aws cloudformation describe-stacks \
  --stack-name wordpress-production \
  --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerURL`].OutputValue' \
  --output text

# Open in browser
# http://<alb-dns-name>
```

## Parameters

| Parameter | Description | Default | Allowed Values |
|-----------|-------------|---------|----------------|
| EnvironmentName | Environment name for tagging | Production | Development, Staging, Production |
| KeyName | EC2 Key Pair name | - | Existing key pair name |
| InstanceType | EC2 instance type | t3.medium | t3.small, t3.medium, t3.large, m5.large, m5.xlarge |
| DBInstanceClass | RDS instance type | db.t3.medium | db.t3.small, db.t3.medium, db.t3.large, db.r5.large, db.r5.xlarge |
| DBName | Database name | wordpressdb | Alphanumeric string |
| DBUsername | Database admin username | wpdbadmin | Alphanumeric string |
| DBPassword | Database admin password | - | Min 8 chars, alphanumeric with special chars |
| MinSize | Min EC2 instances | 2 | Number |
| MaxSize | Max EC2 instances | 6 | Number |
| DesiredCapacity | Desired EC2 instances | 2 | Number |

## Outputs

| Output | Description |
|--------|-------------|
| LoadBalancerDNS | DNS name of the Application Load Balancer |
| LoadBalancerURL | Complete URL to access WordPress |
| DatabaseEndpoint | RDS MySQL endpoint address |
| DatabasePort | RDS MySQL port |
| EFSFileSystemId | EFS file system ID |
| VPCId | VPC ID |
| AutoScalingGroupName | Auto Scaling Group name |

## WordPress Installation

The CloudFormation template uses `AWS::CloudFormation::Init` metadata to automatically:

1. Install Apache, PHP, MySQL client, and required dependencies
2. Mount the EFS file system to `/var/www/html/wp-content`
3. Download and configure WordPress
4. Create database configuration with RDS endpoint
5. Set proper file permissions
6. Configure CloudWatch monitoring

The WordPress site will be accessible via the ALB URL after stack creation completes.

## Cost Considerations

Estimated monthly costs (us-east-1, Production environment):

- EC2 instances (2x t3.medium): ~$60
- RDS MySQL Multi-AZ (db.t3.medium): ~$120
- Application Load Balancer: ~$20
- NAT Gateway: ~$35
- EFS storage: Variable (first 50GB free tier eligible)
- Data transfer: Variable

**Total estimated**: ~$235-300/month (excluding data transfer and beyond free tier)

## Intentional Security Flaws

**WARNING**: This template contains intentional security vulnerabilities for testing and educational purposes. **DO NOT** deploy this in a production environment without addressing these issues.

### Security Flaw #1: Publicly Accessible RDS Instance
- **Issue**: RDS instance has `PubliclyAccessible: true` and is in a subnet group that includes public subnets
- **Risk**: Database directly accessible from the internet
- **Remediation**:
  - Set `PubliclyAccessible: false`
  - Use private subnets only in DBSubnetGroup
  - Ensure RDS security group only allows access from web server security group

### Security Flaw #2: SSH Open to the Internet
- **Issue**: WebServerSecurityGroup allows SSH (port 22) from 0.0.0.0/0
- **Risk**: Brute force attacks, unauthorized access attempts
- **Remediation**:
  - Restrict SSH to specific IP ranges (e.g., corporate VPN)
  - Use AWS Systems Manager Session Manager instead of SSH
  - Implement bastion host pattern with stricter controls

### Security Flaw #3: Plaintext Database Credentials
- **Issue**: Database username and password passed as template parameters
- **Risk**: Credentials exposed in CloudFormation console, logs, and version control
- **Remediation**:
  - Use AWS Secrets Manager to store credentials
  - Reference secret ARN in RDS configuration
  - Rotate credentials automatically using Secrets Manager

### Security Flaw #4: Unencrypted EBS Volumes
- **Issue**: Launch template configures EBS volumes with `Encrypted: false`
- **Risk**: Data at rest not protected, compliance violations
- **Remediation**:
  - Set `Encrypted: true` for all EBS volumes
  - Specify KMS key ARN for customer-managed encryption
  - Enable account-level EBS encryption by default

### Security Flaw #5: HTTP Without HTTPS
- **Issue**: ALB listener only configured for HTTP (port 80) without HTTPS redirect
- **Risk**: Traffic transmitted in plaintext, susceptible to MITM attacks
- **Remediation**:
  - Add ACM certificate for domain
  - Create HTTPS listener (port 443) with certificate
  - Configure HTTP listener to redirect to HTTPS
  - Add HSTS headers in WordPress configuration

## Expected Security Tool Findings

### Prowler
- [check21] RDS instances should not be publicly accessible
- [check22] RDS instances should be encrypted at rest
- [check23] RDS backup retention should be 7 days or more (passes in Production)
- [extra735] Security groups should not have wide open port ranges to public

### Checkov
- CKV_AWS_17: RDS instance should not be publicly accessible
- CKV_AWS_16: RDS DB instance should be encrypted
- CKV_AWS_19: Security group allows ingress from 0.0.0.0/0 to port 22
- CKV_AWS_3: EBS volume should be encrypted
- CKV_AWS_91: ALB should use HTTPS listener

### cfn-nag
- W2: Security group with open access to SSH (port 22)
- W27: RDS instance should not be publicly accessible
- W28: RDS instance should have encryption enabled
- W58: Security group rule allows open egress

## Cleanup

To delete the stack and all resources:

```bash
# Delete the stack
aws cloudformation delete-stack \
  --stack-name wordpress-production \
  --region us-east-1

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete \
  --stack-name wordpress-production \
  --region us-east-1
```

**Note**: The RDS instance has `DeletionPolicy: Snapshot`, so a final snapshot will be created before deletion.

## Customization

### Environment-Specific Configuration

The template uses conditions for environment-specific settings:

- **Production**:
  - Multi-AZ RDS deployment
  - 7-day backup retention
  - Higher instance counts recommended

- **Staging/Development**:
  - Single-AZ RDS deployment
  - 1-day backup retention
  - Lower instance counts to reduce costs

### Scaling Configuration

Adjust auto-scaling parameters:

```yaml
MinSize: 2          # Minimum instances
MaxSize: 6          # Maximum instances
DesiredCapacity: 2  # Initial instance count
```

Modify scaling triggers by adjusting CloudWatch alarms:

```yaml
HighCPUAlarm:
  Threshold: 70     # Scale up at 70% CPU
  Period: 300       # Over 5 minutes

LowCPUAlarm:
  Threshold: 30     # Scale down at 30% CPU
  Period: 300       # Over 5 minutes
```

## Troubleshooting

### Stack Creation Fails

1. Check CloudFormation events:
   ```bash
   aws cloudformation describe-stack-events --stack-name wordpress-production
   ```

2. Common issues:
   - Invalid EC2 key pair name
   - Insufficient IAM permissions
   - Service quota limits exceeded
   - Invalid AMI ID for region

### WordPress Not Accessible

1. Check Auto Scaling Group health:
   ```bash
   aws autoscaling describe-auto-scaling-groups \
     --auto-scaling-group-names <asg-name>
   ```

2. Check Target Group health:
   ```bash
   aws elbv2 describe-target-health \
     --target-group-arn <target-group-arn>
   ```

3. Check EC2 instance logs:
   - SSH to instance (if accessible)
   - Check `/var/log/cloud-init-output.log`
   - Check `/var/log/cfn-init.log`

### Database Connection Issues

1. Verify RDS instance status:
   ```bash
   aws rds describe-db-instances \
     --db-instance-identifier <db-identifier>
   ```

2. Check security group rules allow traffic from web servers
3. Verify database credentials in WordPress configuration

## License

This template is provided as-is for testing and educational purposes. Use at your own risk.
