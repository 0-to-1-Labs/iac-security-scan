# Three-Tier Web Application on AWS

This Terraform configuration deploys a production-ready three-tier web application architecture on AWS.

## Architecture Overview

This infrastructure creates a highly available, scalable web application with the following components:

### Network Layer (VPC)
- **VPC**: Custom VPC with CIDR 10.0.0.0/16
- **Public Subnets**: 2 subnets across 2 availability zones for load balancers
- **Private Subnets**: 2 subnets across 2 availability zones for application servers
- **Database Subnets**: 2 subnets across 2 availability zones for RDS
- **NAT Gateways**: One per AZ for high availability (enables private subnet internet access)
- **Internet Gateway**: For public subnet internet access
- **VPC Flow Logs**: Enabled for network traffic monitoring

### Presentation Layer (Load Balancing)
- **Application Load Balancer (ALB)**: Internet-facing, in public subnets
- **Target Group**: Health checks configured with /health endpoint
- **Listeners**: HTTP (port 80) and optional HTTPS (port 443)
- **Auto-redirect**: HTTP to HTTPS when certificate is provided

### Application Layer (Compute)
- **Auto Scaling Group**: 2-6 EC2 instances (t3.medium) in private subnets
- **Launch Template**: Amazon Linux 2023 with Apache, PHP, CloudWatch agent
- **Scaling Policies**: CPU and request count based auto-scaling
- **User Data**: Automated application deployment script
- **IAM Roles**: EC2 instance profile with CloudWatch and SSM permissions
- **Monitoring**: Enhanced CloudWatch metrics and logs

### Data Layer (Database)
- **RDS MySQL 8.0**: Multi-AZ deployment for high availability
- **Instance Class**: db.t3.medium with 100 GB storage (auto-scaling up to 200 GB)
- **Backups**: 7-day retention, automated backups
- **Monitoring**: Enhanced monitoring, Performance Insights, CloudWatch alarms
- **Security**: Located in private database subnets, isolated from internet

### Security
- **Security Groups**: Layered security with minimal required access
  - ALB: HTTP/HTTPS from internet
  - App Servers: HTTP/HTTPS from ALB only
  - RDS: MySQL from app servers only
- **IAM Roles**: Least privilege access for EC2 and RDS monitoring
- **Encryption**: EBS volumes encrypted at rest
- **Network Isolation**: Private subnets for application and database tiers

## Architecture Diagram

```
                                   Internet
                                      |
                                      v
                        ┌─────────────────────────┐
                        │  Internet Gateway (IGW) │
                        └─────────────────────────┘
                                      |
                    ┌─────────────────┴─────────────────┐
                    │                                   │
            ┌───────▼────────┐              ┌──────────▼──────────┐
            │ Public Subnet  │              │  Public Subnet      │
            │      AZ-1      │              │       AZ-2          │
            │                │              │                     │
            │  ┌──────────┐  │              │   ┌──────────┐     │
            │  │   ALB    │  │              │   │   ALB    │     │
            │  └──────────┘  │              │   └──────────┘     │
            │  ┌──────────┐  │              │   ┌──────────┐     │
            │  │   NAT    │  │              │   │   NAT    │     │
            │  │  Gateway │  │              │   │  Gateway │     │
            │  └──────────┘  │              │   └──────────┘     │
            └────────┬────────┘              └──────────┬─────────┘
                     |                                  |
        ┌────────────┴────────────┬─────────────────────┘
        |                         |
┌───────▼────────┐        ┌──────▼──────────┐
│ Private Subnet │        │ Private Subnet  │
│      AZ-1      │        │      AZ-2       │
│                │        │                 │
│  ┌──────────┐  │        │  ┌──────────┐   │
│  │   EC2    │  │        │  │   EC2    │   │
│  │  (ASG)   │  │        │  │  (ASG)   │   │
│  └──────────┘  │        │  └──────────┘   │
└────────┬────────┘        └─────────┬───────┘
         |                           |
         └──────────┬────────────────┘
                    |
        ┌───────────▼──────────┐
        │                      │
┌───────▼────────┐    ┌────────▼────────┐
│ Database       │    │ Database        │
│ Subnet AZ-1    │    │ Subnet AZ-2     │
│                │    │                 │
│  ┌──────────┐  │    │  ┌──────────┐   │
│  │   RDS    │◄─┼────┼─►│   RDS    │   │
│  │  Primary │  │    │  │ Standby  │   │
│  └──────────┘  │    │  └──────────┘   │
└────────────────┘    └─────────────────┘
```

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with appropriate credentials
- AWS account with permissions to create VPC, EC2, RDS, ALB, IAM resources
- (Optional) ACM certificate for HTTPS support

## Quick Start

### 1. Clone and Navigate

```bash
cd tf-01-three-tier-webapp
```

### 2. Configure Variables

Copy the example tfvars file and customize:

```bash
cp terraform.tfvars.example terraform.tfvars
```

**Important**: Edit `terraform.tfvars` and set:
- `db_password`: Strong password for RDS (minimum 8 characters)
- `aws_region`: Your desired AWS region
- `certificate_arn`: (Optional) ARN of ACM certificate for HTTPS

### 3. Initialize Terraform

```bash
terraform init
```

### 4. Review Plan

```bash
terraform plan
```

### 5. Deploy

```bash
terraform apply
```

Review the plan and type `yes` to confirm.

### 6. Access Your Application

After deployment completes (5-10 minutes), get the ALB DNS name:

```bash
terraform output app_url
```

Visit the URL in your browser. The application will display:
- Instance metadata (ID, AZ, type)
- Database connection status
- Server timestamp

## Configuration

### Input Variables

Key variables you can customize in `terraform.tfvars`:

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region | us-east-1 |
| `environment` | Environment name | production |
| `instance_type` | EC2 instance type | t3.medium |
| `asg_min_size` | Minimum ASG instances | 2 |
| `asg_max_size` | Maximum ASG instances | 6 |
| `db_instance_class` | RDS instance class | db.t3.medium |
| `db_password` | Database password | (required) |
| `certificate_arn` | ACM cert for HTTPS | "" |

See `variables.tf` for complete list.

### Outputs

After deployment, Terraform outputs:

| Output | Description |
|--------|-------------|
| `app_url` | Application URL (load balancer) |
| `alb_dns_name` | ALB DNS name |
| `rds_endpoint` | Database endpoint |
| `vpc_id` | VPC identifier |
| `asg_name` | Auto Scaling Group name |

View all outputs:

```bash
terraform output
```

## Post-Deployment

### Verify Application

1. **Load Balancer Health**: Check ALB target group health in AWS Console
2. **Application**: Visit the `app_url` output
3. **Database**: Application will show "Connected successfully" if RDS is accessible
4. **Auto Scaling**: Verify 2 instances running in ASG

### Access EC2 Instances

Instances are in private subnets. Use AWS Systems Manager Session Manager:

```bash
# List instances
aws ec2 describe-instances --filters "Name=tag:Project,Values=webapp" \
  --query 'Reservations[].Instances[].[InstanceId,State.Name,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Connect via Session Manager
aws ssm start-session --target <instance-id>
```

### Monitor Resources

- **CloudWatch Logs**: `/aws/ec2/webapp-production/*` log groups
- **CloudWatch Alarms**: ASG CPU, RDS CPU/storage/connections
- **VPC Flow Logs**: `/aws/vpc/webapp-production`
- **RDS Performance Insights**: Available in RDS console

## Scaling

### Automatic Scaling

ASG automatically scales based on:
- **CPU Utilization**: Target 70%
- **Request Count**: Target 1000 requests per target

### Manual Scaling

Adjust desired capacity:

```bash
aws autoscaling set-desired-capacity \
  --auto-scaling-group-name $(terraform output -raw asg_name) \
  --desired-capacity 4
```

Or update `terraform.tfvars`:

```hcl
asg_desired_capacity = 4
```

Then apply:

```bash
terraform apply
```

## Maintenance

### Database Maintenance

- **Backups**: Automated daily at 03:00-04:00 UTC
- **Maintenance**: Sundays 04:00-05:00 UTC
- **Recovery**: Restore from automated backup or final snapshot

### Application Updates

Update the user data script or instance configuration:

1. Modify `user-data.sh` or `asg.tf`
2. Apply changes: `terraform apply`
3. ASG instance refresh automatically rolls out updates

### Terraform State

Store state remotely for team collaboration:

```hcl
# Add to main.tf
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "webapp/terraform.tfstate"
    region = "us-east-1"
  }
}
```

## Cost Estimation

Approximate monthly costs (us-east-1, on-demand pricing):

| Resource | Configuration | Monthly Cost |
|----------|---------------|--------------|
| EC2 (ASG) | 2x t3.medium | ~$60 |
| RDS | db.t3.medium Multi-AZ | ~$120 |
| ALB | 1x ALB | ~$20 |
| NAT Gateway | 2x NAT | ~$70 |
| Data Transfer | Moderate | ~$20 |
| **Total** | | **~$290** |

Reduce costs:
- Use Reserved Instances or Savings Plans
- Reduce to 1 NAT Gateway (lower HA)
- Use smaller instance types for dev/test
- Enable RDS storage autoscaling

## Security Considerations

This configuration includes:
- ✅ Network isolation (private subnets)
- ✅ Security groups with least privilege
- ✅ EBS encryption
- ✅ VPC Flow Logs
- ✅ CloudWatch logging
- ✅ IAM instance profiles
- ✅ Multi-AZ RDS
- ✅ Automated backups

Additional hardening:
- Enable AWS WAF on ALB
- Configure AWS Config rules
- Enable GuardDuty
- Implement AWS Secrets Manager for database credentials
- Add AWS Certificate Manager for HTTPS
- Enable S3 bucket for ALB access logs
- Implement AWS Systems Manager Parameter Store

## Disaster Recovery

### Backup Strategy

- **RDS**: Automated daily backups (7-day retention)
- **Final Snapshot**: Created on RDS deletion
- **Application**: Stateless, can be recreated from Terraform

### Recovery Procedure

1. **Database**: Restore from snapshot or point-in-time
2. **Infrastructure**: Re-run `terraform apply`
3. **Application**: User data script automatically deploys app

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

**Warning**: This will:
- Terminate all EC2 instances
- Delete the ALB
- Create a final RDS snapshot before deletion
- Release Elastic IPs
- Delete the VPC and all network resources

## Troubleshooting

### Application Not Accessible

1. Check ALB target health:
   ```bash
   aws elbv2 describe-target-health \
     --target-group-arn $(terraform output -raw alb_arn)
   ```

2. Verify security group rules allow traffic
3. Check ASG has running instances

### Database Connection Failed

1. Verify security group allows traffic from app servers
2. Check RDS instance is available
3. Verify credentials in user data script
4. Check RDS endpoint in outputs

### Instances Not Launching

1. Check ASG activity:
   ```bash
   aws autoscaling describe-scaling-activities \
     --auto-scaling-group-name $(terraform output -raw asg_name)
   ```

2. Review CloudWatch Logs for user data errors
3. Verify IAM instance profile permissions

## File Structure

```
.
├── main.tf                 # Provider and data sources
├── variables.tf            # Input variable definitions
├── outputs.tf              # Output value definitions
├── vpc.tf                  # VPC, subnets, routing, NAT
├── security-groups.tf      # Security group definitions
├── alb.tf                  # Application Load Balancer
├── iam.tf                  # IAM roles and policies
├── asg.tf                  # Auto Scaling Group and Launch Template
├── rds.tf                  # RDS database instance
├── user-data.sh            # EC2 initialization script
├── terraform.tfvars.example # Example variable values
├── .gitignore              # Git ignore patterns
└── README.md               # This file
```

## Contributing

To modify this infrastructure:

1. Make changes to the appropriate `.tf` file
2. Run `terraform fmt` to format code
3. Run `terraform validate` to check syntax
4. Run `terraform plan` to preview changes
5. Run `terraform apply` to deploy changes

## License

This configuration is provided as-is for educational and production use.

## Support

For issues or questions:
1. Check AWS service limits
2. Review CloudWatch Logs
3. Verify security group and network ACL rules
4. Check Terraform state for drift: `terraform plan`

## Version History

- **v1.0.0**: Initial release with three-tier architecture
  - VPC with multi-AZ subnets
  - ALB with auto-scaling EC2 instances
  - Multi-AZ RDS MySQL
  - CloudWatch monitoring and logging
