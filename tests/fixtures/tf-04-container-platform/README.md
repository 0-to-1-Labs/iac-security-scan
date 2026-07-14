# Container Platform - Terraform Infrastructure

## Overview

This Terraform configuration deploys a production-ready container platform on AWS using Amazon ECS with Fargate. The platform includes a full networking stack, load balancing, container orchestration, service discovery, and comprehensive monitoring.

## Architecture

### Core Components

- **Amazon ECS Cluster**: Fargate-based container orchestration with Container Insights enabled
- **Amazon ECR**: Private container registries with lifecycle policies
- **Application Load Balancer**: Internet-facing ALB with HTTPS support
- **VPC Networking**: Multi-AZ VPC with public and private subnets, NAT gateways
- **Service Discovery**: AWS Cloud Map for service-to-service communication
- **Auto Scaling**: CPU and memory-based autoscaling for ECS services
- **Monitoring**: CloudWatch logs, metrics, dashboards, and alarms

### Network Architecture

```
                                 Internet
                                    |
                            Internet Gateway
                                    |
                    +---------------+---------------+
                    |               |               |
              Public Subnet    Public Subnet   Public Subnet
                (AZ-A)            (AZ-B)          (AZ-C)
                    |               |               |
                NAT Gateway      NAT Gateway    NAT Gateway
                    |               |               |
              Private Subnet   Private Subnet  Private Subnet
                (AZ-A)            (AZ-B)          (AZ-C)
                    |               |               |
                ECS Tasks        ECS Tasks      ECS Tasks
```

### ECS Service Architecture

- **Launch Type**: Fargate (serverless container execution)
- **Capacity Providers**: FARGATE (primary) + FARGATE_SPOT (cost optimization)
- **Service Discovery**: Cloud Map private DNS namespace
- **Load Balancing**: ALB with health checks and sticky sessions
- **Scaling**: Target tracking based on CPU (70%) and memory (80%)

## Files

- **main.tf**: Provider configuration and Terraform settings
- **variables.tf**: Input variables with defaults
- **outputs.tf**: Output values (ALB DNS, ECR URLs, etc.)
- **vpc.tf**: VPC, subnets, NAT gateways, route tables, service discovery namespace
- **ecs.tf**: ECS cluster, capacity providers, task definitions
- **ecr.tf**: ECR repositories with lifecycle policies and repository policies
- **services.tf**: ECS services, service discovery, autoscaling policies
- **alb.tf**: Application Load Balancer, target groups, listeners, S3 bucket for logs
- **security-groups.tf**: Security groups for ALB and ECS tasks
- **iam.tf**: IAM roles and policies for task execution and task runtime
- **cloudwatch.tf**: Log groups, CloudWatch dashboard, metric alarms, SNS topic

## Usage

### Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with appropriate credentials
- AWS account with permissions to create the resources

### Deployment

1. **Initialize Terraform**:
   ```bash
   terraform init
   ```

2. **Review the plan**:
   ```bash
   terraform plan
   ```

3. **Apply the configuration**:
   ```bash
   terraform apply
   ```

4. **Access the application**:
   ```bash
   terraform output alb_dns_name
   ```

### Customization

You can customize the deployment by modifying variables:

```bash
terraform apply \
  -var="environment=staging" \
  -var="aws_region=us-west-2" \
  -var="desired_count=3" \
  -var="app_cpu=1024" \
  -var="app_memory=2048"
```

Or create a `terraform.tfvars` file:

```hcl
environment         = "production"
aws_region          = "us-east-1"
project_name        = "myapp"
desired_count       = 3
app_cpu             = 1024
app_memory          = 2048
ecr_repositories    = ["webapp", "api", "worker", "scheduler"]
```

### Deploying Container Images

1. **Authenticate with ECR**:
   ```bash
   aws ecr get-login-password --region us-east-1 | \
     docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com
   ```

2. **Build and tag your image**:
   ```bash
   docker build -t webapp .
   docker tag webapp:latest <ecr-url>/webapp:latest
   ```

3. **Push to ECR**:
   ```bash
   docker push <ecr-url>/webapp:latest
   ```

4. **Update ECS service** (forces new deployment):
   ```bash
   aws ecs update-service \
     --cluster containerplatform-production-cluster \
     --service containerplatform-production-webapp \
     --force-new-deployment
   ```

## Features

### High Availability

- Multi-AZ deployment across 3 availability zones
- ALB distributes traffic across healthy targets
- ECS service maintains desired task count with circuit breaker
- NAT gateways in each AZ for redundancy

### Security

- Private subnets for ECS tasks (no public IPs)
- Security groups with least-privilege access
- IAM roles with specific permissions for tasks
- HTTPS support with ACM certificates
- ALB access logs stored in S3

### Monitoring & Observability

- CloudWatch Container Insights enabled
- Centralized logging to CloudWatch Logs
- Custom CloudWatch dashboard for key metrics
- CloudWatch alarms for:
  - High CPU utilization (>80%)
  - High memory utilization (>85%)
  - Unhealthy ALB targets
  - 5XX errors from application

### Auto Scaling

- Service auto-scaling based on:
  - CPU utilization (target: 70%)
  - Memory utilization (target: 80%)
- Min tasks: 2 (configurable via `desired_count`)
- Max tasks: 10
- Scale-out cooldown: 60 seconds
- Scale-in cooldown: 300 seconds

### Cost Optimization

- Fargate Spot capacity provider for non-critical workloads
- ECR lifecycle policies to clean up old images
- S3 lifecycle policy for ALB logs (90-day retention)
- CloudWatch log retention (30 days)

## Outputs

After applying, you'll get:

- **alb_dns_name**: URL to access your application
- **ecr_repository_urls**: ECR repository URLs for pushing images
- **ecs_cluster_name**: Name of the ECS cluster
- **service_discovery_namespace_id**: Cloud Map namespace for service discovery

## Service Discovery

ECS services register with Cloud Map for internal service-to-service communication:

```
<service-name>.local
```

Example: `webapp.local` can be used by other services in the same VPC to communicate with the webapp service.

## Troubleshooting

### Tasks not starting

1. Check ECS events:
   ```bash
   aws ecs describe-services \
     --cluster containerplatform-production-cluster \
     --services containerplatform-production-webapp
   ```

2. Check CloudWatch logs:
   ```bash
   aws logs tail /ecs/containerplatform-production --follow
   ```

### ALB health checks failing

1. Verify the health check path is correct
2. Ensure the application responds with 200 on the health check endpoint
3. Check security group rules allow ALB -> ECS tasks communication
4. Review target group health status in AWS Console

### Container crashes

1. Check CloudWatch logs for application errors
2. Review task definition resource limits (CPU/memory)
3. Verify IAM permissions for the task role
4. Use ECS Exec to debug running containers:
   ```bash
   aws ecs execute-command \
     --cluster containerplatform-production-cluster \
     --task <task-id> \
     --container webapp \
     --interactive \
     --command "/bin/sh"
   ```

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

**Warning**: This will delete all resources including ECR repositories and their images, CloudWatch logs, and S3 buckets.

## Security Considerations

- Replace the self-signed ACM certificate with a real certificate
- Update SNS email endpoint for CloudWatch alarms
- Review and adjust IAM policies for least-privilege access
- Enable AWS WAF on the ALB for additional security
- Configure VPC Flow Logs for network traffic analysis
- Implement secrets management using AWS Secrets Manager or Parameter Store
- Enable ECR image scanning on push
- Configure container read-only root filesystem
- Enable drop_invalid_header_fields on ALB

## Next Steps

1. Configure a custom domain with Route 53
2. Set up CI/CD pipeline (GitHub Actions, GitLab CI, etc.)
3. Implement blue/green deployments
4. Add additional ECS services (API, worker, etc.)
5. Integrate with AWS X-Ray for distributed tracing
6. Set up AWS Backup for disaster recovery
7. Implement AWS Config rules for compliance monitoring
