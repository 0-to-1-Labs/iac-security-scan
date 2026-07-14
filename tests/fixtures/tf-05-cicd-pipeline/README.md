# CI/CD Pipeline - Terraform Workload

## Overview

This Terraform configuration deploys a complete CI/CD pipeline on AWS using CodePipeline, CodeBuild, and CodeDeploy. The pipeline automates the build, test, and deployment process for applications stored in AWS CodeCommit repositories.

## Architecture

### Pipeline Stages

1. **Source**: Pulls code from AWS CodeCommit repository
2. **Build**: Compiles and packages the application using CodeBuild
3. **Test**: Runs unit tests and generates test reports
4. **Approval** (Optional): Manual approval gate before deployment
5. **Deploy**: Deploys to EC2 instances using CodeDeploy

### Components

- **CodePipeline**: Orchestrates the entire CI/CD workflow
- **CodeBuild**: Two projects (build and test) for compilation and testing
- **CodeDeploy**: Application deployment to EC2 instances
- **S3**: Artifact storage with lifecycle policies
- **SNS**: Pipeline notifications and alerts
- **CloudWatch**: Monitoring, logging, and event-driven triggers
- **IAM**: Service roles with least-privilege access

### Event-Driven Automation

- CloudWatch Events automatically trigger pipeline on CodeCommit push
- Pipeline state changes published to SNS for notifications
- Build/deploy failures trigger CloudWatch alarms
- Dashboard for real-time pipeline monitoring

## Prerequisites

1. **AWS Account**: Active AWS account with appropriate permissions
2. **Terraform**: Version 1.5.0 or higher
3. **AWS CLI**: Configured with credentials
4. **CodeCommit Repository**: Existing repository with application code
5. **EC2 Instances**: Tagged instances for CodeDeploy deployments

## Configuration

### Required Variables

```hcl
variable "repository_name" {
  description = "Name of the CodeCommit repository"
  default     = "myapp-repo"
}

variable "repository_branch" {
  description = "Branch to monitor for changes"
  default     = "main"
}

variable "notification_email" {
  description = "Email for pipeline notifications"
  default     = "devops@example.com"
}
```

### Optional Variables

See `variables.tf` for full list of configurable options including:
- Build compute type and Docker image
- Deployment configuration
- Artifact retention
- Approval stage enablement

## Usage

### Initialize Terraform

```bash
terraform init
```

### Plan Deployment

```bash
terraform plan -var="repository_name=my-repo" \
               -var="notification_email=team@example.com"
```

### Apply Configuration

```bash
terraform apply -var="repository_name=my-repo" \
                -var="notification_email=team@example.com"
```

### Destroy Resources

```bash
terraform destroy
```

## Pipeline Workflow

### 1. Code Commit

Developer pushes code to CodeCommit repository on the monitored branch.

### 2. Automatic Trigger

CloudWatch Event Rule detects the push and triggers CodePipeline execution.

### 3. Build Phase

CodeBuild pulls source code, executes build commands from `buildspec.yml`, and stores artifacts in S3.

### 4. Test Phase

CodeBuild runs unit tests, generates test reports, and uploads results to S3.

### 5. Manual Approval (Optional)

If enabled, pipeline pauses for manual approval via SNS notification.

### 6. Deployment

CodeDeploy deploys artifacts to EC2 instances matching the specified tags.

### 7. Notifications

SNS sends email notifications for:
- Pipeline execution started
- Pipeline execution succeeded
- Pipeline execution failed
- Manual approval needed
- Deployment failures

## Monitoring and Logging

### CloudWatch Dashboard

Access the pipeline dashboard at:
```
CloudWatch Console > Dashboards > {project_name}-{environment}-pipeline-dashboard
```

Displays:
- Pipeline execution success/failure metrics
- CodeBuild duration and build counts
- Recent build logs

### CloudWatch Alarms

Configured alarms:
- **Pipeline Failures**: Alerts on any pipeline execution failure
- **Build Duration**: Alerts when builds exceed 5 minutes
- **Deployment Errors**: Alerts on CodeDeploy failures

### Log Groups

- `/aws/codebuild/{project}-build`: Build logs
- `/aws/codebuild/{project}-test`: Test logs
- `/aws/codepipeline/{project}`: Pipeline event logs

## Buildspec Example

Create a `buildspec.yml` in your repository:

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      nodejs: 18
    commands:
      - echo Installing dependencies...
      - npm install

  pre_build:
    commands:
      - echo Running linters...
      - npm run lint

  build:
    commands:
      - echo Building application...
      - npm run build

  post_build:
    commands:
      - echo Build completed successfully

artifacts:
  files:
    - '**/*'
  name: BuildArtifact

cache:
  paths:
    - 'node_modules/**/*'
```

## CodeDeploy Configuration

### EC2 Instance Requirements

Instances must have:
1. CodeDeploy agent installed
2. Appropriate IAM instance profile
3. Tags matching deployment group configuration

### AppSpec Example

Create an `appspec.yml` in your repository:

```yaml
version: 0.0
os: linux
files:
  - source: /
    destination: /var/www/myapp
hooks:
  BeforeInstall:
    - location: scripts/install_dependencies.sh
      timeout: 300
      runas: root
  ApplicationStart:
    - location: scripts/start_server.sh
      timeout: 300
      runas: root
  ValidateService:
    - location: scripts/validate_service.sh
      timeout: 300
```

## Security Considerations

### IAM Roles

- **CodePipeline Role**: Permissions for S3, CodeBuild, CodeCommit, CodeDeploy
- **CodeBuild Role**: Permissions for CloudWatch Logs, S3, CodeCommit, ECR
- **CodeDeploy Role**: AWS managed `AWSCodeDeployRole` policy
- **CloudWatch Events Role**: Permission to start pipeline execution

### Artifact Storage

- S3 bucket with server-side encryption (AES256)
- Public access blocked
- Secure transport (HTTPS) enforced
- Lifecycle policy for automatic cleanup

### Secrets Management

Environment variables for sensitive data should use:
- AWS Systems Manager Parameter Store
- AWS Secrets Manager

Reference in buildspec:

```yaml
env:
  parameter-store:
    DB_PASSWORD: /myapp/database/password
  secrets-manager:
    API_KEY: myapp/api:key
```

## Outputs

After deployment, Terraform outputs:

- `pipeline_arn`: ARN of the CodePipeline
- `pipeline_name`: Name of the pipeline
- `artifact_bucket_name`: S3 bucket for artifacts
- `build_project_name`: CodeBuild build project name
- `test_project_name`: CodeBuild test project name
- `codedeploy_application_name`: CodeDeploy application name
- `notification_topic_arn`: SNS topic ARN for notifications

## Cost Optimization

### S3 Lifecycle Policies

Artifacts automatically expire after 30 days (configurable via `artifact_retention_days`).

### CodeBuild Caching

Build and test projects use S3 caching to speed up builds and reduce costs.

### CloudWatch Logs Retention

Log groups retain logs for 7-30 days to minimize storage costs.

## Troubleshooting

### Pipeline Not Triggering

1. Verify CloudWatch Event Rule is enabled
2. Check IAM role permissions for CloudWatch Events
3. Confirm repository name and branch match configuration

### Build Failures

1. Check CodeBuild logs in CloudWatch
2. Verify buildspec.yml syntax
3. Ensure IAM role has necessary permissions
4. Review environment variables and Docker image compatibility

### Deployment Failures

1. Verify CodeDeploy agent is running on EC2 instances
2. Check instance tags match deployment group configuration
3. Review appspec.yml for errors
4. Examine deployment logs in CodeDeploy console

### Permission Errors

1. Review IAM role policies
2. Ensure service roles have trust relationships configured
3. Check S3 bucket policies allow CodePipeline/CodeBuild access

## Customization

### Adding Stages

Add custom stages to `codepipeline.tf`:

```hcl
stage {
  name = "CustomStage"

  action {
    name     = "CustomAction"
    category = "Invoke"
    owner    = "AWS"
    provider = "Lambda"
    version  = "1"

    configuration = {
      FunctionName = aws_lambda_function.custom.function_name
    }
  }
}
```

### Blue/Green Deployments

Uncomment blue/green configuration in `codedeploy.tf` and configure load balancer integration.

### Multi-Region

Deploy to multiple regions by:
1. Creating region-specific provider aliases
2. Duplicating CodeDeploy resources per region
3. Using cross-region S3 replication for artifacts

## Support

For issues or questions:
- Review AWS CodePipeline documentation
- Check CloudWatch logs and alarms
- Contact your DevOps team

## License

This Terraform configuration is provided as-is for demonstration purposes.
