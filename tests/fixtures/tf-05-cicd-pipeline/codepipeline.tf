# CodePipeline for CI/CD workflow
resource "aws_codepipeline" "main" {
  name     = "${var.project_name}-${var.environment}-pipeline"
  role_arn = aws_iam_role.codepipeline.arn

  artifact_store {
    location = aws_s3_bucket.artifacts.bucket
    type     = "S3"
  }

  # Source stage - CodeCommit
  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeCommit"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = {
        RepositoryName       = var.repository_name
        BranchName           = var.repository_branch
        PollForSourceChanges = false
      }
    }
  }

  # Build stage - CodeBuild
  stage {
    name = "Build"

    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]

      configuration = {
        ProjectName = aws_codebuild_project.build.name
      }
    }
  }

  # Test stage - CodeBuild
  stage {
    name = "Test"

    action {
      name             = "UnitTest"
      category         = "Test"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["build_output"]
      output_artifacts = ["test_output"]

      configuration = {
        ProjectName = aws_codebuild_project.test.name
      }
    }
  }

  # Optional approval stage
  dynamic "stage" {
    for_each = var.enable_approval_stage ? [1] : []

    content {
      name = "Approval"

      action {
        name     = "ManualApproval"
        category = "Approval"
        owner    = "AWS"
        provider = "Manual"
        version  = "1"

        configuration = {
          NotificationArn = aws_sns_topic.pipeline_notifications.arn
          CustomData      = "Please review and approve deployment to ${var.environment}"
        }
      }
    }
  }

  # Deploy stage - CodeDeploy
  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "CodeDeploy"
      version         = "1"
      input_artifacts = ["build_output"]

      configuration = {
        ApplicationName     = aws_codedeploy_app.main.name
        DeploymentGroupName = aws_codedeploy_deployment_group.main.deployment_group_name
      }
    }
  }

  tags = {
    Name = "${var.project_name}-pipeline"
  }
}

# Webhook for automatic pipeline triggering
resource "aws_codepipeline_webhook" "main" {
  name            = "${var.project_name}-${var.environment}-webhook"
  target_pipeline = aws_codepipeline.main.name
  target_action   = "Source"
  authentication  = "GITHUB_HMAC"

  authentication_configuration {
    secret_token = random_password.webhook_secret.result
  }

  filter {
    json_path    = "$.ref"
    match_equals = "refs/heads/{Branch}"
  }

  tags = {
    Name = "${var.project_name}-webhook"
  }
}

# Random secret for webhook
resource "random_password" "webhook_secret" {
  length  = 32
  special = true
}
