# CodeBuild project for building the application
resource "aws_codebuild_project" "build" {
  name          = "${var.project_name}-${var.environment}-build"
  description   = "Build project for ${var.project_name}"
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 60

  artifacts {
    type = "CODEPIPELINE"
  }

  cache {
    type     = "S3"
    location = "${aws_s3_bucket.artifacts.bucket}/build-cache"
  }

  environment {
    # SECURITY FLAW: Privileged mode enabled when not needed for Docker builds
    privileged_mode             = true
    compute_type                = var.build_compute_type
    image                       = var.build_image
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    # SECURITY FLAW: Sensitive environment variables in plain text (should use Parameter Store/Secrets Manager)
    environment_variable {
      name  = "ENVIRONMENT"
      value = var.environment
    }

    environment_variable {
      name  = "AWS_REGION"
      value = var.aws_region
    }

    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = data.aws_caller_identity.current.account_id
    }

    environment_variable {
      name  = "API_KEY"
      value = "hardcoded-api-key-12345"  # SECURITY FLAW: Hardcoded sensitive value
    }

    environment_variable {
      name  = "DATABASE_PASSWORD"
      value = "MySecretP@ssw0rd"  # SECURITY FLAW: Hardcoded credential
    }
  }

  logs_config {
    cloudwatch_logs {
      status      = "ENABLED"
      group_name  = aws_cloudwatch_log_group.codebuild_build.name
      stream_name = "build"
    }

    s3_logs {
      status   = "ENABLED"
      location = "${aws_s3_bucket.artifacts.bucket}/build-logs"
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = var.buildspec_path
  }

  tags = {
    Name = "${var.project_name}-build"
  }
}

# CodeBuild project for running tests
resource "aws_codebuild_project" "test" {
  name          = "${var.project_name}-${var.environment}-test"
  description   = "Test project for ${var.project_name}"
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 30

  artifacts {
    type = "CODEPIPELINE"
  }

  cache {
    type     = "S3"
    location = "${aws_s3_bucket.artifacts.bucket}/test-cache"
  }

  environment {
    # SECURITY FLAW: Privileged mode enabled unnecessarily
    privileged_mode             = true
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = var.build_image
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "ENVIRONMENT"
      value = var.environment
    }

    environment_variable {
      name  = "TEST_DATABASE_URL"
      value = "postgresql://user:password@localhost:5432/testdb"  # SECURITY FLAW: Hardcoded connection string
    }
  }

  logs_config {
    cloudwatch_logs {
      status      = "ENABLED"
      group_name  = aws_cloudwatch_log_group.codebuild_test.name
      stream_name = "test"
    }

    s3_logs {
      status   = "ENABLED"
      location = "${aws_s3_bucket.artifacts.bucket}/test-logs"
    }
  }

  source {
    type = "CODEPIPELINE"
    buildspec = jsonencode({
      version = "0.2"
      phases = {
        install = {
          commands = [
            "echo Installing test dependencies..."
          ]
        }
        pre_build = {
          commands = [
            "echo Running pre-test setup..."
          ]
        }
        build = {
          commands = [
            "echo Running tests...",
            "npm test || true"
          ]
        }
      }
      reports = {
        test_reports = {
          files = [
            "test-results/**/*.xml"
          ]
          "file-format" = "JUNITXML"
        }
      }
    })
  }

  tags = {
    Name = "${var.project_name}-test"
  }
}

# CloudWatch Log Groups for CodeBuild
resource "aws_cloudwatch_log_group" "codebuild_build" {
  name              = "/aws/codebuild/${var.project_name}-${var.environment}-build"
  retention_in_days = 7

  tags = {
    Name = "${var.project_name}-build-logs"
  }
}

resource "aws_cloudwatch_log_group" "codebuild_test" {
  name              = "/aws/codebuild/${var.project_name}-${var.environment}-test"
  retention_in_days = 7

  tags = {
    Name = "${var.project_name}-test-logs"
  }
}

# CodeBuild Report Groups
resource "aws_codebuild_report_group" "test" {
  name = "${var.project_name}-${var.environment}-test-reports"
  type = "TEST"

  export_config {
    type = "S3"

    s3_destination {
      bucket              = aws_s3_bucket.artifacts.bucket
      path                = "/test-reports"
      packaging           = "ZIP"
      encryption_disabled = false
    }
  }

  tags = {
    Name = "${var.project_name}-test-reports"
  }
}
