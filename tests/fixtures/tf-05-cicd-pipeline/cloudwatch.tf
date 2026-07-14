# CloudWatch Event Rule to trigger pipeline on CodeCommit changes
resource "aws_cloudwatch_event_rule" "codecommit_trigger" {
  name        = "${var.project_name}-${var.environment}-codecommit-trigger"
  description = "Trigger pipeline on CodeCommit push to ${var.repository_branch}"

  event_pattern = jsonencode({
    source      = ["aws.codecommit"]
    detail-type = ["CodeCommit Repository State Change"]
    detail = {
      event         = ["referenceCreated", "referenceUpdated"]
      referenceType = ["branch"]
      referenceName = [var.repository_branch]
    }
    resources = ["arn:aws:codecommit:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${var.repository_name}"]
  })

  tags = {
    Name = "${var.project_name}-codecommit-trigger"
  }
}

# CloudWatch Event Target to start pipeline
resource "aws_cloudwatch_event_target" "pipeline" {
  rule     = aws_cloudwatch_event_rule.codecommit_trigger.name
  arn      = aws_codepipeline.main.arn
  role_arn = aws_iam_role.cloudwatch_events.arn
}

# CloudWatch Event Rule for pipeline state changes
resource "aws_cloudwatch_event_rule" "pipeline_state" {
  name        = "${var.project_name}-${var.environment}-pipeline-state"
  description = "Capture pipeline state changes"

  event_pattern = jsonencode({
    source      = ["aws.codepipeline"]
    detail-type = ["CodePipeline Pipeline Execution State Change"]
    detail = {
      pipeline = [aws_codepipeline.main.name]
    }
  })

  tags = {
    Name = "${var.project_name}-pipeline-state"
  }
}

# CloudWatch Event Target to send pipeline state to SNS
resource "aws_cloudwatch_event_target" "pipeline_state_sns" {
  rule      = aws_cloudwatch_event_rule.pipeline_state.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.pipeline_notifications.arn

  input_transformer {
    input_paths = {
      pipeline   = "$.detail.pipeline"
      state      = "$.detail.state"
      execution  = "$.detail.execution-id"
      time       = "$.time"
    }

    input_template = <<EOF
"Pipeline <pipeline> execution <execution> changed state to <state> at <time>"
EOF
  }
}

# CloudWatch Event Rule for CodeBuild state changes
resource "aws_cloudwatch_event_rule" "codebuild_state" {
  name        = "${var.project_name}-${var.environment}-codebuild-state"
  description = "Capture CodeBuild state changes"

  event_pattern = jsonencode({
    source      = ["aws.codebuild"]
    detail-type = ["CodeBuild Build State Change"]
    detail = {
      "build-status" = ["FAILED", "SUCCEEDED", "STOPPED"]
      "project-name" = [
        aws_codebuild_project.build.name,
        aws_codebuild_project.test.name
      ]
    }
  })

  tags = {
    Name = "${var.project_name}-codebuild-state"
  }
}

# CloudWatch Event Target for CodeBuild notifications
resource "aws_cloudwatch_event_target" "codebuild_state_sns" {
  rule      = aws_cloudwatch_event_rule.codebuild_state.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.pipeline_notifications.arn

  input_transformer {
    input_paths = {
      project = "$.detail.project-name"
      status  = "$.detail.build-status"
      time    = "$.time"
    }

    input_template = <<EOF
"CodeBuild project <project> status: <status> at <time>"
EOF
  }
}

# CloudWatch Log Group for pipeline events
resource "aws_cloudwatch_log_group" "pipeline_events" {
  name              = "/aws/codepipeline/${var.project_name}-${var.environment}"
  retention_in_days = 30

  tags = {
    Name = "${var.project_name}-pipeline-events"
  }
}

# CloudWatch Dashboard for pipeline monitoring
resource "aws_cloudwatch_dashboard" "pipeline" {
  dashboard_name = "${var.project_name}-${var.environment}-pipeline-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/CodePipeline", "PipelineExecutionSuccess", { stat = "Sum" }],
            [".", "PipelineExecutionFailure", { stat = "Sum" }]
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "Pipeline Execution Status"
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/CodeBuild", "Duration", { stat = "Average" }],
            [".", "Builds", { stat = "Sum" }]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "CodeBuild Metrics"
        }
      },
      {
        type = "log"
        properties = {
          query   = <<EOF
SOURCE '/aws/codebuild/${var.project_name}-${var.environment}-build'
| fields @timestamp, @message
| sort @timestamp desc
| limit 20
EOF
          region  = var.aws_region
          title   = "Recent Build Logs"
        }
      }
    ]
  })
}

# CloudWatch Metric Alarm for pipeline failures
resource "aws_cloudwatch_metric_alarm" "pipeline_failures" {
  alarm_name          = "${var.project_name}-${var.environment}-pipeline-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "PipelineExecutionFailure"
  namespace           = "AWS/CodePipeline"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alert when pipeline execution fails"
  treat_missing_data  = "notBreaching"

  dimensions = {
    PipelineName = aws_codepipeline.main.name
  }

  alarm_actions = [aws_sns_topic.pipeline_notifications.arn]

  tags = {
    Name = "${var.project_name}-pipeline-alarm"
  }
}

# CloudWatch Metric Alarm for build duration
resource "aws_cloudwatch_metric_alarm" "build_duration" {
  alarm_name          = "${var.project_name}-${var.environment}-build-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Duration"
  namespace           = "AWS/CodeBuild"
  period              = 300
  statistic           = "Average"
  threshold           = 300000  # 5 minutes in milliseconds
  alarm_description   = "Alert when build duration exceeds 5 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ProjectName = aws_codebuild_project.build.name
  }

  alarm_actions = [aws_sns_topic.pipeline_notifications.arn]

  tags = {
    Name = "${var.project_name}-build-duration-alarm"
  }
}
