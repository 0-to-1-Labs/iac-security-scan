# SNS topic for pipeline notifications
# SECURITY FLAW: Missing encryption at rest
resource "aws_sns_topic" "pipeline_notifications" {
  name = "${var.project_name}-${var.environment}-pipeline-notifications"

  tags = {
    Name = "${var.project_name}-pipeline-notifications"
  }
}

# SNS topic subscription
resource "aws_sns_topic_subscription" "pipeline_email" {
  topic_arn = aws_sns_topic.pipeline_notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# SNS topic policy
resource "aws_sns_topic_policy" "pipeline_notifications" {
  arn = aws_sns_topic.pipeline_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCodePipelinePublish"
        Effect = "Allow"
        Principal = {
          Service = "codestar-notifications.amazonaws.com"
        }
        Action = [
          "SNS:Publish"
        ]
        Resource = aws_sns_topic.pipeline_notifications.arn
      },
      {
        Sid    = "AllowCloudWatchEventsPublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = [
          "SNS:Publish"
        ]
        Resource = aws_sns_topic.pipeline_notifications.arn
      }
    ]
  })
}

# CodeStar notification rule for pipeline events
resource "aws_codestarnotifications_notification_rule" "pipeline" {
  name        = "${var.project_name}-${var.environment}-pipeline-events"
  detail_type = "FULL"
  resource    = aws_codepipeline.main.arn

  event_type_ids = [
    "codepipeline-pipeline-pipeline-execution-failed",
    "codepipeline-pipeline-pipeline-execution-succeeded",
    "codepipeline-pipeline-pipeline-execution-started",
    "codepipeline-pipeline-manual-approval-needed"
  ]

  target {
    address = aws_sns_topic.pipeline_notifications.arn
    type    = "SNS"
  }

  tags = {
    Name = "${var.project_name}-pipeline-notifications"
  }
}
