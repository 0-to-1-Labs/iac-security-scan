output "pipeline_arn" {
  description = "ARN of the CodePipeline"
  value       = aws_codepipeline.main.arn
}

output "pipeline_name" {
  description = "Name of the CodePipeline"
  value       = aws_codepipeline.main.name
}

output "artifact_bucket_name" {
  description = "Name of the S3 artifact bucket"
  value       = aws_s3_bucket.artifacts.bucket
}

output "artifact_bucket_arn" {
  description = "ARN of the S3 artifact bucket"
  value       = aws_s3_bucket.artifacts.arn
}

output "build_project_name" {
  description = "Name of the CodeBuild project"
  value       = aws_codebuild_project.build.name
}

output "test_project_name" {
  description = "Name of the CodeBuild test project"
  value       = aws_codebuild_project.test.name
}

output "codedeploy_application_name" {
  description = "Name of the CodeDeploy application"
  value       = aws_codedeploy_app.main.name
}

output "codedeploy_deployment_group_name" {
  description = "Name of the CodeDeploy deployment group"
  value       = aws_codedeploy_deployment_group.main.deployment_group_name
}

output "notification_topic_arn" {
  description = "ARN of the SNS notification topic"
  value       = aws_sns_topic.pipeline_notifications.arn
}

output "pipeline_webhook_url" {
  description = "Webhook URL for triggering the pipeline"
  value       = aws_codepipeline_webhook.main.url
}
