# CodeDeploy application
resource "aws_codedeploy_app" "main" {
  name             = "${var.project_name}-${var.environment}"
  compute_platform = "Server"

  tags = {
    Name = "${var.project_name}-codedeploy-app"
  }
}

# CodeDeploy deployment group
resource "aws_codedeploy_deployment_group" "main" {
  app_name               = aws_codedeploy_app.main.name
  deployment_group_name  = "${var.project_name}-${var.environment}-deployment-group"
  service_role_arn       = aws_iam_role.codedeploy.arn
  deployment_config_name = var.deployment_config_name

  # EC2 tag filter for instances to deploy to
  ec2_tag_filter {
    key   = var.deployment_instances.key
    type  = var.deployment_instances.type
    value = var.deployment_instances.value
  }

  # Additional tag filters for more precise targeting
  ec2_tag_filter {
    key   = "Application"
    type  = "KEY_AND_VALUE"
    value = var.project_name
  }

  # Auto rollback configuration
  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE", "DEPLOYMENT_STOP_ON_ALARM"]
  }

  # Alarm configuration for deployment monitoring
  alarm_configuration {
    enabled = true
    alarms = [
      aws_cloudwatch_metric_alarm.deployment_errors.alarm_name
    ]
  }

  # Blue/Green deployment configuration (commented out for in-place)
  # deployment_style {
  #   deployment_option = "WITH_TRAFFIC_CONTROL"
  #   deployment_type   = "BLUE_GREEN"
  # }

  # Load balancer info (if using ALB/ELB)
  # load_balancer_info {
  #   target_group_info {
  #     name = aws_lb_target_group.main.name
  #   }
  # }

  tags = {
    Name = "${var.project_name}-deployment-group"
  }
}

# CloudWatch alarm for deployment monitoring
resource "aws_cloudwatch_metric_alarm" "deployment_errors" {
  alarm_name          = "${var.project_name}-${var.environment}-deployment-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FailedDeployments"
  namespace           = "AWS/CodeDeploy"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Monitor CodeDeploy deployment failures"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ApplicationName     = aws_codedeploy_app.main.name
    DeploymentGroupName = aws_codedeploy_deployment_group.main.deployment_group_name
  }

  alarm_actions = [aws_sns_topic.pipeline_notifications.arn]

  tags = {
    Name = "${var.project_name}-deployment-alarm"
  }
}

# CodeDeploy deployment configuration (custom, optional)
resource "aws_codedeploy_deployment_config" "gradual" {
  deployment_config_name = "${var.project_name}-${var.environment}-gradual-deployment"
  compute_platform       = "Server"

  minimum_healthy_hosts {
    type  = "FLEET_PERCENT"
    value = 75
  }

  traffic_routing_config {
    type = "AllAtOnce"
  }
}
