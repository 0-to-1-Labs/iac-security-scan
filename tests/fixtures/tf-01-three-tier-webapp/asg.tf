# Launch Template for EC2 Instances
resource "aws_launch_template" "main" {
  name_prefix   = "${var.project_name}-${var.environment}-lt-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = var.instance_type

  # Security Flaw: metadata_options block missing (no IMDSv2 enforcement)
  # Proper configuration would be:
  # metadata_options {
  #   http_endpoint               = "enabled"
  #   http_tokens                 = "required"  # IMDSv2 enforcement
  #   http_put_response_hop_limit = 1
  #   instance_metadata_tags      = "enabled"
  # }

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2.name
  }

  vpc_security_group_ids = [aws_security_group.app.id]

  user_data = base64encode(templatefile("${path.module}/user-data.sh", {
    project_name = var.project_name
    environment  = var.environment
    region       = var.aws_region
    db_endpoint  = aws_db_instance.main.endpoint
    db_name      = var.db_name
  }))

  monitoring {
    enabled = true
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      iops                  = 3000
      throughput            = 125
      delete_on_termination = true
      encrypted             = true
    }
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "${var.project_name}-${var.environment}-app-server"
    }
  }

  tag_specifications {
    resource_type = "volume"

    tags = {
      Name = "${var.project_name}-${var.environment}-app-volume"
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-launch-template"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "main" {
  name                = "${var.project_name}-${var.environment}-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.app.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  min_size         = var.asg_min_size
  max_size         = var.asg_max_size
  desired_capacity = var.asg_desired_capacity

  launch_template {
    id      = aws_launch_template.main.id
    version = "$Latest"
  }

  enabled_metrics = [
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupTotalInstances"
  ]

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 300
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-${var.environment}-asg-instance"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }

  tag {
    key                 = "ManagedBy"
    value               = "terraform"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [desired_capacity]
  }
}

# Auto Scaling Policy - Target Tracking (CPU)
resource "aws_autoscaling_policy" "cpu" {
  name                   = "${var.project_name}-${var.environment}-cpu-scaling"
  autoscaling_group_name = aws_autoscaling_group.main.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# Auto Scaling Policy - Target Tracking (ALB Request Count)
resource "aws_autoscaling_policy" "alb_request_count" {
  name                   = "${var.project_name}-${var.environment}-request-count-scaling"
  autoscaling_group_name = aws_autoscaling_group.main.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "${aws_lb.main.arn_suffix}/${aws_lb_target_group.app.arn_suffix}"
    }
    target_value = 1000.0
  }
}

# CloudWatch Alarms for ASG
resource "aws_cloudwatch_metric_alarm" "asg_high_cpu" {
  alarm_name          = "${var.project_name}-${var.environment}-asg-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = []

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.main.name
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-asg-high-cpu-alarm"
  }
}
