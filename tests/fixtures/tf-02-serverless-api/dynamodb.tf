# DynamoDB table for storing items
resource "aws_dynamodb_table" "main" {
  name           = "${var.project_name}-${var.environment}-items"
  billing_mode   = var.dynamodb_billing_mode
  hash_key       = "id"
  range_key      = "created_at"

  # SECURITY FLAW #2: Server-side encryption block is omitted
  # This defaults to AWS owned key (not customer managed KMS key)
  # Best practice would be to use:
  # server_side_encryption {
  #   enabled     = true
  #   kms_key_arn = aws_kms_key.dynamodb.arn
  # }

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "N"
  }

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "category"
    type = "S"
  }

  # Global Secondary Index for querying by user
  global_secondary_index {
    name            = "UserIndex"
    hash_key        = "user_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # Global Secondary Index for querying by status
  global_secondary_index {
    name            = "StatusIndex"
    hash_key        = "status"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # Global Secondary Index for querying by category
  global_secondary_index {
    name            = "CategoryIndex"
    hash_key        = "category"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # Enable point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  # Enable TTL for automatic item expiration
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Enable streams for event processing
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  tags = {
    Name = "${var.project_name}-${var.environment}-items"
  }
}

# CloudWatch alarm for read capacity
resource "aws_cloudwatch_metric_alarm" "dynamodb_read_throttle" {
  alarm_name          = "${var.project_name}-${var.environment}-dynamodb-read-throttle"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ReadThrottleEvents"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors DynamoDB read throttle events"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.main.name
  }
}

# CloudWatch alarm for write capacity
resource "aws_cloudwatch_metric_alarm" "dynamodb_write_throttle" {
  alarm_name          = "${var.project_name}-${var.environment}-dynamodb-write-throttle"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "WriteThrottleEvents"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors DynamoDB write throttle events"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.main.name
  }
}
