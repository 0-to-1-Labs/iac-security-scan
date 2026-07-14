# Athena Workgroup for Data Lake queries
resource "aws_athena_workgroup" "main" {
  name        = "${var.project_name}-workgroup-${var.environment}"
  description = "Athena workgroup for ${var.project_name} data lake queries"
  state       = "ENABLED"

  configuration {
    # SECURITY FLAW #5: Query result encryption not enabled
    # (encryption_configuration block is missing)

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.id}/query-results/"
    }

    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    engine_version {
      selected_engine_version = "Athena engine version 3"
    }
  }

  tags = {
    Purpose = "data-analytics"
  }
}

# Athena Named Query - Sample queries for common data access patterns
resource "aws_athena_named_query" "customer_analytics" {
  name        = "customer_analytics_summary"
  description = "Query to analyze customer behavior patterns"
  database    = aws_glue_catalog_database.main.name
  workgroup   = aws_athena_workgroup.main.id

  query = <<-EOF
    SELECT
      customer_id,
      COUNT(*) as transaction_count,
      SUM(amount) as total_spent,
      AVG(amount) as avg_transaction_value,
      MAX(transaction_date) as last_transaction_date
    FROM curated.customer_transactions
    WHERE transaction_date >= DATE_ADD('month', -12, CURRENT_DATE)
    GROUP BY customer_id
    HAVING COUNT(*) > 5
    ORDER BY total_spent DESC
    LIMIT 100;
  EOF
}

resource "aws_athena_named_query" "daily_metrics" {
  name        = "daily_metrics_rollup"
  description = "Daily aggregated metrics for reporting"
  database    = aws_glue_catalog_database.main.name
  workgroup   = aws_athena_workgroup.main.id

  query = <<-EOF
    SELECT
      DATE(event_timestamp) as event_date,
      event_type,
      COUNT(*) as event_count,
      COUNT(DISTINCT user_id) as unique_users,
      AVG(session_duration_seconds) as avg_session_duration
    FROM processed.user_events
    WHERE DATE(event_timestamp) = CURRENT_DATE - INTERVAL '1' DAY
    GROUP BY DATE(event_timestamp), event_type
    ORDER BY event_date DESC, event_count DESC;
  EOF
}

resource "aws_athena_named_query" "revenue_by_product" {
  name        = "revenue_by_product_category"
  description = "Revenue analysis by product category"
  database    = aws_glue_catalog_database.main.name
  workgroup   = aws_athena_workgroup.main.id

  query = <<-EOF
    SELECT
      p.category,
      p.subcategory,
      COUNT(DISTINCT o.order_id) as order_count,
      SUM(o.quantity * p.unit_price) as total_revenue,
      AVG(o.quantity * p.unit_price) as avg_order_value
    FROM curated.orders o
    JOIN curated.products p ON o.product_id = p.product_id
    WHERE o.order_date >= DATE_ADD('month', -3, CURRENT_DATE)
    GROUP BY p.category, p.subcategory
    ORDER BY total_revenue DESC;
  EOF
}

resource "aws_athena_named_query" "data_quality_check" {
  name        = "data_quality_validation"
  description = "Data quality checks for raw zone ingestion"
  database    = aws_glue_catalog_database.main.name
  workgroup   = aws_athena_workgroup.main.id

  query = <<-EOF
    SELECT
      table_name,
      COUNT(*) as total_records,
      COUNT(DISTINCT partition_date) as partition_count,
      MIN(ingestion_timestamp) as earliest_record,
      MAX(ingestion_timestamp) as latest_record,
      SUM(CASE WHEN primary_key IS NULL THEN 1 ELSE 0 END) as null_pk_count,
      SUM(CASE WHEN data_validation_flag = 'INVALID' THEN 1 ELSE 0 END) as invalid_records
    FROM raw.data_ingestion_log
    WHERE partition_date = CURRENT_DATE - INTERVAL '1' DAY
    GROUP BY table_name
    ORDER BY table_name;
  EOF
}

# Athena Data Catalog for external Hive metastore (optional)
resource "aws_athena_data_catalog" "glue_catalog" {
  name        = "${var.project_name}-glue-catalog-${var.environment}"
  description = "AWS Glue Data Catalog integration"
  type        = "GLUE"

  parameters = {
    "catalog-id" = data.aws_caller_identity.current.account_id
  }

  tags = {
    Purpose = "metadata-management"
  }
}
