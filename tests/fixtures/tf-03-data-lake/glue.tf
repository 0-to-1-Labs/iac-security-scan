# Glue Data Catalog Database
resource "aws_glue_catalog_database" "main" {
  name        = "${var.project_name}_${var.environment}_catalog"
  description = "Data catalog for ${var.project_name} data lake"

  catalog_id = data.aws_caller_identity.current.account_id

  create_table_default_permission {
    permissions = ["SELECT"]

    principal {
      data_lake_principal_identifier = "IAM_ALLOWED_PRINCIPALS"
    }
  }
}

# Glue Crawler for Raw Zone
resource "aws_glue_crawler" "raw_zone" {
  name          = "${var.project_name}-raw-zone-crawler-${var.environment}"
  role          = aws_iam_role.glue_crawler.arn
  database_name = aws_glue_catalog_database.main.name

  description = "Crawler for raw zone data discovery"

  s3_target {
    path = "s3://${aws_s3_bucket.raw_zone.id}/"
  }

  schema_change_policy {
    delete_behavior = "LOG"
    update_behavior = "UPDATE_IN_DATABASE"
  }

  configuration = jsonencode({
    Version = 1.0
    Grouping = {
      TableGroupingPolicy = "CombineCompatibleSchemas"
    }
    CrawlerOutput = {
      Partitions = {
        AddOrUpdateBehavior = "InheritFromTable"
      }
    }
  })

  schedule = var.glue_crawler_schedule

  tags = {
    Zone = "raw"
  }
}

# Glue Crawler for Processed Zone
resource "aws_glue_crawler" "processed_zone" {
  name          = "${var.project_name}-processed-zone-crawler-${var.environment}"
  role          = aws_iam_role.glue_crawler.arn
  database_name = aws_glue_catalog_database.main.name

  description = "Crawler for processed zone data discovery"

  s3_target {
    path = "s3://${aws_s3_bucket.processed_zone.id}/"
  }

  schema_change_policy {
    delete_behavior = "LOG"
    update_behavior = "UPDATE_IN_DATABASE"
  }

  configuration = jsonencode({
    Version = 1.0
    Grouping = {
      TableGroupingPolicy = "CombineCompatibleSchemas"
    }
    CrawlerOutput = {
      Partitions = {
        AddOrUpdateBehavior = "InheritFromTable"
      }
    }
  })

  schedule = var.glue_crawler_schedule

  tags = {
    Zone = "processed"
  }
}

# Glue ETL Job - Raw to Processed transformation
resource "aws_glue_job" "etl_job" {
  name        = "${var.project_name}-raw-to-processed-etl-${var.environment}"
  role_arn    = aws_iam_role.glue_job.arn
  description = "ETL job to transform raw data to processed zone"

  glue_version      = "4.0"
  max_retries       = 2
  timeout           = 60
  worker_type       = "G.1X"
  number_of_workers = 5

  command {
    name            = "glueetl"
    script_location = "s3://${aws_s3_bucket.processed_zone.id}/scripts/raw_to_processed_etl.py"
    python_version  = "3"
  }

  default_arguments = {
    "--job-language"                     = "python"
    "--job-bookmark-option"              = "job-bookmark-enable"
    "--enable-metrics"                   = "true"
    "--enable-continuous-cloudwatch-log" = "true"
    "--enable-spark-ui"                  = "true"
    "--spark-event-logs-path"            = "s3://${aws_s3_bucket.processed_zone.id}/spark-logs/"
    "--TempDir"                          = "s3://${aws_s3_bucket.processed_zone.id}/temp/"
    "--raw_bucket"                       = aws_s3_bucket.raw_zone.id
    "--processed_bucket"                 = aws_s3_bucket.processed_zone.id
    "--database_name"                    = aws_glue_catalog_database.main.name
  }

  execution_property {
    max_concurrent_runs = 3
  }

  tags = {
    Purpose = "data-transformation"
  }
}

# Glue ETL Job - Processed to Curated transformation
resource "aws_glue_job" "curated_etl_job" {
  name        = "${var.project_name}-processed-to-curated-etl-${var.environment}"
  role_arn    = aws_iam_role.glue_job.arn
  description = "ETL job to transform processed data to curated zone"

  glue_version      = "4.0"
  max_retries       = 2
  timeout           = 120
  worker_type       = "G.2X"
  number_of_workers = 10

  command {
    name            = "glueetl"
    script_location = "s3://${aws_s3_bucket.curated_zone.id}/scripts/processed_to_curated_etl.py"
    python_version  = "3"
  }

  default_arguments = {
    "--job-language"                     = "python"
    "--job-bookmark-option"              = "job-bookmark-enable"
    "--enable-metrics"                   = "true"
    "--enable-continuous-cloudwatch-log" = "true"
    "--enable-spark-ui"                  = "true"
    "--spark-event-logs-path"            = "s3://${aws_s3_bucket.curated_zone.id}/spark-logs/"
    "--TempDir"                          = "s3://${aws_s3_bucket.curated_zone.id}/temp/"
    "--processed_bucket"                 = aws_s3_bucket.processed_zone.id
    "--curated_bucket"                   = aws_s3_bucket.curated_zone.id
    "--database_name"                    = aws_glue_catalog_database.main.name
  }

  execution_property {
    max_concurrent_runs = 2
  }

  tags = {
    Purpose = "data-aggregation"
  }
}

# Glue Workflow to orchestrate crawlers and ETL jobs
resource "aws_glue_workflow" "main" {
  name        = "${var.project_name}-etl-workflow-${var.environment}"
  description = "Orchestrates data lake ETL pipeline"

  max_concurrent_runs = 1

  tags = {
    Purpose = "etl-orchestration"
  }
}

# Glue Trigger - Start workflow on schedule
resource "aws_glue_trigger" "scheduled_start" {
  name          = "${var.project_name}-scheduled-trigger-${var.environment}"
  type          = "SCHEDULED"
  workflow_name = aws_glue_workflow.main.name

  schedule = var.glue_crawler_schedule

  actions {
    crawler_name = aws_glue_crawler.raw_zone.name
  }

  tags = {
    Purpose = "workflow-scheduler"
  }
}

# Glue Trigger - Start ETL after raw crawler completes
resource "aws_glue_trigger" "etl_after_raw_crawler" {
  name          = "${var.project_name}-etl-trigger-${var.environment}"
  type          = "CONDITIONAL"
  workflow_name = aws_glue_workflow.main.name

  predicate {
    conditions {
      crawler_name = aws_glue_crawler.raw_zone.name
      crawl_state  = "SUCCEEDED"
    }
  }

  actions {
    job_name = aws_glue_job.etl_job.name
  }

  tags = {
    Purpose = "etl-orchestration"
  }
}

# Glue Trigger - Start processed crawler after ETL completes
resource "aws_glue_trigger" "crawler_after_etl" {
  name          = "${var.project_name}-processed-crawler-trigger-${var.environment}"
  type          = "CONDITIONAL"
  workflow_name = aws_glue_workflow.main.name

  predicate {
    conditions {
      job_name = aws_glue_job.etl_job.name
      state    = "SUCCEEDED"
    }
  }

  actions {
    crawler_name = aws_glue_crawler.processed_zone.name
  }

  tags = {
    Purpose = "etl-orchestration"
  }
}
