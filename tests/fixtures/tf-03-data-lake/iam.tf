# IAM Role for Glue Crawlers
resource "aws_iam_role" "glue_crawler" {
  name               = "${var.project_name}-glue-crawler-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.glue_assume_role.json

  tags = {
    Purpose = "glue-crawler"
  }
}

data "aws_iam_policy_document" "glue_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["glue.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy_attachment" "glue_crawler_service" {
  role       = aws_iam_role.glue_crawler.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "glue_crawler_s3" {
  name = "${var.project_name}-glue-crawler-s3-policy-${var.environment}"
  role = aws_iam_role.glue_crawler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.raw_zone.arn,
          "${aws_s3_bucket.raw_zone.arn}/*",
          aws_s3_bucket.processed_zone.arn,
          "${aws_s3_bucket.processed_zone.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = [aws_kms_key.datalake.arn]
      }
    ]
  })
}

# IAM Role for Glue Jobs
resource "aws_iam_role" "glue_job" {
  name               = "${var.project_name}-glue-job-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.glue_assume_role.json

  tags = {
    Purpose = "glue-etl-job"
  }
}

resource "aws_iam_role_policy_attachment" "glue_job_service" {
  role       = aws_iam_role.glue_job.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

# SECURITY FLAW #3: Overly permissive IAM role with s3:* on all resources
resource "aws_iam_role_policy" "glue_job_s3" {
  name = "${var.project_name}-glue-job-s3-policy-${var.environment}"
  role = aws_iam_role.glue_job.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = [aws_kms_key.datalake.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy" "glue_job_cloudwatch" {
  name = "${var.project_name}-glue-job-cloudwatch-policy-${var.environment}"
  role = aws_iam_role.glue_job.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws-glue/*"
        ]
      }
    ]
  })
}

# IAM Role for Lake Formation Admin
resource "aws_iam_role" "lakeformation_admin" {
  name = "${var.project_name}-lakeformation-admin-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lakeformation.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Purpose = "lake-formation-admin"
  }
}

resource "aws_iam_role_policy" "lakeformation_admin_s3" {
  name = "${var.project_name}-lakeformation-admin-s3-policy-${var.environment}"
  role = aws_iam_role.lakeformation_admin.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.raw_zone.arn,
          "${aws_s3_bucket.raw_zone.arn}/*",
          aws_s3_bucket.processed_zone.arn,
          "${aws_s3_bucket.processed_zone.arn}/*",
          aws_s3_bucket.curated_zone.arn,
          "${aws_s3_bucket.curated_zone.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = [aws_kms_key.datalake.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lakeformation_admin" {
  role       = aws_iam_role.lakeformation_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AWSLakeFormationDataAdmin"
}

# IAM Role for Athena query execution
resource "aws_iam_role" "athena_execution" {
  name = "${var.project_name}-athena-execution-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "athena.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Purpose = "athena-query-execution"
  }
}

resource "aws_iam_role_policy" "athena_execution_s3" {
  name = "${var.project_name}-athena-execution-s3-policy-${var.environment}"
  role = aws_iam_role.athena_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.processed_zone.arn,
          "${aws_s3_bucket.processed_zone.arn}/*",
          aws_s3_bucket.curated_zone.arn,
          "${aws_s3_bucket.curated_zone.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.athena_results.arn,
          "${aws_s3_bucket.athena_results.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = [aws_kms_key.datalake.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy" "athena_execution_glue" {
  name = "${var.project_name}-athena-execution-glue-policy-${var.environment}"
  role = aws_iam_role.athena_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetPartitions",
          "glue:GetPartition"
        ]
        Resource = [
          "arn:aws:glue:${var.aws_region}:${data.aws_caller_identity.current.account_id}:catalog",
          "arn:aws:glue:${var.aws_region}:${data.aws_caller_identity.current.account_id}:database/${aws_glue_catalog_database.main.name}",
          "arn:aws:glue:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${aws_glue_catalog_database.main.name}/*"
        ]
      }
    ]
  })
}
