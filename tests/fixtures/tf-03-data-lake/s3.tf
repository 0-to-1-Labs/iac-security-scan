# Raw Zone Bucket - Landing zone for raw ingested data
resource "aws_s3_bucket" "raw_zone" {
  bucket = "${var.project_name}-raw-zone-${var.environment}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Zone               = "raw"
    DataClassification = var.data_classification
  }
}

# SECURITY FLAW #1: Using AES256 instead of customer-managed KMS key
resource "aws_s3_bucket_server_side_encryption_configuration" "raw_zone" {
  bucket = aws_s3_bucket.raw_zone.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# SECURITY FLAW #4: Versioning not enabled on raw zone
# (Versioning resource is commented out or missing)

resource "aws_s3_bucket_public_access_block" "raw_zone" {
  bucket = aws_s3_bucket.raw_zone.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "raw_zone" {
  bucket = aws_s3_bucket.raw_zone.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = var.raw_zone_retention_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.raw_zone_retention_days + 90
      storage_class = "GLACIER"
    }

    expiration {
      days = var.raw_zone_retention_days + 365
    }
  }

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Processed Zone Bucket - Cleaned and transformed data
resource "aws_s3_bucket" "processed_zone" {
  bucket = "${var.project_name}-processed-zone-${var.environment}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Zone               = "processed"
    DataClassification = var.data_classification
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "processed_zone" {
  bucket = aws_s3_bucket.processed_zone.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.datalake.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "processed_zone" {
  bucket = aws_s3_bucket.processed_zone.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "processed_zone" {
  bucket = aws_s3_bucket.processed_zone.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "processed_zone" {
  bucket = aws_s3_bucket.processed_zone.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = var.processed_zone_retention_days
      storage_class = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Curated Zone Bucket - Business-ready, optimized data
resource "aws_s3_bucket" "curated_zone" {
  bucket = "${var.project_name}-curated-zone-${var.environment}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Zone               = "curated"
    DataClassification = var.data_classification
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "curated_zone" {
  bucket = aws_s3_bucket.curated_zone.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.datalake.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "curated_zone" {
  bucket = aws_s3_bucket.curated_zone.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "curated_zone" {
  bucket = aws_s3_bucket.curated_zone.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "curated_zone" {
  bucket = aws_s3_bucket.curated_zone.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = var.curated_zone_retention_days
      storage_class = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = 60
      storage_class   = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = 180
    }
  }
}

# Athena Query Results Bucket
resource "aws_s3_bucket" "athena_results" {
  bucket = "${var.project_name}-athena-results-${var.environment}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Purpose = "athena-query-results"
  }
}

# SECURITY FLAW #2: No access logging enabled for S3 buckets
# (Missing aws_s3_bucket_logging resources)

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.datalake.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-query-results"
    status = "Enabled"

    expiration {
      days = var.athena_query_result_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}
