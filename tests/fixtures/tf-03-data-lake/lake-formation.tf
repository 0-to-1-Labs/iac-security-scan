# Lake Formation Settings
resource "aws_lakeformation_data_lake_settings" "main" {
  count = var.enable_lake_formation ? 1 : 0

  admins = [
    aws_iam_role.lakeformation_admin.arn
  ]

  create_database_default_permissions {
    permissions = ["ALL"]

    principal {
      data_lake_principal_identifier = aws_iam_role.lakeformation_admin.arn
    }
  }

  create_table_default_permissions {
    permissions = ["ALL"]

    principal {
      data_lake_principal_identifier = aws_iam_role.lakeformation_admin.arn
    }
  }

  trusted_resource_owners = [
    data.aws_caller_identity.current.account_id
  ]
}

# Lake Formation Resource - Register S3 locations
resource "aws_lakeformation_resource" "raw_zone" {
  count = var.enable_lake_formation ? 1 : 0

  arn      = aws_s3_bucket.raw_zone.arn
  role_arn = aws_iam_role.lakeformation_admin.arn
}

resource "aws_lakeformation_resource" "processed_zone" {
  count = var.enable_lake_formation ? 1 : 0

  arn      = aws_s3_bucket.processed_zone.arn
  role_arn = aws_iam_role.lakeformation_admin.arn
}

resource "aws_lakeformation_resource" "curated_zone" {
  count = var.enable_lake_formation ? 1 : 0

  arn      = aws_s3_bucket.curated_zone.arn
  role_arn = aws_iam_role.lakeformation_admin.arn
}

# Lake Formation Permissions - Database level
resource "aws_lakeformation_permissions" "glue_job_database" {
  count = var.enable_lake_formation ? 1 : 0

  principal   = aws_iam_role.glue_job.arn
  permissions = ["CREATE_TABLE", "ALTER", "DROP", "DESCRIBE"]

  database {
    name = aws_glue_catalog_database.main.name
  }
}

# Lake Formation Permissions - Table level for Glue jobs
resource "aws_lakeformation_permissions" "glue_job_tables" {
  count = var.enable_lake_formation ? 1 : 0

  principal   = aws_iam_role.glue_job.arn
  permissions = ["SELECT", "INSERT", "DELETE", "DESCRIBE", "ALTER"]

  table {
    database_name = aws_glue_catalog_database.main.name
    wildcard      = true
  }
}

# Lake Formation Permissions - Data location for Glue
resource "aws_lakeformation_permissions" "glue_job_data_location" {
  count = var.enable_lake_formation ? 1 : 0

  principal   = aws_iam_role.glue_job.arn
  permissions = ["DATA_LOCATION_ACCESS"]

  data_location {
    arn = aws_s3_bucket.processed_zone.arn
  }
}

resource "aws_lakeformation_permissions" "glue_job_curated_location" {
  count = var.enable_lake_formation ? 1 : 0

  principal   = aws_iam_role.glue_job.arn
  permissions = ["DATA_LOCATION_ACCESS"]

  data_location {
    arn = aws_s3_bucket.curated_zone.arn
  }
}

# Lake Formation Permissions - Crawler access
resource "aws_lakeformation_permissions" "crawler_database" {
  count = var.enable_lake_formation ? 1 : 0

  principal   = aws_iam_role.glue_crawler.arn
  permissions = ["CREATE_TABLE", "ALTER", "DESCRIBE"]

  database {
    name = aws_glue_catalog_database.main.name
  }
}

resource "aws_lakeformation_permissions" "crawler_tables" {
  count = var.enable_lake_formation ? 1 : 0

  principal   = aws_iam_role.glue_crawler.arn
  permissions = ["SELECT", "INSERT", "ALTER", "DESCRIBE"]

  table {
    database_name = aws_glue_catalog_database.main.name
    wildcard      = true
  }
}
