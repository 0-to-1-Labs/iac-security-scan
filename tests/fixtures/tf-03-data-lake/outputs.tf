output "raw_zone_bucket_name" {
  description = "Name of the raw zone S3 bucket"
  value       = aws_s3_bucket.raw_zone.id
}

output "raw_zone_bucket_arn" {
  description = "ARN of the raw zone S3 bucket"
  value       = aws_s3_bucket.raw_zone.arn
}

output "processed_zone_bucket_name" {
  description = "Name of the processed zone S3 bucket"
  value       = aws_s3_bucket.processed_zone.id
}

output "processed_zone_bucket_arn" {
  description = "ARN of the processed zone S3 bucket"
  value       = aws_s3_bucket.processed_zone.arn
}

output "curated_zone_bucket_name" {
  description = "Name of the curated zone S3 bucket"
  value       = aws_s3_bucket.curated_zone.id
}

output "curated_zone_bucket_arn" {
  description = "ARN of the curated zone S3 bucket"
  value       = aws_s3_bucket.curated_zone.arn
}

output "athena_results_bucket_name" {
  description = "Name of the Athena query results S3 bucket"
  value       = aws_s3_bucket.athena_results.id
}

output "glue_database_name" {
  description = "Name of the Glue Data Catalog database"
  value       = aws_glue_catalog_database.main.name
}

output "glue_crawler_raw_name" {
  description = "Name of the Glue crawler for raw zone"
  value       = aws_glue_crawler.raw_zone.name
}

output "glue_crawler_processed_name" {
  description = "Name of the Glue crawler for processed zone"
  value       = aws_glue_crawler.processed_zone.name
}

output "glue_etl_job_name" {
  description = "Name of the Glue ETL job"
  value       = aws_glue_job.etl_job.name
}

output "athena_workgroup_name" {
  description = "Name of the Athena workgroup"
  value       = aws_athena_workgroup.main.name
}

output "glue_job_role_arn" {
  description = "ARN of the IAM role for Glue jobs"
  value       = aws_iam_role.glue_job.arn
}

output "kms_key_id" {
  description = "ID of the KMS key for data lake encryption"
  value       = aws_kms_key.datalake.key_id
}

output "kms_key_arn" {
  description = "ARN of the KMS key for data lake encryption"
  value       = aws_kms_key.datalake.arn
}
