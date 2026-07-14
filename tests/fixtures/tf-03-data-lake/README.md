# Data Lake Platform - Terraform Configuration

## Overview

This Terraform configuration deploys a production-ready AWS data lake platform with a three-tier architecture (raw, processed, curated zones) using AWS Glue, Athena, and S3. The platform is designed for scalable data ingestion, transformation, and analytics workflows.

## Architecture

### Data Zones

1. **Raw Zone** (`raw-zone` bucket)
   - Landing zone for raw, unprocessed data ingestion
   - Lifecycle policies for cost optimization (transition to IA after 90 days)
   - Server-side encryption enabled
   - No data transformation applied

2. **Processed Zone** (`processed-zone` bucket)
   - Cleaned, validated, and transformed data
   - KMS-encrypted with customer-managed keys
   - Versioning enabled for data lineage
   - Partitioned and optimized for query performance

3. **Curated Zone** (`curated-zone` bucket)
   - Business-ready, aggregated datasets
   - Optimized for analytics and reporting
   - KMS-encrypted with customer-managed keys
   - Long-term retention policies

### Components

- **AWS Glue Data Catalog**: Centralized metadata repository
- **Glue Crawlers**: Automated schema discovery for raw and processed zones
- **Glue ETL Jobs**: PySpark jobs for data transformation pipelines
- **Glue Workflows**: Orchestration of crawlers and ETL jobs
- **Amazon Athena**: SQL-based querying of data lake
- **AWS Lake Formation**: Fine-grained access control (optional)
- **KMS Keys**: Customer-managed encryption keys
- **IAM Roles**: Service roles for Glue, Athena, Lake Formation

## File Structure

```
.
├── main.tf              # Provider configuration and version requirements
├── variables.tf         # Input variables with defaults
├── outputs.tf           # Output values (bucket names, ARNs, etc.)
├── s3.tf                # S3 buckets for all data zones
├── glue.tf              # Glue catalog, crawlers, jobs, workflows
├── athena.tf            # Athena workgroups and named queries
├── lake-formation.tf    # Lake Formation settings and permissions
├── kms.tf               # KMS keys for encryption
├── iam.tf               # IAM roles and policies
└── README.md            # This file
```

## Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with appropriate credentials
- AWS account with permissions to create:
  - S3 buckets
  - Glue resources (catalog, crawlers, jobs)
  - Athena workgroups
  - Lake Formation settings
  - KMS keys
  - IAM roles and policies

## Usage

### Initialize Terraform

```bash
terraform init
```

### Review Configuration

```bash
terraform plan -var="environment=dev"
```

### Deploy Infrastructure

```bash
terraform apply -var="environment=prod" -var="project_name=mycompany-datalake"
```

### Destroy Infrastructure

```bash
terraform destroy -var="environment=dev"
```

## Configuration Variables

Key variables you can customize:

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region for deployment | `us-east-1` |
| `environment` | Environment name (dev/staging/prod) | `prod` |
| `project_name` | Project name for resource naming | `datalake` |
| `enable_lake_formation` | Enable AWS Lake Formation | `true` |
| `glue_crawler_schedule` | Cron schedule for crawlers | `cron(0 2 * * ? *)` |
| `raw_zone_retention_days` | Days before transitioning to IA | `90` |

See `variables.tf` for complete list.

## Data Pipeline Flow

1. **Ingestion**: Raw data lands in `raw-zone` bucket
2. **Crawling**: Glue crawler discovers schema and updates Data Catalog
3. **Transformation**: Glue ETL job processes raw → processed zone
4. **Cataloging**: Glue crawler updates schema for processed data
5. **Aggregation**: Second Glue job transforms processed → curated zone
6. **Querying**: Athena queries against processed/curated data

## Glue Workflow Orchestration

The workflow is triggered on schedule (default: daily at 2 AM UTC):

```
Scheduled Trigger
    ↓
Raw Zone Crawler
    ↓
ETL Job (Raw → Processed)
    ↓
Processed Zone Crawler
    ↓
ETL Job (Processed → Curated)
```

## Athena Query Examples

Pre-configured named queries are available in the workgroup:

- `customer_analytics_summary`: Customer behavior analysis
- `daily_metrics_rollup`: Daily aggregated metrics
- `revenue_by_product_category`: Revenue analysis
- `data_quality_validation`: Data quality checks

## Security Features

- **Encryption at Rest**: All S3 buckets encrypted (AES256 or KMS)
- **Encryption in Transit**: HTTPS enforced for all data access
- **Public Access Blocking**: All buckets block public access
- **IAM Least Privilege**: Service roles with minimal permissions
- **Lake Formation**: Fine-grained table/column-level access control
- **Versioning**: Enabled on processed and curated zones
- **KMS Key Rotation**: Annual automatic key rotation enabled

## Cost Optimization

- **Lifecycle Policies**: Automatic transition to cheaper storage classes
- **Intelligent Tiering**: Available for infrequently accessed data
- **Query Result Expiration**: Athena results auto-deleted after 30 days
- **Glue Job Bookmarks**: Process only new/changed data
- **Partitioning**: Reduced data scanned per query

## Monitoring and Logging

- **Glue Job Metrics**: Published to CloudWatch
- **Spark UI**: Enabled for job debugging
- **CloudWatch Logs**: Continuous log streaming for Glue jobs
- **Athena Query Metrics**: Published to CloudWatch
- **S3 Access Logs**: (Optional) Enable for audit trail

## Lake Formation Setup

If `enable_lake_formation = true`:

1. Lake Formation admin role is created
2. S3 locations registered as Lake Formation resources
3. Permissions granted to Glue roles for database/table access
4. Fine-grained access control replaces S3 bucket policies

## ETL Job Development

### Upload Glue Scripts

Before running ETL jobs, upload PySpark scripts to S3:

```bash
# Raw to Processed ETL script
aws s3 cp raw_to_processed_etl.py s3://datalake-processed-zone-prod-123456789012/scripts/

# Processed to Curated ETL script
aws s3 cp processed_to_curated_etl.py s3://datalake-curated-zone-prod-123456789012/scripts/
```

### Example ETL Script Structure

```python
import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job

args = getResolvedOptions(sys.argv, ['JOB_NAME', 'raw_bucket', 'processed_bucket'])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

# Your ETL logic here

job.commit()
```

## Outputs

After deployment, retrieve important values:

```bash
terraform output raw_zone_bucket_name
terraform output glue_database_name
terraform output athena_workgroup_name
terraform output kms_key_arn
```

## Troubleshooting

### Glue Crawler Fails

- Check IAM role has `AWSGlueServiceRole` policy
- Verify S3 bucket permissions
- Check Lake Formation permissions if enabled

### Glue Job Fails

- Review CloudWatch logs in `/aws-glue/jobs/`
- Check Spark UI for detailed execution plan
- Verify script location in S3
- Ensure sufficient DPU allocation

### Athena Query Fails

- Verify workgroup configuration
- Check S3 permissions for query results bucket
- Validate Glue Data Catalog table schema
- Review Lake Formation permissions

## Best Practices

1. **Partitioning**: Partition tables by date for query performance
2. **File Format**: Use Parquet/ORC for columnar storage
3. **Compression**: Enable compression (Snappy/GZIP) for cost savings
4. **Data Quality**: Implement validation checks in ETL jobs
5. **Version Control**: Store Glue scripts in Git
6. **Testing**: Test ETL jobs in dev environment first
7. **Monitoring**: Set up CloudWatch alarms for job failures
8. **Backup**: Enable S3 versioning and cross-region replication

## Compliance

This configuration supports compliance requirements for:

- Data encryption (at rest and in transit)
- Access control and auditing
- Data retention and lifecycle management
- Fine-grained permissions via Lake Formation

## Support

For issues or questions:

1. Check CloudWatch Logs for error details
2. Review AWS Glue documentation
3. Consult AWS Lake Formation best practices
4. Contact data engineering team

## License

Proprietary - Internal use only

## Version History

- v1.0.0 (2024-01-15): Initial production release
  - Three-tier data lake architecture
  - Glue ETL pipeline with workflow orchestration
  - Athena analytics workgroup
  - Lake Formation integration
  - KMS encryption
