# IoT Data Ingestion Platform

## Overview

This CloudFormation template deploys a production-grade IoT data ingestion platform for processing and storing telemetry data from IoT devices. The architecture is designed to handle high-throughput data ingestion, real-time transformation, and long-term data lake storage.

## Architecture

```
IoT Devices
    ↓
AWS IoT Core (Thing Types, Policies, Topic Rules)
    ↓
Kinesis Data Stream
    ↓
Kinesis Firehose (with Lambda transformation)
    ├→ Lambda Function (data transformation)
    │   └→ DynamoDB (device state updates)
    ↓
S3 Data Lake (partitioned by date)

CloudWatch (monitoring & alerts)
    └→ SNS (email notifications)
```

## Components

### IoT Core
- **Thing Types**: Defines sensor and gateway device types with searchable attributes
- **IoT Policy**: Permissions policy for device authentication and authorization
- **Topic Rule**: Routes device telemetry from `devices/+/telemetry` to Kinesis

### Data Ingestion Pipeline
- **Kinesis Data Stream**: High-throughput ingestion stream with configurable shards
- **Lambda Transformation**: Enriches data, validates, and updates device state
- **Kinesis Firehose**: Delivers transformed data to S3 with buffering and compression
- **S3 Data Lake**: Stores data with date partitioning and lifecycle policies

### Device State Management
- **DynamoDB Table**: Tracks current device state with TTL for automatic cleanup
- **Global Secondary Index**: Enables queries by device type and timestamp

### Monitoring
- **CloudWatch Alarms**: Monitors stream iterator age, Lambda errors, delivery failures, DynamoDB throttles
- **CloudWatch Dashboard**: Visualizes key metrics across all components
- **SNS Notifications**: Sends email alerts for operational issues

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| EnvironmentName | production | Environment tag for resources |
| DataRetentionDays | 90 | Days to retain data in S3 (30-365) |
| KinesisShardCount | 2 | Number of Kinesis stream shards (1-10) |
| FirehoseBufferSizeMB | 5 | Firehose buffer size in MB (1-128) |
| FirehoseBufferIntervalSeconds | 300 | Firehose buffer interval in seconds (60-900) |
| AlertEmail | alerts@example.com | Email for CloudWatch alarm notifications |

## Data Flow

### Ingestion Path
1. IoT devices publish telemetry to `devices/{deviceId}/telemetry`
2. IoT Topic Rule routes messages to Kinesis Data Stream
3. Firehose reads from Kinesis and invokes Lambda for transformation
4. Lambda enriches data and updates DynamoDB device state
5. Firehose delivers transformed data to S3 with GZIP compression

### Storage Structure
```
s3://bucket-name/
├── iot-data/
│   └── year=2024/
│       └── month=01/
│           └── day=15/
│               └── transformed-data-*.gz
├── backup/
│   └── year=2024/
│       └── month=01/
│           └── day=15/
│               └── raw-data-*.gz
└── errors/
    └── processing-failed/
        └── year=2024/
            └── month=01/
                └── day=15/
```

## Deployment

### Prerequisites
- AWS CLI configured with appropriate credentials
- Permissions to create IAM roles, S3 buckets, Kinesis streams, Lambda functions, IoT resources

### Deploy Stack
```bash
aws cloudformation create-stack \
  --stack-name iot-ingestion-platform \
  --template-body file://template.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

### Update Stack
```bash
aws cloudformation update-stack \
  --stack-name iot-ingestion-platform \
  --template-body file://template.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

### Delete Stack
```bash
# Empty S3 bucket first
aws s3 rm s3://$(aws cloudformation describe-stacks \
  --stack-name iot-ingestion-platform \
  --query 'Stacks[0].Outputs[?OutputKey==`DataLakeBucketName`].OutputValue' \
  --output text) --recursive

# Delete stack
aws cloudformation delete-stack \
  --stack-name iot-ingestion-platform \
  --region us-east-1
```

## Device Integration

### Create IoT Thing
```bash
STACK_NAME="iot-ingestion-platform"

# Create thing
aws iot create-thing \
  --thing-name sensor-001 \
  --thing-type-name $(aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --query 'Stacks[0].Outputs[?OutputKey==`SensorThingTypeName`].OutputValue' \
    --output text)

# Create certificate
aws iot create-keys-and-certificate \
  --set-as-active \
  --certificate-pem-outfile sensor-001.cert.pem \
  --public-key-outfile sensor-001.public.key \
  --private-key-outfile sensor-001.private.key

# Attach policy to certificate
aws iot attach-policy \
  --policy-name $(aws cloudformation describe-stacks \
    --stack-name $STACK_NAME \
    --query 'Stacks[0].Outputs[?OutputKey==`DevicePolicyName`].OutputValue' \
    --output text) \
  --target <certificate-arn>

# Attach certificate to thing
aws iot attach-thing-principal \
  --thing-name sensor-001 \
  --principal <certificate-arn>
```

### Publish Test Data
```bash
# Get IoT endpoint
IOT_ENDPOINT=$(aws iot describe-endpoint --endpoint-type iot:Data-ATS --query 'endpointAddress' --output text)

# Publish telemetry
aws iot-data publish \
  --topic "devices/sensor-001/telemetry" \
  --cli-binary-format raw-in-base64-out \
  --payload '{
    "deviceId": "sensor-001",
    "deviceType": "temperature-sensor",
    "timestamp": 1705334400,
    "measurements": {
      "temperature": 22.5,
      "humidity": 45.2,
      "pressure": 1013.25
    }
  }'
```

## Data Format

### Input Message (from IoT devices)
```json
{
  "deviceId": "sensor-001",
  "deviceType": "temperature-sensor",
  "timestamp": 1705334400,
  "measurements": {
    "temperature": 22.5,
    "humidity": 45.2,
    "pressure": 1013.25
  }
}
```

### Transformed Message (stored in S3)
```json
{
  "deviceId": "sensor-001",
  "deviceType": "temperature-sensor",
  "timestamp": 1705334400,
  "measurements": {
    "temperature": 22.5,
    "temperature_f": 72.5,
    "humidity": 45.2,
    "pressure": 1013.25
  },
  "metadata": {
    "processingTime": "2024-01-15T12:00:00.000Z",
    "version": "1.0",
    "source": "iot-core"
  }
}
```

## Monitoring

### CloudWatch Dashboard
Access the dashboard to view:
- Kinesis ingestion rate (records/sec, bytes/sec)
- Lambda transformation metrics (invocations, errors, duration)
- Firehose delivery metrics (success rate, data freshness)
- DynamoDB capacity consumption and errors

Dashboard URL is provided in CloudFormation outputs.

### Alarms
The stack creates the following alarms:
- **Stream Iterator Age**: Alerts when data processing falls behind
- **Lambda Errors**: Alerts when transformation failures exceed threshold
- **Firehose Delivery Failures**: Alerts when S3 delivery success rate drops
- **DynamoDB Throttles**: Alerts when requests are throttled

All alarms send notifications to the configured email address.

### Logs
- **Lambda Logs**: `/aws/lambda/{stack-name}-data-transformer`
- **Firehose Logs**: `/aws/kinesisfirehose/{stack-name}-delivery-stream`
- **IoT Rule Errors**: `/aws/iot/{stack-name}-rule-errors`

## Data Lifecycle

### S3 Lifecycle Policy
- **Day 0-30**: STANDARD storage class
- **Day 30-90**: Transition to STANDARD_IA
- **Day 90-retention**: Transition to GLACIER
- **After retention period**: Automatic deletion

### DynamoDB TTL
Device state records are automatically deleted after 90 days using the `ttl` attribute.

## Cost Optimization

### Estimated Monthly Costs (US East 1)
Based on 1,000 devices sending data every 5 minutes:

| Service | Usage | Est. Cost |
|---------|-------|-----------|
| IoT Core | 8.64M messages/month | $8.64 |
| Kinesis Data Stream | 2 shards × 730 hours | $29.20 |
| Kinesis Firehose | 25 GB ingested | $1.25 |
| Lambda | 8.64M invocations @ 512MB | $17.28 |
| DynamoDB | On-demand, 8.64M writes | $10.80 |
| S3 Storage | 100 GB (compressed) | $2.30 |
| CloudWatch Logs | 5 GB ingested | $2.50 |
| **Total** | | **~$72/month** |

### Optimization Tips
- Adjust Kinesis shard count based on actual throughput
- Tune Firehose buffer settings to reduce Lambda invocations
- Use S3 Intelligent-Tiering for unpredictable access patterns
- Set appropriate CloudWatch Logs retention periods
- Implement data sampling for less critical metrics

## Security Considerations

### Authentication & Authorization
- Devices authenticate using X.509 certificates
- IoT policy restricts device actions and topics
- IAM roles follow principle of least privilege

### Data Protection
- Data in transit: HTTPS for IoT Core, encrypted Kinesis connections
- Data at rest: S3 encryption, DynamoDB encryption enabled
- Certificate management: Rotate device certificates regularly

### Network Security
- S3 bucket blocks public access
- S3 bucket policy enforces HTTPS-only access
- VPC endpoints can be added for private connectivity

### Compliance
- CloudWatch Logs retention supports audit requirements
- S3 versioning enables data recovery
- DynamoDB point-in-time recovery enabled

## Troubleshooting

### No Data in S3
1. Check IoT devices are publishing to correct topic
2. Verify IoT Topic Rule is enabled and has correct SQL
3. Check Kinesis stream for incoming records
4. Review Lambda function logs for errors
5. Check Firehose delivery success metrics

### Lambda Transformation Errors
1. Review Lambda CloudWatch Logs
2. Verify DynamoDB table permissions
3. Check data format matches expected schema
4. Ensure Lambda timeout is sufficient

### High Costs
1. Review Kinesis shard count vs actual throughput
2. Optimize Lambda memory allocation
3. Adjust Firehose buffer settings
4. Review S3 storage class transitions
5. Reduce CloudWatch Logs retention if acceptable

### DynamoDB Throttling
1. DynamoDB is in on-demand mode (auto-scales)
2. Check for hot partitions (uneven deviceId distribution)
3. Review CloudWatch metrics for throttle events
4. Consider provisioned capacity for predictable workloads

## Scaling

### Horizontal Scaling
- **Kinesis Shards**: Increase for higher throughput (1 MB/sec per shard)
- **Lambda Concurrency**: Auto-scales up to account limits
- **DynamoDB**: On-demand mode auto-scales for capacity

### Vertical Scaling
- **Lambda Memory**: Increase for faster processing (also increases CPU)
- **Firehose Buffer**: Increase for larger batches (reduces Lambda invocations)

## Outputs

The stack provides the following outputs:

- **DataLakeBucketName**: S3 bucket name for querying data
- **DeviceStateTableName**: DynamoDB table name for device lookups
- **IngestionStreamName**: Kinesis stream name
- **DeliveryStreamName**: Firehose stream name
- **TransformationFunctionArn**: Lambda function ARN
- **DevicePolicyName**: IoT policy name for device provisioning
- **Thing Type Names**: For creating new devices
- **AlertTopicArn**: SNS topic for subscribing to alerts
- **DashboardURL**: Direct link to CloudWatch dashboard

## Next Steps

1. **Subscribe to SNS alerts**: Confirm email subscription
2. **Create IoT devices**: Register things and attach certificates
3. **Configure devices**: Point to IoT endpoint and use certificates
4. **Monitor dashboard**: Verify data flow through pipeline
5. **Query data**: Use Athena to query S3 data lake
6. **Set up analytics**: Connect to QuickSight, Redshift, or EMR

## Related Resources

- [AWS IoT Core Documentation](https://docs.aws.amazon.com/iot/latest/developerguide/)
- [Kinesis Data Streams Guide](https://docs.aws.amazon.com/streams/latest/dev/)
- [Kinesis Firehose Guide](https://docs.aws.amazon.com/firehose/latest/dev/)
- [DynamoDB Developer Guide](https://docs.aws.amazon.com/dynamodb/latest/developerguide/)

## License

This template is provided as-is for demonstration purposes.
