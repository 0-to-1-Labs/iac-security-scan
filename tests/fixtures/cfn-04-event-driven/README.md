# Event-Driven Order Processing System

## Overview

This CloudFormation template deploys a production-grade event-driven architecture for an order processing system. The architecture demonstrates modern serverless patterns using AWS EventBridge, Lambda, Step Functions, SQS, SNS, and DynamoDB.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Event-Driven Architecture                   │
└─────────────────────────────────────────────────────────────────┘

                    ┌──────────────────────┐
                    │   EventBridge Bus    │
                    │  (order-event-bus)   │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
    ┌─────────────────┐ ┌────────────┐ ┌──────────────┐
    │ OrderCreated    │ │OrderShipped│ │OrderFailed   │
    │      Rule       │ │    Rule    │ │    Rule      │
    └────────┬────────┘ └─────┬──────┘ └──────┬───────┘
             │                │                │
        ┌────┴────┐          │           ┌────▼────┐
        ▼         ▼          │           │  SQS    │
    ┌──────┐  ┌──────┐      │           │ Alert   │
    │ SQS  │  │Lambda│      │           │ Queue   │
    │Queue │  │Validator    │           └────┬────┘
    └──┬───┘  └──────┘      │                │
       │                    │                ▼
       ▼                    │          ┌──────────┐
  ┌─────────┐              │          │ Lambda   │
  │ Lambda  │              │          │  Alert   │
  │Processor│              │          └──────────┘
  └────┬────┘              │
       │                   │
       ▼                   ▼
  ┌──────────────────┐ ┌──────┐
  │  Step Functions  │ │ SNS  │
  │   (Workflow)     │ │Topic │
  └────────┬─────────┘ └──────┘
           │
    ┌──────┼──────┐
    ▼      ▼      ▼
Reserve  Pay   Ship
Inventory ment  Order
    │      │      │
    └──────┴──────┘
           │
           ▼
      ┌─────────┐
      │DynamoDB │
      │ Tables  │
      └─────────┘
```

## Components

### EventBridge
- **Order Event Bus**: Central event router for order-related events
- **Event Rules**:
  - `order.created` → Routes to SQS Queue & Lambda Validator
  - `order.shipped` → Routes to SNS Topic for notifications
  - `order.failed` → Routes to Alert Queue

### SQS Queues
- **Order Processing Queue**: Buffers order events for batch processing
- **Order Processing DLQ**: Dead-letter queue for failed messages
- **Order Alert Queue**: Handles failed order alerts

### Lambda Functions
1. **Order Validation Function** (`order-validation`)
   - Validates incoming orders (schema, business rules)
   - Emits validation results to EventBridge
   - Triggered by EventBridge rule

2. **Order Processor Function** (`order-processor`)
   - Processes orders from SQS in batches
   - Starts Step Functions workflow
   - Updates order status in DynamoDB
   - Triggered by SQS queue

3. **Order Alert Function** (`order-alert`)
   - Handles failed order alerts
   - Sends notifications via SNS
   - Has reserved concurrency for controlled scaling

### Step Functions
- **Order Fulfillment State Machine**: Orchestrates order fulfillment workflow
  - Reserve Inventory
  - Process Payment
  - Ship Order
  - Error handling with failure events

### DynamoDB Tables
1. **Orders Table**
   - Stores order records
   - GSI: Customer Index (customerId + createdAt)
   - GSI: Status Index (status + createdAt)
   - Point-in-time recovery enabled
   - Encryption at rest enabled

2. **Order Events Table**
   - Event sourcing for order lifecycle
   - GSI: OrderId Index for event history
   - TTL enabled (30-day retention)
   - On-demand billing

### SNS
- **Order Notification Topic**: Publishes order status notifications
- Email subscription for operations team

### CloudWatch
- **Dashboard**: Visualizes metrics for SQS, Lambda, Step Functions, and DynamoDB
- **Alarms**:
  - Queue depth monitoring
  - Lambda error rates
  - Step Functions failures

## Event Flow

### Happy Path
1. External system publishes `order.created` event to EventBridge
2. EventBridge routes event to:
   - Order Processing Queue (for async processing)
   - Order Validation Lambda (for immediate validation)
3. Validation Lambda validates order and emits `order.validated` event
4. Order Processor Lambda consumes messages from SQS
5. Processor starts Step Functions workflow
6. Workflow executes: Reserve → Payment → Shipping
7. On completion, emits `order.shipped` event
8. EventBridge routes to SNS for customer notification

### Error Path
1. If validation fails, emit `order.failed` event
2. EventBridge routes to Alert Queue
3. Alert Lambda processes and notifies operations team
4. If Step Functions fails, emit `order.failed` event (same flow)

## Deployment

### Prerequisites
- AWS CLI configured with appropriate credentials
- AWS SAM CLI (for packaging Lambda functions)
- S3 bucket for deployment artifacts

### Deploy Stack

```bash
# Package the template (uploads Lambda code to S3)
aws cloudformation package \
  --template-file template.yaml \
  --s3-bucket your-deployment-bucket \
  --output-template-file packaged-template.yaml

# Deploy the stack
aws cloudformation deploy \
  --template-file packaged-template.yaml \
  --stack-name order-processing-dev \
  --parameter-overrides file://parameters.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

### Deploy with SAM CLI

```bash
sam build
sam deploy \
  --stack-name order-processing-dev \
  --parameter-overrides ParameterKey=Environment,ParameterValue=dev \
                        ParameterKey=NotificationEmail,ParameterValue=ops@example.com \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

## Testing

### Publish Test Event

```bash
# Get the EventBridge bus name
EVENT_BUS=$(aws cloudformation describe-stacks \
  --stack-name order-processing-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`EventBusName`].OutputValue' \
  --output text)

# Publish order.created event
aws events put-events \
  --entries '[
    {
      "Source": "order.service",
      "DetailType": "order.created",
      "Detail": "{\"orderId\":\"ORD-12345\",\"customerId\":\"CUST-789\",\"items\":[{\"sku\":\"ITEM-001\",\"quantity\":2,\"price\":29.99}],\"totalAmount\":59.98,\"createdAt\":1234567890}",
      "EventBusName": "'"$EVENT_BUS"'"
    }
  ]'
```

### Monitor Processing

```bash
# Check SQS queue depth
aws sqs get-queue-attributes \
  --queue-url $(aws cloudformation describe-stacks \
    --stack-name order-processing-dev \
    --query 'Stacks[0].Outputs[?OutputKey==`OrderProcessingQueueUrl`].OutputValue' \
    --output text) \
  --attribute-names ApproximateNumberOfMessages

# View Lambda logs
aws logs tail /aws/lambda/dev-order-validation --follow

# Check Step Functions executions
aws stepfunctions list-executions \
  --state-machine-arn $(aws cloudformation describe-stacks \
    --stack-name order-processing-dev \
    --query 'Stacks[0].Outputs[?OutputKey==`StateMachineArn`].OutputValue' \
    --output text)
```

### Query DynamoDB

```bash
# Get recent orders
aws dynamodb scan \
  --table-name dev-orders \
  --limit 10

# Query by customer
aws dynamodb query \
  --table-name dev-orders \
  --index-name CustomerIndex \
  --key-condition-expression "customerId = :cid" \
  --expression-attribute-values '{":cid":{"S":"CUST-789"}}'
```

## Configuration

### Parameters

| Parameter | Description | Default | Allowed Values |
|-----------|-------------|---------|----------------|
| Environment | Environment name | dev | dev, staging, prod |
| OrderTableReadCapacity | DynamoDB read capacity | 5 | 1-10000 |
| OrderTableWriteCapacity | DynamoDB write capacity | 5 | 1-10000 |
| NotificationEmail | Email for notifications | - | Valid email |
| EnableDetailedMonitoring | Enable detailed metrics | true | true, false |

### Scaling Considerations

**Lambda Concurrency**:
- Order Validation: No reserved concurrency (can scale freely) ⚠️
- Order Processor: No reserved concurrency (can scale freely) ⚠️
- Order Alert: Reserved concurrency = 5

**DynamoDB**:
- Provisioned capacity can be adjusted via parameters
- Consider switching to PAY_PER_REQUEST for variable workloads

**SQS**:
- Default visibility timeout: 300 seconds (Order Processing)
- Batch processing: 10 messages per Lambda invocation

## Security Considerations

### Embedded Security Flaws (for testing purposes)

This template intentionally includes several security anti-patterns for demonstration and testing:

1. **Unencrypted SQS Queues**
   - `OrderProcessingQueue`: Missing `KmsMasterKeyId`
   - `OrderAlertQueue`: Missing `KmsMasterKeyId`
   - **Risk**: Messages stored in plaintext
   - **Fix**: Add `KmsMasterKeyId: alias/aws/sqs`

2. **Missing Dead-Letter Queues**
   - `OrderProcessingQueue`: No `RedrivePolicy` configured
   - `OrderAlertQueue`: No `RedrivePolicy` configured
   - **Risk**: Lost messages on repeated failures
   - **Fix**: Configure DLQ with `RedrivePolicy`

3. **Lambda Without Reserved Concurrency**
   - `OrderValidationFunction`: No throttling protection
   - `OrderProcessorFunction`: No throttling protection
   - **Risk**: Uncontrolled scaling can exhaust account limits
   - **Fix**: Set `ReservedConcurrentExecutions`

4. **Unencrypted SNS Topic**
   - `OrderNotificationTopic`: Missing `KmsMasterKeyId`
   - **Risk**: Notifications sent in plaintext
   - **Fix**: Add `KmsMasterKeyId`

5. **EventBridge Rules Without DLQ**
   - All EventBridge rules lack `DeadLetterConfig`
   - **Risk**: Failed events lost without retry exhaustion tracking
   - **Fix**: Configure DLQ ARN in target configuration

### Recommended Security Enhancements

```yaml
# Example: Encrypted SQS Queue with DLQ
OrderProcessingQueue:
  Type: AWS::SQS::Queue
  Properties:
    QueueName: !Sub '${Environment}-order-processing-queue'
    KmsMasterKeyId: alias/aws/sqs  # Enable encryption
    RedrivePolicy:                  # Configure DLQ
      deadLetterTargetArn: !GetAtt OrderProcessingDLQ.Arn
      maxReceiveCount: 3

# Example: Lambda with reserved concurrency
OrderValidationFunction:
  Type: AWS::Serverless::Function
  Properties:
    ReservedConcurrentExecutions: 10  # Limit scaling

# Example: Encrypted SNS Topic
OrderNotificationTopic:
  Type: AWS::SNS::Topic
  Properties:
    KmsMasterKeyId: alias/aws/sns  # Enable encryption

# Example: EventBridge target with DLQ
OrderCreatedRule:
  Type: AWS::Events::Rule
  Properties:
    Targets:
      - Arn: !GetAtt OrderProcessingQueue.Arn
        DeadLetterConfig:
          Arn: !GetAtt EventBridgeDLQ.Arn  # Configure DLQ
```

## Monitoring

### CloudWatch Dashboard
Access the dashboard via the `DashboardURL` output:
```bash
aws cloudformation describe-stacks \
  --stack-name order-processing-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`DashboardURL`].OutputValue' \
  --output text
```

### Key Metrics
- **SQS**: Queue depth, messages sent/received
- **Lambda**: Invocations, errors, duration
- **Step Functions**: Executions started/succeeded/failed
- **DynamoDB**: Consumed capacity units

### Alarms
- Queue depth > 100 messages (avg over 10 min)
- Lambda errors > 5 in 5 minutes
- Step Functions failures > 3 in 5 minutes

## Cost Optimization

### Estimated Monthly Costs (10,000 orders/month)

| Service | Usage | Estimated Cost |
|---------|-------|----------------|
| Lambda | ~30K invocations, 1GB-sec avg | $0.60 |
| Step Functions | 10K executions | $0.25 |
| DynamoDB | 5 RCU, 5 WCU provisioned | $2.88 |
| SQS | 30K requests | $0.01 |
| EventBridge | 40K events | $0.04 |
| SNS | 10K notifications | $0.50 |
| CloudWatch Logs | 5GB ingestion | $2.50 |
| **Total** | | **~$6.78/month** |

### Cost Reduction Tips
1. Switch DynamoDB to on-demand for variable workloads
2. Enable SQS long polling (already configured)
3. Increase Lambda batch size to reduce invocations
4. Adjust CloudWatch Logs retention (currently 30 days)

## Cleanup

```bash
# Delete the stack
aws cloudformation delete-stack --stack-name order-processing-dev

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete --stack-name order-processing-dev
```

**Note**: DynamoDB tables with deletion protection will need manual intervention.

## Troubleshooting

### Issue: Messages stuck in queue

**Check**:
```bash
# View DLQ messages
aws sqs receive-message \
  --queue-url $(aws sqs get-queue-url --queue-name dev-order-processing-dlq --query 'QueueUrl' --output text) \
  --max-number-of-messages 10
```

### Issue: Lambda timeouts

**Solution**:
- Increase Lambda timeout in template
- Check for slow DynamoDB queries
- Review Step Functions execution times

### Issue: Step Functions failures

**Debug**:
```bash
# Get execution details
aws stepfunctions describe-execution \
  --execution-arn <execution-arn> \
  --query 'status, output, stopDate'

# View execution history
aws stepfunctions get-execution-history \
  --execution-arn <execution-arn>
```

## References

- [AWS EventBridge Documentation](https://docs.aws.amazon.com/eventbridge/)
- [AWS Step Functions Best Practices](https://docs.aws.amazon.com/step-functions/latest/dg/best-practices.html)
- [Event-Driven Architecture Patterns](https://aws.amazon.com/event-driven-architecture/)
- [AWS SAM Documentation](https://docs.aws.amazon.com/serverless-application-model/)

## License

This template is provided as-is for educational and testing purposes.
