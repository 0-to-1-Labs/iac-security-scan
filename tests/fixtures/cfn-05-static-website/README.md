# Static Website with CloudFront - CloudFormation Template

## Overview

This CloudFormation template deploys a production-grade static website infrastructure on AWS with the following components:

- **S3 Bucket**: Stores static website content with versioning and encryption
- **CloudFront Distribution**: Global CDN with HTTP/2, HTTP/3, and IPv6 support
- **CloudFront OAI**: Origin Access Identity for secure S3 access
- **WAF WebACL**: Web Application Firewall for DDoS and attack protection
- **Lambda@Edge**: Adds security headers to all responses
- **ACM Certificate**: SSL/TLS certificate for HTTPS (auto-provisioned or provided)
- **Route 53 Records**: DNS records for the domain (optional)
- **CloudWatch Alarms**: Monitoring for error rates and traffic spikes
- **CloudWatch Dashboard**: Real-time metrics visualization

## Architecture

```
Internet
    |
    v
[Route 53] --> [CloudFront Distribution] --> [WAF WebACL]
                       |
                       |--> [Lambda@Edge (Security Headers)]
                       |
                       v
               [S3 Bucket (Private)]
                       |
                       v
                  [Logs Bucket]
```

## Features

- **High Availability**: Multi-edge location distribution via CloudFront
- **Security**: WAF protection, encryption at rest, HTTPS only, security headers
- **Performance**: CloudFront caching, Origin Shield, compression enabled
- **Monitoring**: CloudWatch alarms and dashboard for operational visibility
- **Compliance**: Versioning, lifecycle policies, encrypted storage

## Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **Domain name** (if using custom domain)
3. **Route 53 Hosted Zone** (optional, for DNS management)
4. **ACM Certificate** in `us-east-1` region (optional, can be auto-created)

## Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `DomainName` | Domain name for the website | - | Yes |
| `HostedZoneId` | Route 53 Hosted Zone ID | Empty | No |
| `CertificateArn` | ACM Certificate ARN in us-east-1 | Empty | No |
| `Environment` | Environment name | production | Yes |
| `PriceClass` | CloudFront price class | PriceClass_100 | Yes |

## Deployment

### Option 1: Using AWS CLI

```bash
# Validate the template
aws cloudformation validate-template \
  --template-body file://template.yaml

# Create the stack
aws cloudformation create-stack \
  --stack-name my-static-website \
  --template-body file://template.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_IAM \
  --region us-east-1

# Monitor stack creation
aws cloudformation wait stack-create-complete \
  --stack-name my-static-website \
  --region us-east-1

# Get outputs
aws cloudformation describe-stacks \
  --stack-name my-static-website \
  --region us-east-1 \
  --query 'Stacks[0].Outputs'
```

### Option 2: Using AWS Console

1. Navigate to CloudFormation in the AWS Console
2. Click "Create stack" > "With new resources"
3. Upload the `template.yaml` file
4. Fill in the parameters
5. Review and create the stack

## Post-Deployment Steps

### 1. Upload Website Content

```bash
# Get the bucket name from stack outputs
BUCKET_NAME=$(aws cloudformation describe-stacks \
  --stack-name my-static-website \
  --query 'Stacks[0].Outputs[?OutputKey==`WebsiteBucketName`].OutputValue' \
  --output text)

# Upload your website files
aws s3 sync ./website-content s3://$BUCKET_NAME/ \
  --exclude ".git/*" \
  --exclude ".DS_Store" \
  --cache-control "public, max-age=3600"

# Upload index.html with specific settings
aws s3 cp ./website-content/index.html s3://$BUCKET_NAME/index.html \
  --content-type "text/html" \
  --cache-control "public, max-age=300"
```

### 2. Invalidate CloudFront Cache

```bash
# Get the distribution ID
DISTRIBUTION_ID=$(aws cloudformation describe-stacks \
  --stack-name my-static-website \
  --query 'Stacks[0].Outputs[?OutputKey==`CloudFrontDistributionId`].OutputValue' \
  --output text)

# Create invalidation
aws cloudfront create-invalidation \
  --distribution-id $DISTRIBUTION_ID \
  --paths "/*"
```

### 3. Configure DNS (if not using Route 53)

If you didn't provide a Hosted Zone ID, you'll need to manually configure your DNS:

```bash
# Get the CloudFront domain name
CLOUDFRONT_DOMAIN=$(aws cloudformation describe-stacks \
  --stack-name my-static-website \
  --query 'Stacks[0].Outputs[?OutputKey==`CloudFrontDomainName`].OutputValue' \
  --output text)

# Create a CNAME record pointing your domain to the CloudFront domain
echo "Create CNAME: $CLOUDFRONT_DOMAIN"
```

## Monitoring

### CloudWatch Dashboard

Access the dashboard at:
- AWS Console > CloudWatch > Dashboards > `{DomainName}-monitoring`

Metrics included:
- Total requests and bytes downloaded
- 4xx and 5xx error rates
- WAF blocked and allowed requests

### CloudWatch Alarms

The template creates two alarms:
1. **Error Rate Alarm**: Triggers when 5xx error rate exceeds 5%
2. **Request Spike Alarm**: Triggers when requests exceed 100,000 in 5 minutes

Configure SNS notifications:

```bash
# Create SNS topic
aws sns create-topic --name website-alerts

# Subscribe to topic
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:ACCOUNT_ID:website-alerts \
  --protocol email \
  --notification-endpoint your-email@example.com

# Update alarms to use the topic
aws cloudwatch put-metric-alarm \
  --alarm-name my-static-website-error-rate \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT_ID:website-alerts
```

## Security Features

### Lambda@Edge Security Headers

The template includes a Lambda@Edge function that adds the following headers:

- `Strict-Transport-Security`: Enforces HTTPS
- `X-Content-Type-Options`: Prevents MIME sniffing
- `X-Frame-Options`: Prevents clickjacking
- `X-XSS-Protection`: Enables XSS filter
- `Referrer-Policy`: Controls referrer information
- `Content-Security-Policy`: Restricts resource loading

### WAF Protection

The WAF WebACL includes:
- Rate limiting (2000 requests per 5 minutes per IP)
- Integration with CloudFront for edge protection

### Encryption

- S3 bucket encryption: AES-256 (SSE-S3)
- HTTPS only via CloudFront viewer protocol policy
- TLS certificate via ACM

## Cost Optimization

### Estimated Monthly Costs (for 1M requests, 10GB data transfer)

- CloudFront: ~$20
- S3 storage (10GB): ~$0.23
- S3 requests: ~$0.40
- Lambda@Edge: ~$1.50
- WAF: ~$5 + $1 per 1M requests = ~$6
- Route 53 (if used): ~$0.50
- **Total: ~$28.63/month**

### Tips to Reduce Costs

1. Use `PriceClass_100` for US/Europe only (default)
2. Set appropriate cache TTLs to reduce origin requests
3. Enable compression to reduce data transfer
4. Use lifecycle policies to delete old S3 versions

## Maintenance

### Update Website Content

```bash
# Sync new content
aws s3 sync ./website-content s3://$BUCKET_NAME/

# Invalidate cache
aws cloudfront create-invalidation \
  --distribution-id $DISTRIBUTION_ID \
  --paths "/*"
```

### Update Stack

```bash
# Update with new template or parameters
aws cloudformation update-stack \
  --stack-name my-static-website \
  --template-body file://template.yaml \
  --parameters file://parameters.json \
  --capabilities CAPABILITY_IAM
```

### View Logs

```bash
# List CloudFront logs
aws s3 ls s3://$BUCKET_NAME-logs/cloudfront/

# Download and analyze logs
aws s3 sync s3://$BUCKET_NAME-logs/cloudfront/ ./logs/
```

## Cleanup

```bash
# Empty the S3 buckets first
aws s3 rm s3://$BUCKET_NAME --recursive
aws s3 rm s3://$BUCKET_NAME-logs --recursive

# Delete the stack
aws cloudformation delete-stack \
  --stack-name my-static-website

# Wait for deletion
aws cloudformation wait stack-delete-complete \
  --stack-name my-static-website
```

## Troubleshooting

### Issue: Certificate Validation Stuck

If using auto-created ACM certificate with DNS validation:

```bash
# Get certificate ARN
aws cloudformation describe-stacks \
  --stack-name my-static-website \
  --query 'Stacks[0].Outputs[?OutputKey==`CertificateArn`].OutputValue' \
  --output text

# Check certificate status
aws acm describe-certificate \
  --certificate-arn CERTIFICATE_ARN \
  --region us-east-1

# Add the CNAME records shown in ValidationData to your DNS
```

### Issue: 403 Access Denied

Check that:
1. S3 bucket policy allows CloudFront OAI
2. Objects in S3 have correct permissions
3. CloudFront cache has been invalidated

### Issue: Custom Domain Not Working

Verify:
1. Certificate is in `us-east-1` region
2. Certificate domain matches your domain name
3. DNS CNAME/A record points to CloudFront distribution
4. SSL/TLS negotiation succeeds (check browser)

## Best Practices

1. **Always use HTTPS**: Template enforces HTTPS via viewer protocol policy
2. **Enable logging**: Monitor access patterns and troubleshoot issues
3. **Set cache headers**: Optimize performance with appropriate cache-control headers
4. **Use versioning**: Enables rollback and prevents accidental deletions
5. **Monitor costs**: Set up billing alarms to avoid surprises
6. **Regular updates**: Keep Lambda runtime and dependencies up to date

## References

- [CloudFront Documentation](https://docs.aws.amazon.com/cloudfront/)
- [S3 Static Website Hosting](https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html)
- [Lambda@Edge Documentation](https://docs.aws.amazon.com/lambda/latest/dg/lambda-edge.html)
- [WAF Documentation](https://docs.aws.amazon.com/waf/)
- [ACM Documentation](https://docs.aws.amazon.com/acm/)

## License

This template is provided as-is for demonstration purposes.
