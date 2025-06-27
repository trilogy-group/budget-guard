# Budget Guard

Budget Guard is an AI-driven AWS cost tracking and accountability system that provides real-time cost anomaly detection, budget tracking, and intelligent cost attribution across thousands of AWS accounts.

## System Architecture

Budget Guard uses an event-driven microservices architecture with the following components:

### Core Services

1. **The Scout** - Data collection service that aggregates cost and resource data from all AWS accounts
2. **The Detective** - Anomaly detection service that identifies cost spikes, budget violations, and other anomalies
3. **The Investigator** - Context enrichment service that adds deployment, commit, and CloudTrail context to anomalies
4. **The Dispatcher** - Alert routing service that sends notifications via Slack, PagerDuty, email, and Teams

### Data Storage

- **DynamoDB Tables**: Products, Metrics, Anomalies, Resource Mappings
- **S3 + Athena**: Time-series cost data from AWS Cost & Usage Reports
- **DynamoDB Streams**: Event streaming between services

### API Layer

- **AWS AppSync**: GraphQL API for frontend applications
- **Cognito**: Authentication and authorization

## Features

- **Real-time Anomaly Detection**: Detects cost spikes, new resources, budget violations, and more
- **Intelligent Context**: Automatically correlates anomalies with recent deployments and AWS activities
- **Multi-Account Support**: Monitors costs across thousands of AWS accounts
- **Smart Alert Routing**: Routes alerts based on severity with suppression for known deployments
- **Product Attribution**: Maps AWS resources to products and teams automatically
- **Acquisition Tracking**: Tracks cost reduction targets for acquired products

## Anomaly Types

1. **COST_SPIKE**: >50% increase day-over-day or >$1000 absolute
2. **NEW_RESOURCE**: Expensive resource (>$100/day) not seen before
3. **MISSING_RESOURCE**: Resource disappeared but still incurring costs
4. **BUDGET_VIOLATION**: Exceeding monthly budget threshold
5. **UNTAGGED_RESOURCE**: Missing required tags (Product, Team, Environment)
6. **ORPHANED_RESOURCE**: No Infrastructure as Code reference found
7. **ACQUISITION_MISS**: Not meeting cost reduction targets

## Prerequisites

- AWS SAM CLI installed
- Python 3.11+
- AWS credentials configured
- Google OAuth credentials (for Cognito)
- Slack webhook URL (optional)
- PagerDuty API token (optional)

## Deployment

### 1. Deploy IAM Roles in Master Account

```bash
aws cloudformation create-stack \
  --stack-name budget-guard-iam \
  --template-body file://infrastructure/iam-roles.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

### 2. Deploy Cross-Account Role in Monitored Accounts

Deploy the `BudgetGuardRole` in each AWS account you want to monitor:

```bash
# Get the template from the IAM stack outputs
aws cloudformation describe-stacks \
  --stack-name budget-guard-iam \
  --query 'Stacks[0].Outputs[?OutputKey==`CrossAccountRoleTemplate`].OutputValue' \
  --output text > cross-account-role.json

# Deploy in each monitored account
aws cloudformation create-stack \
  --stack-name budget-guard-cross-account \
  --template-body file://cross-account-role.json \
  --capabilities CAPABILITY_NAMED_IAM
```

### 3. Deploy Cognito Authentication

```bash
aws cloudformation create-stack \
  --stack-name budget-guard-cognito \
  --template-body file://infrastructure/cognito.yaml \
  --parameters \
    ParameterKey=GoogleClientId,ParameterValue=YOUR_GOOGLE_CLIENT_ID \
    ParameterKey=GoogleClientSecret,ParameterValue=YOUR_GOOGLE_CLIENT_SECRET \
  --capabilities CAPABILITY_IAM
```

### 4. Deploy DynamoDB Tables

```bash
aws cloudformation create-stack \
  --stack-name budget-guard-dynamodb \
  --template-body file://infrastructure/dynamodb_tables.yaml
```

### 5. Build and Deploy the Application

```bash
# Build the application
sam build

# Deploy (first time)
sam deploy --guided \
  --stack-name budget-guard \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    SlackWebhookUrl=YOUR_SLACK_WEBHOOK \
    PagerDutyToken=YOUR_PAGERDUTY_TOKEN \
    PagerDutyServiceId=YOUR_SERVICE_ID \
    GitHubToken=YOUR_GITHUB_TOKEN \
    AlertEmail=alerts@yourcompany.com

# Subsequent deployments
sam deploy
```

## Configuration

### Adding Products

Products are stored in the DynamoDB Products table. Add a product using the AWS CLI:

```bash
aws dynamodb put-item \
  --table-name budget-guard-products \
  --item '{
    "PK": {"S": "PRODUCT#video-platform"},
    "SK": {"S": "METADATA"},
    "name": {"S": "Video Platform"},
    "type": {"S": "ACQUISITION"},
    "teamId": {"S": "team-video"},
    "monthlyBudget": {"N": "50000"},
    "targetReduction": {"N": "0.30"},
    "accounts": {"L": [{"S": "123456789012"}, {"S": "987654321098"}]},
    "repos": {"L": [{"S": "github.com/company/video-api"}]}
  }'
```

### Required Tags

Ensure all AWS resources are tagged with:
- `Product`: The product ID
- `Team`: The team ID
- `Environment`: prod/staging/dev
- `Component`: The component name

## API Usage

### GraphQL Queries

```graphql
# Get product details with anomalies
query GetProduct {
  product(id: "video-platform") {
    name
    monthlyBudget
    currentMonthSpend
    anomalies(status: ACTIVE) {
      items {
        type
        severity
        costImpact
        detectedAt
      }
    }
  }
}

# Get cost trend
query GetCostTrend {
  costTrend(
    productId: "video-platform"
    groupBy: SERVICE
    dateRange: { start: "2024-11-01", end: "2024-11-30" }
  ) {
    timestamp
    value
    dimension
  }
}
```

### GraphQL Mutations

```graphql
# Acknowledge an anomaly
mutation AcknowledgeAnomaly {
  acknowledgeAnomaly(
    id: "anomaly-123"
    notes: "Planned scaling for Black Friday"
  ) {
    id
    status
    acknowledgedBy
  }
}
```

## Monitoring

### CloudWatch Dashboards

The system automatically creates CloudWatch dashboards for:
- Lambda function performance
- DynamoDB read/write capacity
- Anomaly detection rates
- Alert delivery success

### X-Ray Tracing

All Lambda functions and AppSync API calls are traced with AWS X-Ray for debugging.

## Cost Optimization

Budget Guard itself is designed to be cost-effective:
- DynamoDB on-demand pricing
- Lambda pay-per-invocation
- 90-day data retention with S3 archival
- Efficient batch processing

## Security

- All data encrypted at rest and in transit
- IAM roles with least privilege access
- Cognito authentication with MFA support
- Cross-account access via assumed roles
- No credentials stored in code

## Troubleshooting

### Common Issues

1. **No cost data appearing**
   - Verify Cost & Usage Reports are enabled
   - Check IAM permissions in monitored accounts
   - Ensure Scout Lambda is running (check CloudWatch logs)

2. **Anomalies not being detected**
   - Verify DynamoDB streams are enabled
   - Check Detective Lambda logs
   - Ensure historical data exists (30 days needed)

3. **Alerts not being sent**
   - Verify webhook URLs and tokens
   - Check Dispatcher Lambda logs
   - Ensure anomalies are enriched (check Investigator logs)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

Copyright (c) 2024. All rights reserved.