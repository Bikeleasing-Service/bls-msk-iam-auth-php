# AWS MSK IAM Auth PHP

Simple PHP library for generating AWS MSK IAM authentication tokens. 
Designed for EKS environments using IAM roles for service accounts.

This small library is basically a PHP translation of:

- [aws-msk-iam-sasl-signer-go](https://github.com/aws/aws-msk-iam-sasl-signer-go)
- [aws-msk-iam-sasl-signer-js](https://github.com/aws/aws-msk-iam-sasl-signer-js)

restricted to the case of EKS with IAM Roles for Service Accounts (IRSA).

## Features

- Simple single-class implementation
- AWS SigV4 signing for MSK authentication
- Automatic EC2/EKS instance metadata credential retrieval
- No external dependencies (only native PHP)
- Base64-encoded OAuth Bearer token generation

## How It Works

The library generates AWS-signed URLs that serve as OAuth Bearer tokens for MSK authentication:

1. **Get AWS credentials** (via EKS service account or EC2 instance metadata)
2. **Create signed URL** using AWS SigV4 algorithm (`https://kafka.region.amazonaws.com/?Action=kafka-cluster:Connect&X-Amz-Signature=...`)
3. **Base64 encode the URL** to create an OAuth Bearer token
4. **Use with Kafka client** via SASL OAUTHBEARER mechanism

**Note:** `generateAuthToken()` returns a base64-encoded signed URL, not a traditional token. This is the expected format for MSK IAM authentication.

📖 **[Read the detailed explanation](docs/HOW-IT-WORKS.md)** of the authentication flow and technical implementation.

## Requirements

- PHP 8.1+
- ext-json
- ext-simplexml

## Installation

```bash
composer require bls/msk-iam-auth
```

## Usage

### EKS with IAM Roles for Service Accounts (IRSA)

The library automatically detects and uses EKS service account tokens when running in a properly configured pod:

```php
<?php

require 'vendor/autoload.php';

// The library will automatically use the service account token
// mounted at /var/run/secrets/kubernetes.io/serviceaccount/token
// and the AWS_ROLE_ARN environment variable set by EKS
$auth = new MskIamAuth('eu-central-1');
$token = $auth->generateAuthToken();

// Use token with your Kafka client
echo "OAuth Bearer token: " . $token;
```

### Required EKS Environment Variables

When running in EKS with IRSA, these environment variables are automatically set:

- `AWS_ROLE_ARN` - The IAM role ARN associated with your service account
- `AWS_WEB_IDENTITY_TOKEN_FILE` - Path to the service account token file (defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`)
- `AWS_REGION` - Your AWS region

### Integration with rdkafka

```php
$conf = new RdKafka\Conf();
$conf->set('bootstrap.servers', 'your-msk-broker:9098');
$conf->set('security.protocol', 'SASL_SSL');
$conf->set('sasl.mechanism', 'OAUTHBEARER');
$conf->set('sasl.oauthbearer.token', $auth->generateAuthToken());

$producer = new RdKafka\Producer($conf);
```

## Testing

### Local Testing (with PHP)
```bash
# Basic test with mock credentials
php test-example.php

# Simple example (will try real credentials first)
php simple-example.php
```

### Docker Testing (if you don't have PHP locally)
```bash
# Build and test with mock credentials
docker build -t msk-iam-auth-test .
docker run --rm -e AWS_REGION=eu-central-1 msk-iam-auth-test php test-example.php
```

## AWS IAM Setup for EKS

### 1. IAM Role Permissions Policy

Your IAM role needs these MSK permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kafka-cluster:Connect",
                "kafka-cluster:ReadData",
            ],
            "Resource": "arn:aws:kafka:eu-central-1:123456789012:cluster/your-cluster-name/*"
        }
    ]
}
```

### 3. Kubernetes Service Account

Link your service account to the IAM role using the annotation:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: msk-app-service-account
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/MSKAccessRole
```

## License

Apache 2.0