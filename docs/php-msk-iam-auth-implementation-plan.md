# PHP MSK IAM Authentication Library - Pragmatic Implementation Plan

## Overview

This document outlines a focused plan to create a solid PHP library that provides AWS IAM authentication for Apache Kafka clients connecting to Amazon MSK clusters. The library implements the core authentication mechanisms from the Java reference implementation with PHP 8.3 support.

## Architecture Design

### Core Components

Based on the Java implementation analysis, we need to implement the following core components in PHP:

1. **MSKIAMAuthenticator** - Main authentication orchestrator
2. **CredentialProvider** - AWS credential resolution and management
3. **SignatureGenerator** - AWS SigV4 signature generation
4. **SASLMechanism** - SASL protocol implementation for Kafka
5. **OAuthBearerHandler** - OAuth Bearer token generation (alternative mechanism)
6. **RetryManager** - Credential loading retry logic
7. **ConfigurationManager** - Configuration parsing and validation

### Package Structure

```
src/
├── AwsMskIamAuth/
│   ├── Client.php                     # Main client entry point
│   ├── Config.php                     # Configuration management
│   ├── Credentials/
│   │   ├── CredentialProvider.php     # Main credential provider
│   │   ├── ProfileProvider.php        # AWS profile-based credentials
│   │   ├── EnvironmentProvider.php    # Environment variable credentials
│   │   ├── InstanceProvider.php       # EC2 instance profile credentials
│   │   └── RoleProvider.php           # STS assume role credentials
│   ├── Signature/
│   │   ├── Signer.php                 # AWS SigV4 signature implementation
│   │   └── PayloadGenerator.php       # Authentication payload generation
│   ├── Sasl/
│   │   ├── IamMechanism.php           # AWS_MSK_IAM SASL mechanism
│   │   └── OAuthMechanism.php         # OAUTHBEARER mechanism
│   ├── Retry/
│   │   └── RetryHandler.php           # Retry logic with backoff
│   └── Exception/
│       ├── AuthException.php
│       ├── CredentialException.php
│       └── ConfigException.php
```

## Implementation Details

### 1. Main Client Class

```php
<?php

namespace AwsMskIamAuth;

class Client
{
    private Config $config;
    private Credentials\CredentialProvider $credentialProvider;
    private Signature\PayloadGenerator $payloadGenerator;
    private Retry\RetryHandler $retryHandler;

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->credentialProvider = new Credentials\CredentialProvider($config);
        $this->payloadGenerator = new Signature\PayloadGenerator();
        $this->retryHandler = new Retry\RetryHandler($config);
    }

    public function generateAuthPayload(string $brokerHost): array
    {
        return $this->retryHandler->execute(function() use ($brokerHost) {
            $credentials = $this->credentialProvider->resolve();
            return $this->payloadGenerator->generate($brokerHost, $credentials, $this->config);
        });
    }

    public function generateOAuthToken(string $region): string
    {
        $credentials = $this->credentialProvider->resolve();
        $mechanism = new Sasl\OAuthMechanism();
        return $mechanism->generateToken($credentials, $region, $this->config);
    }
}
```

### 2. AWS Credential Provider

```php
<?php

namespace AwsMskIamAuth\Credentials;

class CredentialProvider
{
    private array $providers = [];

    public function __construct(Config $config)
    {
        $this->initializeProviders($config);
    }

    private function initializeProviders(Config $config): void
    {
        if ($config->getProfileName()) {
            $this->providers[] = new ProfileProvider($config->getProfileName());
        }

        if ($config->getRoleArn()) {
            $this->providers[] = new RoleProvider($config);
        }

        // Default chain: environment, instance profile
        $this->providers[] = new EnvironmentProvider();
        $this->providers[] = new InstanceProvider();
    }

    public function resolve(): Credentials
    {
        foreach ($this->providers as $provider) {
            try {
                $credentials = $provider->getCredentials();
                if ($credentials) {
                    return $credentials;
                }
            } catch (CredentialException $e) {
                continue;
            }
        }

        throw new CredentialException('Unable to resolve AWS credentials');
    }
}

class Credentials
{
    public function __construct(
        private string $accessKeyId,
        private string $secretKey,
        private ?string $sessionToken = null
    ) {}

    public function getAccessKeyId(): string { return $this->accessKeyId; }
    public function getSecretKey(): string { return $this->secretKey; }
    public function getSessionToken(): ?string { return $this->sessionToken; }
}
```

### 3. Signature Generator

```php
<?php

namespace AwsMskIamAuth\Signature;

class PayloadGenerator
{
    private const ALGORITHM = 'AWS4-HMAC-SHA256';
    private const SERVICE = 'kafka-cluster';
    private const ACTION = 'kafka-cluster:Connect';
    private const VERSION = '2020_10_22';

    public function generate(string $host, Credentials $credentials, Config $config): array
    {
        $timestamp = new \DateTime('now', new \DateTimeZone('UTC'));
        $region = $config->getRegion();

        $canonicalRequest = $this->buildCanonicalRequest($host, $credentials, $timestamp, $region);
        $stringToSign = $this->buildStringToSign($canonicalRequest, $region, $timestamp);
        $signature = $this->calculateSignature($credentials, $region, $timestamp, $stringToSign);

        return [
            'version' => self::VERSION,
            'host' => $host,
            'user-agent' => 'aws-msk-iam-auth-php/1.0.0',
            'action' => self::ACTION,
            'x-amz-algorithm' => self::ALGORITHM,
            'x-amz-credential' => $this->buildCredentialScope($credentials, $region, $timestamp),
            'x-amz-date' => $timestamp->format('Ymd\THis\Z'),
            'x-amz-expires' => '900',
            'x-amz-signedheaders' => 'host',
            'x-amz-signature' => $signature,
            ...($credentials->getSessionToken() ? ['x-amz-security-token' => $credentials->getSessionToken()] : [])
        ];
    }

    private function buildCanonicalRequest(string $host, Credentials $credentials, \DateTime $timestamp, string $region): string
    {
        $queryParams = [
            'Action' => self::ACTION,
            'X-Amz-Algorithm' => self::ALGORITHM,
            'X-Amz-Credential' => $this->buildCredentialScope($credentials, $region, $timestamp),
            'X-Amz-Date' => $timestamp->format('Ymd\THis\Z'),
            'X-Amz-Expires' => '900',
            'X-Amz-SignedHeaders' => 'host'
        ];

        if ($credentials->getSessionToken()) {
            $queryParams['X-Amz-Security-Token'] = $credentials->getSessionToken();
        }

        ksort($queryParams);
        $queryString = http_build_query($queryParams, '', '&', PHP_QUERY_RFC3986);
        
        return "GET\n/\n{$queryString}\nhost:{$host}\n\nhost\n" . hash('sha256', '');
    }

    private function buildStringToSign(string $canonicalRequest, string $region, \DateTime $timestamp): string
    {
        $scope = $timestamp->format('Ymd') . "/{$region}/" . self::SERVICE . "/aws4_request";
        return self::ALGORITHM . "\n" . $timestamp->format('Ymd\THis\Z') . "\n{$scope}\n" . hash('sha256', $canonicalRequest);
    }

    private function calculateSignature(Credentials $credentials, string $region, \DateTime $timestamp, string $stringToSign): string
    {
        $dateKey = hash_hmac('sha256', $timestamp->format('Ymd'), 'AWS4' . $credentials->getSecretKey(), true);
        $regionKey = hash_hmac('sha256', $region, $dateKey, true);
        $serviceKey = hash_hmac('sha256', self::SERVICE, $regionKey, true);
        $signingKey = hash_hmac('sha256', 'aws4_request', $serviceKey, true);

        return hash_hmac('sha256', $stringToSign, $signingKey);
    }

    private function buildCredentialScope(Credentials $credentials, string $region, \DateTime $timestamp): string
    {
        return $credentials->getAccessKeyId() . '/' . $timestamp->format('Ymd') . "/{$region}/" . self::SERVICE . "/aws4_request";
    }
}
```

## Testing Against Real MSK Cluster

### 1. Composer Package Setup

```json
{
    "name": "aws/msk-iam-auth",
    "description": "AWS IAM authentication for Apache Kafka MSK clusters",
    "type": "library",
    "license": "Apache-2.0",
    "require": {
        "php": "^8.3",
        "ext-rdkafka": "*",
        "ext-json": "*",
        "guzzlehttp/guzzle": "^7.0"
    },
    "require-dev": {
        "phpunit/phpunit": "^10.0"
    },
    "autoload": {
        "psr-4": {
            "AwsMskIamAuth\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "AwsMskIamAuth\\Tests\\": "tests/"
        }
    }
}
```

### 2. Basic Test Setup

```php
<?php
// tests/MSKConnectionTest.php

namespace AwsMskIamAuth\Tests;

use PHPUnit\Framework\TestCase;
use AwsMskIamAuth\Client;
use AwsMskIamAuth\Config;

class MSKConnectionTest extends TestCase
{
    private Client $client;
    private string $brokerEndpoint;

    protected function setUp(): void
    {
        $this->brokerEndpoint = $_ENV['MSK_BROKER_ENDPOINT'] ?? 'localhost:9092';
        
        $config = new Config([
            'region' => $_ENV['AWS_REGION'] ?? 'us-east-1',
            'profile_name' => $_ENV['AWS_PROFILE'] ?? null,
            'role_arn' => $_ENV['AWS_ROLE_ARN'] ?? null
        ]);

        $this->client = new Client($config);
    }

    public function testGenerateAuthPayload(): void
    {
        $payload = $this->client->generateAuthPayload($this->brokerEndpoint);
        
        $this->assertArrayHasKey('version', $payload);
        $this->assertArrayHasKey('x-amz-signature', $payload);
        $this->assertEquals('2020_10_22', $payload['version']);
    }

    public function testKafkaProducer(): void
    {
        $conf = new \RdKafka\Conf();
        $conf->set('bootstrap.servers', $this->brokerEndpoint);
        
        // For actual MSK testing, you'd integrate the auth payload here
        // This is a placeholder showing structure
        $producer = new \RdKafka\Producer($conf);
        $this->assertInstanceOf(\RdKafka\Producer::class, $producer);
    }
}
```

## How to Run and Test

### 1. Installation

```bash
# Clone or create the project
mkdir aws-msk-iam-auth-php
cd aws-msk-iam-auth-php

# Install dependencies
composer install

# Install rdkafka extension (if not installed)
# Ubuntu/Debian:
sudo apt-get install librdkafka-dev
pecl install rdkafka

# macOS:
brew install librdkafka
pecl install rdkafka
```

### 2. Basic Usage Example

```php
<?php
// example.php

use AwsMskIamAuth\Client;
use AwsMskIamAuth\Config;

require_once 'vendor/autoload.php';

// Configure client
$config = new Config([
    'region' => 'us-east-1',
    'profile_name' => 'my-aws-profile', // optional
    'role_arn' => 'arn:aws:iam::123456789012:role/MSKRole', // optional
    'max_retries' => 3
]);

$client = new Client($config);

// Generate authentication payload
$brokerHost = 'b-1.your-cluster.abc123.c2.kafka.us-east-1.amazonaws.com';
$authPayload = $client->generateAuthPayload($brokerHost);

echo "Generated auth payload:\n";
echo json_encode($authPayload, JSON_PRETTY_PRINT);

// For OAuth Bearer token
$oauthToken = $client->generateOAuthToken('us-east-1');
echo "\nOAuth Bearer token: " . $oauthToken;
```

### 3. Testing with Real MSK Cluster

#### Prerequisites
- AWS account with MSK cluster
- IAM permissions for kafka-cluster actions
- PHP 8.3+ with rdkafka extension

#### Environment Setup
```bash
# Set environment variables
export AWS_REGION=us-east-1
export MSK_BROKER_ENDPOINT=b-1.your-cluster.abc123.c2.kafka.us-east-1.amazonaws.com:9098
export AWS_PROFILE=your-profile  # or use IAM role

# Run tests
./vendor/bin/phpunit tests/
```

#### Simple Integration Test
```php
<?php
// test-integration.php

use AwsMskIamAuth\Client;
use AwsMskIamAuth\Config;

require_once 'vendor/autoload.php';

$config = new Config([
    'region' => $_ENV['AWS_REGION'],
    'profile_name' => $_ENV['AWS_PROFILE'] ?? null
]);

$client = new Client($config);
$brokerHost = $_ENV['MSK_BROKER_ENDPOINT'];

try {
    $payload = $client->generateAuthPayload($brokerHost);
    echo "✓ Successfully generated auth payload\n";
    
    $token = $client->generateOAuthToken($_ENV['AWS_REGION']);
    echo "✓ Successfully generated OAuth token\n";
    
    echo "✅ All tests passed!\n";
} catch (Exception $e) {
    echo "❌ Test failed: " . $e->getMessage() . "\n";
    exit(1);
}
```

## Implementation Timeline

### Phase 1: Core Implementation (2-3 weeks)
- [ ] Project setup with Composer
- [ ] AWS credential provider chain
- [ ] SigV4 signature generation
- [ ] Basic configuration management
- [ ] Unit tests for core components

### Phase 2: SASL Integration (1-2 weeks)
- [ ] AWS_MSK_IAM mechanism implementation
- [ ] OAuth Bearer token support
- [ ] Retry logic with exponential backoff
- [ ] Error handling and exceptions

### Phase 3: Testing and Documentation (1 week)
- [ ] Integration tests with real MSK cluster
- [ ] Documentation and usage examples
- [ ] Package publication preparation

## Essential Components Only

This plan focuses on delivering a solid, working PHP library with:

✅ **Core Features:**
- AWS SigV4 signature generation
- Complete credential provider chain (environment, profiles, roles, instance profile)
- Both AWS_MSK_IAM and OAUTHBEARER mechanisms
- Retry logic with exponential backoff
- Proper error handling

✅ **Quality:**
- PHP 8.3+ compatibility
- Unit and integration tests
- Clear documentation
- PSR-12 coding standards

❌ **Excluded (nice-to-have):**
- Performance benchmarking
- Advanced monitoring
- Complex CI/CD pipelines
- Extensive configuration options

The result will be a production-ready library that implements the complete Java functionality in a clean, maintainable PHP package.