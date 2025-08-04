# AWS MSK IAM Authentication Library - Technical Analysis

## Overview

The **Amazon MSK Library for AWS Identity and Access Management** is a Java library that enables Apache Kafka clients to authenticate with Amazon MSK clusters using AWS IAM credentials. It implements a custom SASL (Simple Authentication and Security Layer) mechanism called `AWS_MSK_IAM` and also supports the standard SASL/OAUTHBEARER mechanism with IAM authentication.

## Architecture Overview

### Core Components

The library is structured around several key components that work together to provide IAM-based authentication:

1. **IAMLoginModule** - SASL login module registration
2. **IAMClientCallbackHandler** - Credential extraction and management
3. **IAMSaslClient** - SASL client implementation for AWS_MSK_IAM mechanism
4. **IAMOAuthBearerLoginCallbackHandler** - OAuth Bearer token handler for OAUTHBEARER mechanism
5. **AWS4SignedPayloadGenerator** - AWS SigV4 signature generation
6. **MSKCredentialProvider** - AWS credential provider with retry logic

### Package Structure

```
software.amazon.msk.auth.iam/
├── IAMLoginModule.java                    # SASL mechanism registration
├── IAMClientCallbackHandler.java         # Credential callback handler
├── IAMOAuthBearerLoginCallbackHandler.java # OAuth Bearer implementation
├── IAMOAuthBearerToken.java              # OAuth token wrapper
└── internals/
    ├── AWS4SignedPayloadGenerator.java   # SigV4 payload generation
    ├── AWSCredentialsCallback.java       # Credential callback interface
    ├── AuthenticationRequestParams.java  # Request parameter container
    ├── AuthenticationResponse.java       # Server response model
    ├── IAMSaslClient.java               # SASL client implementation
    ├── IAMSaslClientProvider.java       # SASL client factory
    ├── MSKCredentialProvider.java       # Credential provider with retry
    └── utils/
        ├── RegionUtils.java             # AWS region utilities
        └── URIUtils.java               # URI manipulation utilities
```

## Technical Deep Dive

### 1. SASL Mechanism Registration (IAMLoginModule)

The `IAMLoginModule` class implements the Java `LoginModule` interface and serves as the entry point for registering the custom SASL mechanism:

- **Mechanism Name**: `AWS_MSK_IAM`
- **Purpose**: Registers `IAMSaslClientProvider` as a provider for the custom mechanism
- **Initialization**: Sets up both regular and class-loader aware SASL client providers
- **Implementation**: Minimal no-op implementation focusing on provider registration

### 2. Credential Management (IAMClientCallbackHandler)

The `IAMClientCallbackHandler` is responsible for extracting AWS credentials:

**Configuration Sources**:
- JAAS configuration entries with custom options
- Falls back to AWS Default Credentials Provider Chain if no options provided

**Supported Options**:
- `awsProfileName` - Specific AWS credential profile
- `awsRoleArn` - IAM role ARN for assumption
- `awsRoleSessionName` - Session name for role assumption
- `awsStsRegion` - STS regional endpoint
- `awsDebugCreds` - Debug credential information
- `awsMaxRetries` - Maximum retry attempts
- `awsMaxBackOffTimeMs` - Maximum backoff time

**Credential Provider Chain**:
1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
2. Java system properties (aws.accessKeyId, aws.secretKey)
3. Web Identity Token credentials
4. AWS credential profiles file (~/.aws/credentials)  
5. Amazon ECS container credentials
6. EC2 instance profile credentials

### 3. SASL Client Implementation (IAMSaslClient)

The `IAMSaslClient` implements the core SASL authentication protocol:

**State Machine**:
- `SEND_CLIENT_FIRST_MESSAGE` - Initial state, sends authentication payload
- `RECEIVE_SERVER_RESPONSE` - Waits for server acknowledgment  
- `COMPLETE` - Authentication completed successfully
- `FAILED` - Authentication failed

**Authentication Flow**:
1. **Initial Challenge**: Empty challenge expected, generates signed payload
2. **Server Response**: Non-empty response expected with request ID
3. **Completion**: Authentication successful, transitions to COMPLETE state

**Message Generation**:
- Uses `AWS4SignedPayloadGenerator` to create signed authentication payload
- Invokes callback handler to fetch AWS credentials
- Generates signed payload with server name and credentials

### 4. AWS SigV4 Signature Generation (AWS4SignedPayloadGenerator)

This component implements AWS Signature Version 4 for creating authentication payloads:

**Process**:
1. **Request Creation**: Creates GET request to broker with action parameter
2. **Presigning**: Uses AWS SDK's `Aws4Signer` to presign the request
3. **Payload Generation**: Converts signed request to JSON payload
4. **Serialization**: Returns payload as JSON bytes

**Request Parameters**:
- **Method**: GET
- **Protocol**: HTTPS  
- **Action**: "kafka-cluster:Connect"
- **Expiry**: 15 minutes
- **Service Scope**: "kafka-cluster"

**Generated Payload Structure**:
```json
{
    "version": "2020_10_22",
    "host": "<broker-address>",
    "user-agent": "<client-user-agent>",
    "action": "kafka-cluster:Connect",
    "x-amz-algorithm": "AWS4-HMAC-SHA256",
    "x-amz-credential": "<access-key>/<date>/<region>/kafka-cluster/aws4_request",
    "x-amz-date": "<timestamp>",
    "x-amz-security-token": "<session-token>",
    "x-amz-signedheaders": "host",
    "x-amz-expires": "900",
    "x-amz-signature": "<signature>"
}
```

### 5. Enhanced Credential Provider (MSKCredentialProvider)

The `MSKCredentialProvider` extends AWS credential resolution with:

**Retry Logic**:
- Default: 3 retries with exponential backoff
- Configurable via `awsMaxRetries` and `awsMaxBackOffTimeMs`
- Handles `SdkClientException` with full jitter backoff strategy
- Base delay: 500ms, maximum backoff: 5000ms (configurable)

**Provider Chain**:
- Profile-based providers (with profile name)
- STS role assumption providers
- Falls back to default AWS credential provider chain

**Role Assumption Support**:
- Basic role assumption with session name
- Role assumption with explicit credentials (access key, secret key, session token)
- Role assumption with external ID
- Cross-account role assumption
- STS regional endpoint configuration

**Debug Features**:
- Caller identity logging when `awsDebugCreds=true`
- Detailed credential source information
- Class loader debugging information

### 6. OAuth Bearer Implementation (IAMOAuthBearerLoginCallbackHandler)

For SASL/OAUTHBEARER mechanism support:

**Token Generation**:
- Creates base64-encoded presigned URL as OAuth token
- Uses same AWS SigV4 signing process as custom mechanism
- Automatically resolves AWS region from metadata

**Token Structure**:
- Base64 URL-encoded without padding
- Contains full presigned URL with all authentication parameters
- Includes User-Agent header in query parameters

## Build System and Dependencies

### Gradle Configuration

**Build System**: Gradle with multiple plugins
- `java-library` - Java library support
- `lombok` - Code generation
- `shadow` - Uber JAR creation
- `maven-publish` - Maven Central publishing
- `signing` - JAR signing for distribution
- `dependencycheck` - Security vulnerability scanning

**Java Compatibility**: 
- Source/Target: Java 8
- Ensures broad compatibility with existing Kafka deployments

### Dependencies

**Core Dependencies**:
- **Kafka Clients**: `org.apache.kafka:kafka-clients:2.8.1` (compile-only)
- **AWS SDK v2**: BOM version 2.30.23
  - `software.amazon.awssdk:auth` - Core authentication
  - `software.amazon.awssdk:sso` - Single Sign-On support
  - `software.amazon.awssdk:ssooidc` - SSO OIDC support
  - `software.amazon.awssdk:sts` - Security Token Service
  - `software.amazon.awssdk:apache-client` - HTTP client (runtime)
- **Jackson**: `com.fasterxml.jackson.core:jackson-databind:2.18.3` - JSON processing
- **SLF4J**: `org.slf4j:slf4j-api:1.7.25` - Logging facade

**Test Dependencies**:
- JUnit 5 - Testing framework
- Mockito - Mocking framework  
- Apache Commons Lang3 - Utilities
- Log4j2 - Logging implementation

### Packaging

**Standard JAR**:
- Contains only library classes
- Requires all dependencies on classpath
- Suitable for Maven/Gradle dependency management

**Shadow JAR (Uber JAR)**:
- Includes all dependencies except Kafka clients and SLF4J
- Uses package relocation to avoid conflicts
- Relocation prefix: `aws_msk_iam_auth_shadow`
- Excludes modern Java version metadata (Java 17, 21, 22)
- Suitable for deployment with existing Kafka installations

**Class Loading Support**:
- Multi-classloader environment support (Apache Flink, Kafka Connect)
- Class-loader aware SASL client provider
- Debug logging for classloader issues

## Authentication Flow

### End-to-End Process

1. **Kafka Client Configuration**:
   ```properties
   security.protocol=SASL_SSL
   sasl.mechanism=AWS_MSK_IAM
   sasl.jaas.config=software.amazon.msk.auth.iam.IAMLoginModule required;
   sasl.client.callback.handler.class=software.amazon.msk.auth.iam.IAMClientCallbackHandler
   ```

2. **SASL Negotiation**:
   - Kafka client initiates SASL handshake
   - `IAMLoginModule` registers custom mechanism
   - `IAMSaslClient` handles authentication protocol

3. **Credential Resolution**:
   - `IAMClientCallbackHandler` resolves AWS credentials
   - `MSKCredentialProvider` handles credential loading with retries
   - Supports various credential sources (profiles, roles, environment, etc.)

4. **Signature Generation**:
   - `AWS4SignedPayloadGenerator` creates presigned authentication payload
   - Uses AWS SigV4 signing with broker hostname and current timestamp
   - Payload includes all necessary authentication parameters

5. **Server Exchange**:
   - Client sends signed payload to MSK broker
   - Broker validates signature and IAM permissions
   - Server responds with success confirmation and request ID

6. **Authentication Completion**:
   - SASL client transitions to COMPLETE state
   - Connection established for Kafka operations

### Alternative OAuth Flow

For SASL/OAUTHBEARER mechanism:

1. **Configuration**:
   ```properties
   security.protocol=SASL_SSL
   sasl.mechanism=OAUTHBEARER
   sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required;
   sasl.login.callback.handler.class=software.amazon.msk.auth.iam.IAMOAuthBearerLoginCallbackHandler
   sasl.client.callback.handler.class=software.amazon.msk.auth.iam.IAMOAuthBearerLoginCallbackHandler
   ```

2. **Token Generation**:
   - Handler creates base64-encoded presigned URL as OAuth token
   - Same signing process as custom mechanism
   - Token refresh handled by OAuth Bearer framework

## Error Handling and Resilience

### Retry Mechanisms

**Credential Loading Retries**:
- Exponential backoff with full jitter
- Configurable retry count and maximum backoff time
- Handles transient AWS service failures

**Connection Rate Limiting**:
- Broker-side protection against excessive connection attempts
- Configurable `reconnect.backoff.ms` for client-side backoff
- Different limits based on MSK broker instance types

### Common Error Scenarios

**Class Not Found**:
- Library not on classpath
- Incorrect JAAS configuration
- Class loader issues in plugin environments

**Access Denied**:
- Insufficient IAM permissions
- Incorrect credential configuration  
- Cross-account access issues

**Too Many Connects**:
- Excessive connection rate to broker
- Insufficient backoff configuration
- Multiple clients from same source

**Dependency Conflicts**:
- Version mismatches with Kafka client
- Conflicting AWS SDK versions
- SLF4J binding issues

## Security Considerations

### Credential Security

**No Credential Storage**:
- Library never persists credentials
- Uses standard AWS credential providers
- Supports secure credential sources (IAM roles, STS tokens)

**Signature Security**:
- Uses AWS SigV4 signing standard
- 15-minute signature expiry
- Unique signatures per request

**Network Security**:
- Requires TLS (SASL_SSL protocol)
- No plaintext credential transmission
- Standard Kafka broker TLS configuration

### Permissions Requirements

**MSK Cluster Access**:
- `kafka-cluster:Connect` action permission
- Appropriate cluster ARN in resource specification
- Topic-level permissions for actual operations

**AWS Service Permissions**:
- STS access for role assumption (if using roles)
- SSO permissions for SSO-based authentication
- EC2 metadata access for instance profiles

## Performance Characteristics

### Overhead Analysis

**Connection Establishment**:
- Additional SASL round-trip vs. plaintext
- AWS credential resolution time  
- Signature generation (minimal CPU overhead)

**Runtime Performance**:
- No per-message overhead after authentication
- Periodic credential refresh (for temporary credentials)
- Memory usage comparable to standard SASL mechanisms

### Optimization Recommendations

**Credential Caching**:
- Use long-lived credentials when possible
- Configure appropriate refresh intervals
- Consider connection pooling for high-throughput applications

**Connection Management**:
- Configure appropriate `reconnect.backoff.ms`
- Monitor connection rate limits
- Use connection pooling for multiple clients

## Version History and Compatibility

### Current Version: 2.3.2
- Fix unreleased file lock issue in Gradle
- Enable FIPS endpoint support
- AWS SDK v2 migration complete
- Jackson Databind security updates

### Key Version Milestones

**2.0.0**: Added SASL/OAUTHBEARER mechanism support
**1.1.0**: Added IAM role support without credential profiles  
**1.0.0**: Initial release with AWS_MSK_IAM mechanism

### Compatibility Matrix

**Kafka Versions**: 2.2.1+ (tested up to 2.8.1)
**Java Versions**: Java 8+
**AWS SDK**: v2.30.23 (migrated from v1)
**MSK Versions**: All versions supporting IAM authentication

## Troubleshooting Guide

### Debug Configuration

**Enable Debug Logging**:
```properties
sasl.jaas.config=software.amazon.msk.auth.iam.IAMLoginModule required awsDebugCreds=true;
```

**Log Level Configuration**:
```properties
log4j.logger.software.amazon.msk.auth.iam=DEBUG
```

### Common Issues

1. **ClassNotFoundException**: Add library to classpath, not plugin path
2. **UnsupportedCallbackException**: Class loader conflicts in plugin environments  
3. **Access Denied**: Check IAM permissions and credential configuration
4. **Too Many Connects**: Increase `reconnect.backoff.ms` setting
5. **Dependency Conflicts**: Use shadow JAR for simpler deployment

### Monitoring and Observability

**Key Metrics to Monitor**:
- Connection establishment time
- Authentication failure rate  
- Credential resolution errors
- Connection rate to brokers

**Log Analysis**:
- Debug credential information (when enabled)
- SASL state transitions
- Retry attempts and backoff timing
- Server response request IDs for correlation

This library provides a robust, production-ready solution for IAM-based authentication with Amazon MSK, with comprehensive error handling, retry logic, and support for various AWS credential sources.