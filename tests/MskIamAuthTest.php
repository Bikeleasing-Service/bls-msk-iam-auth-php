<?php

declare(strict_types=1);

namespace MskIamAuth\Tests;

use DateTime;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class MskIamAuthTest extends TestCase
{
    private TestableMskIamAuth $auth;

    protected function setUp(): void
    {
        $this->auth = new TestableMskIamAuth('eu-central-1');
    }

    public function testConstructorSetsRegion(): void
    {
        $auth = new TestableMskIamAuth('eu-central-1');
        $this->assertSame('eu-central-1', $auth->getRegion());
    }

    public function testGenerateAuthTokenReturnsBase64String(): void
    {
        $this->auth->setMockCredentials([
            'accessKeyId' => 'AKIATEST123',
            'secretAccessKey' => 'secret123',
            'sessionToken' => 'session123',
            'expiration' => new \DateTime('+1 hour')
        ]);

        $token = $this->auth->generateAuthToken();

        // Should be base64 encoded
        $this->assertNotFalse(base64_decode($token, true));

        // Should contain expected URL components when decoded
        $decodedUrl = base64_decode($token);
        $this->assertStringContainsString('kafka.eu-central-1.amazonaws.com', $decodedUrl);
        $this->assertStringContainsString('Action=kafka-cluster%3AConnect', $decodedUrl);
        $this->assertStringContainsString('X-Amz-Algorithm=AWS4-HMAC-SHA256', $decodedUrl);
    }

    public function testSignRequestCreatesValidSignedUrl(): void
    {
        $this->auth->setMockCredentials([
            'accessKeyId' => 'AKIATEST123',
            'secretAccessKey' => 'secret123',
            'sessionToken' => 'session123',
            'expiration' => new \DateTime('+1 hour')
        ]);

        // Set a fixed datetime for consistent testing
        $this->auth->setMockDateTime('20231201T120000Z');

        $request = [
            'method' => 'GET',
            'hostname' => 'kafka.eu-central-1.amazonaws.com',
            'path' => '/',
            'query' => ['Action' => 'kafka-cluster:Connect'],
            'headers' => ['host' => 'kafka.eu-central-1.amazonaws.com']
        ];

        $signedUrl = $this->auth->testSignRequest($request, [
            'accessKeyId' => 'AKIATEST123',
            'secretAccessKey' => 'secret123',
            'sessionToken' => 'session123'
        ]);

        // Verify URL structure
        $this->assertStringStartsWith('https://kafka.eu-central-1.amazonaws.com/', $signedUrl);
        $this->assertStringContainsString('X-Amz-Algorithm=AWS4-HMAC-SHA256', $signedUrl);
        $this->assertStringContainsString('X-Amz-Credential=AKIATEST123%2F20231201%2Feu-central-1%2Fkafka-cluster%2Faws4_request', $signedUrl);
        $this->assertStringContainsString('X-Amz-Date=20231201T120000Z', $signedUrl);
        $this->assertStringContainsString('X-Amz-Expires=900', $signedUrl);
        $this->assertStringContainsString('X-Amz-Security-Token=session123', $signedUrl);
        $this->assertStringContainsString('X-Amz-SignedHeaders=host', $signedUrl);
        $this->assertStringContainsString('X-Amz-Signature=', $signedUrl);
    }

    public function testCalculateSignatureReturnsConsistentHash(): void
    {
        $stringToSign = "AWS4-HMAC-SHA256\n20231201T120000Z\n20231201/eu-central-1/kafka-cluster/aws4_request\n" .
                       hash('sha256', 'test-canonical-request');

        $signature1 = $this->auth->testCalculateSignature($stringToSign, 'secret123', '20231201');
        $signature2 = $this->auth->testCalculateSignature($stringToSign, 'secret123', '20231201');

        $this->assertSame($signature1, $signature2);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $signature1);
    }

    public function testWebIdentityCredentialsDetection(): void
    {
        // Test when IRSA environment variables are not set
        $credentials = $this->auth->testGetWebIdentityCredentials();
        $this->assertNull($credentials);

        // Test when role ARN is set but token file doesn't exist
        $_ENV['AWS_ROLE_ARN'] = 'arn:aws:iam::123456789012:role/TestRole';
        $credentials = $this->auth->testGetWebIdentityCredentials();
        $this->assertNull($credentials);

        unset($_ENV['AWS_ROLE_ARN']);
    }

    public function testAssumeRoleWithWebIdentityParsesXmlResponse(): void
    {
        $mockXmlResponse = '<?xml version="1.0" encoding="UTF-8"?>
        <AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
            <AssumeRoleWithWebIdentityResult>
                <Credentials>
                    <AccessKeyId>ASIAMOCKKEY123</AccessKeyId>
                    <SecretAccessKey>mocksecret123</SecretAccessKey>
                    <SessionToken>mocktoken123</SessionToken>
                    <Expiration>2023-12-01T13:00:00Z</Expiration>
                </Credentials>
            </AssumeRoleWithWebIdentityResult>
        </AssumeRoleWithWebIdentityResponse>';

        $this->auth->setMockHttpResponse($mockXmlResponse);

        $credentials = $this->auth->testAssumeRoleWithWebIdentity(
            'arn:aws:iam::123456789012:role/TestRole',
            'mock-web-identity-token'
        );

        $this->assertSame('ASIAMOCKKEY123', $credentials['accessKeyId']);
        $this->assertSame('mocksecret123', $credentials['secretAccessKey']);
        $this->assertSame('mocktoken123', $credentials['sessionToken']);
        $this->assertEquals(new \DateTime('2023-12-01T13:00:00Z'), $credentials['expiration']);
    }

    public function testAssumeRoleWithWebIdentityThrowsOnError(): void
    {
        $mockErrorResponse = '<?xml version="1.0" encoding="UTF-8"?>
        <ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
            <Error>
                <Type>Sender</Type>
                <Code>InvalidIdentityToken</Code>
                <Message>The web identity token that was passed is expired</Message>
            </Error>
        </ErrorResponse>';

        $this->auth->setMockHttpResponse($mockErrorResponse);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('STS AssumeRoleWithWebIdentity failed: The web identity token that was passed is expired');

        $this->auth->testAssumeRoleWithWebIdentity(
            'arn:aws:iam::123456789012:role/TestRole',
            'expired-token'
        );
    }

    public function testIMDSCredentialsParsingWithValidJson(): void
    {
        $mockMetadataResponse = json_encode([
            'AccessKeyId' => 'AKIAIMDSTEST123',
            'SecretAccessKey' => 'imdssecret123',
            'Token' => 'imdstoken123',
            'Expiration' => '2023-12-01T13:00:00Z'
        ]);

        $this->auth->setMockHttpResponses([
            'imds-token-response', // IMDSv2 token
            'test-role-name',      // Role name
            $mockMetadataResponse  // Credentials
        ]);

        $credentials = $this->auth->testGetIMDSCredentials();

        $this->assertSame('AKIAIMDSTEST123', $credentials['accessKeyId']);
        $this->assertSame('imdssecret123', $credentials['secretAccessKey']);
        $this->assertSame('imdstoken123', $credentials['sessionToken']);
        $this->assertEquals(new \DateTime('2023-12-01T13:00:00Z'), $credentials['expiration']);
    }

    public function testHttpRequestThrowsOnFailure(): void
    {
        $this->auth->setShouldFailHttpRequest(true);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Failed to fetch from test-url');

        $this->auth->testHttpRequest('test-url');
    }

    public function testTokenExpirationHandling(): void
    {
        // Test with credentials that expire soon
        $expiringSoon = new \DateTime('+5 minutes');
        $this->auth->setMockCredentials([
            'accessKeyId' => 'AKIATEST123',
            'secretAccessKey' => 'secret123',
            'sessionToken' => 'session123',
            'expiration' => $expiringSoon
        ]);

        $token = $this->auth->generateAuthToken();
        $decodedUrl = base64_decode($token);

        // Should still generate a valid token
        $this->assertStringContainsString('X-Amz-Expires=', $decodedUrl);

        // Parse the expires value - should be less than 900 seconds
        preg_match('/X-Amz-Expires=(\d+)/', $decodedUrl, $matches);
        $expiresValue = (int)$matches[1];
        $this->assertLessThan(900, $expiresValue);
        $this->assertGreaterThan(0, $expiresValue);
    }
}
