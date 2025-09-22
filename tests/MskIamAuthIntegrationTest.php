<?php

declare(strict_types=1);

namespace MskIamAuth\Tests;

use DateTime;
use PHPUnit\Framework\TestCase;

class MskIamAuthIntegrationTest extends TestCase
{
    public function testGenerateTokenWithMockCredentials(): void
    {
        $auth = new TestableMskIamAuth('eu-central-1');
        $auth->setMockCredentials([
            'accessKeyId' => 'AKIATEST1234567890',
            'secretAccessKey' => 'test-secret-key-1234567890123456789012',
            'sessionToken' => 'test-session-token-from-web-identity',
            'expiration' => new DateTime('+1 hour')
        ]);

        $token = $auth->generateAuthToken();

        // Verify it's a valid base64 string
        $this->assertNotFalse(base64_decode($token, true));

        // Decode and verify URL structure
        $decodedUrl = base64_decode($token);
        $this->assertStringStartsWith('https://kafka.eu-central-1.amazonaws.com/', $decodedUrl);

        // Parse URL to verify components
        $urlParts = parse_url($decodedUrl);
        $this->assertSame('https', $urlParts['scheme']);
        $this->assertSame('kafka.eu-central-1.amazonaws.com', $urlParts['host']);
        $this->assertSame('/', $urlParts['path']);

        parse_str($urlParts['query'], $queryParams);

        // Verify required parameters are present
        $requiredParams = [
            'Action',
            'X-Amz-Algorithm',
            'X-Amz-Credential',
            'X-Amz-Date',
            'X-Amz-Expires',
            'X-Amz-Security-Token',
            'X-Amz-SignedHeaders',
            'X-Amz-Signature'
        ];

        foreach ($requiredParams as $param) {
            $this->assertArrayHasKey($param, $queryParams, "Missing required parameter: $param");
            $this->assertNotEmpty($queryParams[$param], "Empty parameter: $param");
        }

        // Verify parameter values
        $this->assertSame('kafka-cluster:Connect', $queryParams['Action']);
        $this->assertSame('AWS4-HMAC-SHA256', $queryParams['X-Amz-Algorithm']);
        $this->assertStringStartsWith('AKIATEST1234567890/', $queryParams['X-Amz-Credential']);
        $this->assertMatchesRegularExpression('/^\d{8}T\d{6}Z$/', $queryParams['X-Amz-Date']);
        $this->assertSame('900', $queryParams['X-Amz-Expires']);
        $this->assertSame('test-session-token-from-web-identity', $queryParams['X-Amz-Security-Token']);
        $this->assertSame('host', $queryParams['X-Amz-SignedHeaders']);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $queryParams['X-Amz-Signature']);

        // Verify credential scope format
        $credentialParts = explode('/', $queryParams['X-Amz-Credential']);
        $this->assertCount(5, $credentialParts);
        $this->assertSame('AKIATEST1234567890', $credentialParts[0]);
        $this->assertMatchesRegularExpression('/^\d{8}$/', $credentialParts[1]); // Date
        $this->assertSame('eu-central-1', $credentialParts[2]); // Region
        $this->assertSame('kafka-cluster', $credentialParts[3]); // Service
        $this->assertSame('aws4_request', $credentialParts[4]); // Terminator
    }

    public function testTokenCompatibilityWithDifferentRegions(): void
    {
        $regions = ['us-east-1', 'us-west-2', 'eu-central-1', 'ap-southeast-1'];

        foreach ($regions as $region) {
            $auth = new TestableMskIamAuth($region);
            $auth->setMockCredentials([
                'accessKeyId' => 'AKIATEST123',
                'secretAccessKey' => 'secret123',
                'sessionToken' => 'session123',
                'expiration' => new DateTime('+1 hour')
            ]);

            $token = $auth->generateAuthToken();
            $decodedUrl = base64_decode($token);

            // Verify region-specific hostname
            $this->assertStringContainsString("kafka.{$region}.amazonaws.com", $decodedUrl);

            // Verify region in credential scope
            parse_str(parse_url($decodedUrl)['query'], $queryParams);
            $credentialParts = explode('/', $queryParams['X-Amz-Credential']);
            $this->assertSame($region, $credentialParts[2]);
        }
    }

    public function testTokenWithoutSessionToken(): void
    {
        $auth = new TestableMskIamAuth('eu-central-1');
        $auth->setMockCredentials([
            'accessKeyId' => 'AKIATEST123',
            'secretAccessKey' => 'secret123',
            // No session token (like for EC2 instance roles)
            'expiration' => new DateTime('+1 hour')
        ]);

        $token = $auth->generateAuthToken();
        $decodedUrl = base64_decode($token);

        // Should not contain X-Amz-Security-Token
        $this->assertStringNotContainsString('X-Amz-Security-Token', $decodedUrl);

        // But should still be valid
        parse_str(parse_url($decodedUrl)['query'], $queryParams);
        $this->assertArrayHasKey('X-Amz-Signature', $queryParams);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $queryParams['X-Amz-Signature']);
    }

    public function testTokenExpirationRespectingCredentialExpiry(): void
    {
        // Test with credentials expiring in 5 minutes
        $nearExpiry = new DateTime('+5 minutes');
        $auth = new TestableMskIamAuth('eu-central-1');
        $auth->setMockCredentials([
            'accessKeyId' => 'AKIATEST123',
            'secretAccessKey' => 'secret123',
            'sessionToken' => 'session123',
            'expiration' => $nearExpiry
        ]);

        $token = $auth->generateAuthToken();
        $decodedUrl = base64_decode($token);

        parse_str(parse_url($decodedUrl)['query'], $queryParams);

        // Should have expires less than default 900 seconds
        $expires = (int)$queryParams['X-Amz-Expires'];
        $this->assertLessThan(900, $expires);
        $this->assertGreaterThan(0, $expires);
        $this->assertLessThanOrEqual(300, $expires); // Should be close to 5 minutes (300 seconds)
    }

    public function testBase64UrlSafeEncoding(): void
    {
        $auth = new TestableMskIamAuth('eu-central-1');
        $auth->setMockCredentials([
            'accessKeyId' => 'AKIATEST123',
            'secretAccessKey' => 'secret123',
            'sessionToken' => 'session123',
            'expiration' => new DateTime('+1 hour')
        ]);

        $token = $auth->generateAuthToken();

        // Should not contain padding characters
        $this->assertStringNotContainsString('=', $token);

        // Should be valid base64url (which is valid base64)
        $this->assertNotFalse(base64_decode($token, true));

        // Decoded content should be a valid URL
        $decodedUrl = base64_decode($token);
        $this->assertStringStartsWith('https://', $decodedUrl);
        $this->assertNotFalse(parse_url($decodedUrl));
    }

    public function testConsistentSignatureGeneration(): void
    {
        $auth = new TestableMskIamAuth('eu-central-1');
        $auth->setMockCredentials([
            'accessKeyId' => 'AKIATEST123',
            'secretAccessKey' => 'secret123',
            'sessionToken' => 'session123',
            'expiration' => new DateTime('+1 hour')
        ]);

        // Fix the datetime for consistent signatures
        $auth->setMockDateTime('20231201T120000Z');

        $token1 = $auth->generateAuthToken();
        $token2 = $auth->generateAuthToken();

        // Should generate identical tokens with same credentials and timestamp
        $this->assertSame($token1, $token2);

        // Verify the signature is consistent
        $decodedUrl = base64_decode($token1);
        parse_str(parse_url($decodedUrl)['query'], $queryParams);

        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $queryParams['X-Amz-Signature']);
    }
}
