<?php

declare(strict_types=1);

namespace MskIamAuth\Tests;

use DateTime;
use Bls\MskIamAuth\MskIamAuth;

class TestableMskIamAuth extends MskIamAuth
{
    private ?array $mockCredentials = null;
    private ?string $mockHttpResponse = null;
    private array $mockHttpResponses = [];
    private int $httpResponseIndex = 0;
    private bool $shouldFailHttpRequest = false;
    private ?string $mockDateTime = null;

    public function getRegion(): string
    {
        return $this->region;
    }

    public function setMockCredentials(array $credentials): void
    {
        $this->mockCredentials = $credentials;
    }

    public function setMockHttpResponse(string $response): void
    {
        $this->mockHttpResponse = $response;
    }

    public function setMockHttpResponses(array $responses): void
    {
        $this->mockHttpResponses = $responses;
        $this->httpResponseIndex = 0;
    }

    public function setShouldFailHttpRequest(bool $shouldFail): void
    {
        $this->shouldFailHttpRequest = $shouldFail;
    }

    public function setMockDateTime(string $dateTime): void
    {
        $this->mockDateTime = $dateTime;
    }

    protected function getCredentials(): array
    {
        if ($this->mockCredentials !== null) {
            return $this->mockCredentials;
        }

        return parent::getCredentials();
    }

    public function testGetWebIdentityCredentials(): ?array
    {
        return $this->getWebIdentityCredentials();
    }

    public function testAssumeRoleWithWebIdentity(string $roleArn, string $webIdentityToken): array
    {
        // Override the HTTP request method to avoid actual network calls
        if ($this->mockHttpResponse !== null || !empty($this->mockHttpResponses)) {
            return $this->assumeRoleWithWebIdentity($roleArn, $webIdentityToken);
        }

        // Fallback for tests without mocked responses
        throw new \RuntimeException('No mock HTTP response set for AssumeRoleWithWebIdentity test');
    }

    public function testGetIMDSCredentials(): array
    {
        return $this->getIMDSCredentials();
    }

    public function testSignRequest(array $request, array $credentials): string
    {
        return $this->signRequest($request, $credentials);
    }

    public function testCalculateSignature(string $stringToSign, string $secretKey, string $date): string
    {
        return $this->calculateSignature($stringToSign, $secretKey, $date);
    }

    public function testHttpRequest(string $url, array $headers = [], string $method = 'GET', string $body = ''): string
    {
        return $this->httpRequest($url, $headers, $method, $body);
    }

    protected function httpRequest(string $url, array $headers = [], string $method = 'GET', string $body = ''): string
    {
        if ($this->shouldFailHttpRequest) {
            throw new \RuntimeException("Failed to fetch from $url");
        }

        if ($this->mockHttpResponse !== null) {
            return $this->mockHttpResponse;
        }

        if (!empty($this->mockHttpResponses)) {
            $response = $this->mockHttpResponses[$this->httpResponseIndex] ?? '';
            $this->httpResponseIndex++;
            return $response;
        }

        return parent::httpRequest($url, $headers, $method, $body);
    }

    protected function signRequest(array $request, array $credentials): string
    {
        $datetime = $this->mockDateTime ?? gmdate('Ymd\THis\Z');
        $date = substr($datetime, 0, 8);

        $credentialScope = "{$date}/{$this->region}/" . self::SIGNING_SERVICE . "/aws4_request";

        $query = array_merge($request['query'], [
            'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
            'X-Amz-Credential' => $credentials['accessKeyId'] . '/' . $credentialScope,
            'X-Amz-Date' => $datetime,
            'X-Amz-Expires' => self::EXPIRY_IN_SECONDS,
            'X-Amz-SignedHeaders' => 'host'
        ]);

        if (isset($credentials['sessionToken'])) {
            $query['X-Amz-Security-Token'] = $credentials['sessionToken'];
        }

        ksort($query);
        $queryString = http_build_query($query, '', '&', PHP_QUERY_RFC3986);

        $canonicalRequest = implode("\n", [
            $request['method'],
            $request['path'],
            $queryString,
            "host:{$request['hostname']}",
            '',
            'host',
            hash('sha256', '')
        ]);

        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256',
            $datetime,
            $credentialScope,
            hash('sha256', $canonicalRequest)
        ]);

        $signature = $this->calculateSignature($stringToSign, $credentials['secretAccessKey'], $date);
        $query['X-Amz-Signature'] = $signature;

        return "https://{$request['hostname']}{$request['path']}?" . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    // Expose protected constants for testing
    public const SIGNING_SERVICE = parent::SIGNING_SERVICE;
    public const HTTP_METHOD = parent::HTTP_METHOD;
    public const ACTION_VALUE = parent::ACTION_VALUE;
    public const EXPIRY_IN_SECONDS = parent::EXPIRY_IN_SECONDS;
}
