<?php

declare(strict_types=1);

namespace Bls\MskIamAuth;

use DateTime;

class MskIamAuth
{
    protected const SIGNING_SERVICE = 'kafka-cluster';
    protected const HTTP_METHOD = 'GET';
    protected const ACTION_VALUE = 'kafka-cluster:Connect';
    protected const EXPIRY_IN_SECONDS = 900;

    protected string $region;

    public function __construct(string $region)
    {
        $this->region = $region;
    }

    public function generateAuthToken(): string
    {
        $credentials = $this->getCredentials();
        $hostname = "kafka.{$this->region}.amazonaws.com";

        $request = [
            'method' => self::HTTP_METHOD,
            'hostname' => $hostname,
            'path' => '/',
            'query' => ['Action' => self::ACTION_VALUE],
            'headers' => ['host' => $hostname]
        ];

        $signedUrl = $this->signRequest($request, $credentials);

        return rtrim(base64_encode($signedUrl), '=');
    }

    /**
     * @return array{accessKeyId: string, secretAccessKey: string, sessionToken: string|null, expiration: DateTime|null}
     * @throws \RuntimeException
     */
    protected function getCredentials(): array
    {
        // Try EKS service account web identity token first
        if ($webIdentityCredentials = $this->getWebIdentityCredentials()) {
            return $webIdentityCredentials;
        }

        // Fallback to EC2 instance metadata (for EC2-based deployments)
        return $this->getIMDSCredentials();
    }

    /**
     * @return array{accessKeyId: string, secretAccessKey: string, sessionToken: string, expiration: DateTime}|null
     */
    protected function getWebIdentityCredentials(): ?array
    {
        $tokenFile = $_ENV['AWS_WEB_IDENTITY_TOKEN_FILE'] ?? '/var/run/secrets/kubernetes.io/serviceaccount/token';
        $roleArn = $_ENV['AWS_ROLE_ARN'] ?? null;

        if (!$roleArn || !file_exists($tokenFile)) {
            return null;
        }

        $webIdentityToken = file_get_contents($tokenFile);
        if (!$webIdentityToken) {
            return null;
        }

        return $this->assumeRoleWithWebIdentity($roleArn, $webIdentityToken);
    }

    /**
     * @param string $roleArn
     * @param string $webIdentityToken
     * @return array{accessKeyId: string, secretAccessKey: string, sessionToken: string, expiration: DateTime}
     * @throws \Exception
     */
    protected function assumeRoleWithWebIdentity(string $roleArn, string $webIdentityToken): array
    {
        $stsEndpoint = "https://sts.{$this->region}.amazonaws.com/";

        $params = [
            'Action' => 'AssumeRoleWithWebIdentity',
            'RoleArn' => $roleArn,
            'RoleSessionName' => 'msk-iam-auth-' . time(),
            'WebIdentityToken' => $webIdentityToken,
            'Version' => '2011-06-15'
        ];

        $response = $this->httpRequest($stsEndpoint, [], 'POST', http_build_query($params));
        $xml = simplexml_load_string($response);

        if (!$xml || isset($xml->Error)) {
            $errorMsg = isset($xml->Error) ? (string)$xml->Error->Message : 'Failed to assume role';
            throw new \RuntimeException("STS AssumeRoleWithWebIdentity failed: $errorMsg");
        }

        $credentials = $xml->AssumeRoleWithWebIdentityResult->Credentials;

        return [
            'accessKeyId' => (string)$credentials->AccessKeyId,
            'secretAccessKey' => (string)$credentials->SecretAccessKey,
            'sessionToken' => (string)$credentials->SessionToken,
            'expiration' => new \DateTime((string)$credentials->Expiration)
        ];
    }

    /**
     * @return array{accessKeyId: string, secretAccessKey: string, sessionToken: string, expiration: DateTime}
     * @throws \Exception
     */
    protected function getIMDSCredentials(): array
    {
        $token = $this->getIMDSv2Token();

        $role = $this->httpRequest(
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            ['X-aws-ec2-metadata-token' => $token]
        );

        $credentials = json_decode($this->httpRequest(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/{$role}",
            ['X-aws-ec2-metadata-token' => $token]
        ), true);

        return [
            'accessKeyId' => $credentials['AccessKeyId'],
            'secretAccessKey' => $credentials['SecretAccessKey'],
            'sessionToken' => $credentials['Token'],
            'expiration' => new DateTime($credentials['Expiration'])
        ];
    }

    protected function getIMDSv2Token(): string
    {
        return $this->httpRequest(
            'http://169.254.169.254/latest/api/token',
            ['X-aws-ec2-metadata-token-ttl-seconds' => '21600'],
            'PUT'
        );
    }

    /**
     * @param array{method: string, hostname: string, path: string, query: array<string, string>, headers: array<string, string>} $request
     * @param array{accessKeyId: string, secretAccessKey: string, sessionToken: string|null, expiration: DateTime|null} $credentials
     * @return string
     */
    private function signRequest(array $request, array $credentials): string
    {
        $datetime = gmdate('Ymd\THis\Z');
        $date = substr($datetime, 0, 8);

        $credentialScope = "{$date}/{$this->region}/" . self::SIGNING_SERVICE . "/aws4_request";

        // Calculate TTL based on credential expiration
        $ttl = isset($credentials['expiration']) && $credentials['expiration'] instanceof \DateTime
            ? min(($credentials['expiration']->getTimestamp() - time()), self::EXPIRY_IN_SECONDS)
            : self::EXPIRY_IN_SECONDS;

        $query = array_merge($request['query'], [
            'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
            'X-Amz-Credential' => $credentials['accessKeyId'] . '/' . $credentialScope,
            'X-Amz-Date' => $datetime,
            'X-Amz-Expires' => $ttl,
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

    protected function calculateSignature(string $stringToSign, string $secretKey, string $date): string
    {
        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secretKey, true);
        $kRegion = hash_hmac('sha256', $this->region, $kDate, true);
        $kService = hash_hmac('sha256', self::SIGNING_SERVICE, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        return hash_hmac('sha256', $stringToSign, $kSigning);
    }

    /**
     * @param string $url
     * @param array<string, string> $headers
     * @param string $method
     * @param string $body
     * @return string
     * @throws \RuntimeException
     */
    protected function httpRequest(string $url, array $headers = [], string $method = 'GET', string $body = ''): string
    {
        $contextOptions = [
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", array_map(
                    fn($k, $v) => "$k: $v",
                    array_keys($headers),
                    $headers
                )),
                'timeout' => 10
            ]
        ];

        if ($body) {
            $contextOptions['http']['content'] = $body;
            if (!isset($headers['Content-Type'])) {
                $contextOptions['http']['header'] .= "\r\nContent-Type: application/x-www-form-urlencoded";
            }
        }

        $context = stream_context_create($contextOptions);
        $result = file_get_contents($url, false, $context);

        if ($result === false) {
            throw new \RuntimeException("Failed to fetch from $url");
        }

        return $result;
    }
}
