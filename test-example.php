<?php

require_once __DIR__ . '/src/MskIamAuth.php';

class TestMskIamAuth extends MskIamAuth
{
    public function __construct(string $region)
    {
        parent::__construct($region);
    }

    protected function getCredentials(): array
    {
        return [
            'accessKeyId' => 'AKIATEST1234567890',
            'secretAccessKey' => 'test-secret-key-1234567890123456789012',
            'sessionToken' => 'test-session-token',
            'expiration' => new DateTime('+1 hour')
        ];
    }
}

try {
    $region = $_ENV['AWS_REGION'] ?? 'us-east-1';
    $auth = new TestMskIamAuth($region);

    echo "Generating AWS MSK IAM auth token (test mode)...\n";
    $token = $auth->generateAuthToken();

    echo "Token: " . $token . "\n";
    echo "Success!\n";
    echo "\nFull token length: " . strlen($token) . " characters\n";

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
}