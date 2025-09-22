<?php

require_once __DIR__ . '/src/MskIamAuth.php';

try {
    $region = $_ENV['AWS_REGION'] ?? 'us-east-1';
    $auth = new MskIamAuth($region);

    echo "Generating AWS MSK IAM auth token...\n";
    $token = $auth->generateAuthToken();

    echo "Token: " . substr($token, 0, 50) . "...\n";
    echo "✅ Success!\n";

} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
    exit(1);
}