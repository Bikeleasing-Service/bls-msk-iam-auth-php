#!/bin/bash

echo "Testing MSK IAM Auth in Docker container..."
docker build -t msk-iam-auth-test .
docker run --rm -e AWS_REGION=us-east-1 msk-iam-auth-test