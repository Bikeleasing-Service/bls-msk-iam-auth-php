# Simple Dockerfile for testing MSK IAM Auth PHP
FROM php:8.3-cli-alpine

# Install minimal required extensions
RUN docker-php-ext-install -j$(nproc) simplexml

# Copy project files
WORKDIR /app
COPY . .

# Install dependencies
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
RUN composer install --no-dev --optimize-autoloader

# Default test command
CMD ["php", "test-example.php"]