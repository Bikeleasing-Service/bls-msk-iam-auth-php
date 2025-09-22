# Dockerfile for MSK IAM Auth PHP development and testing
FROM php:8.3-cli-alpine

# Install required system packages
RUN apk add --no-cache libxml2-dev git && \
    docker-php-ext-install -j$(nproc) simplexml

# Install Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /app

# Copy composer files first for better caching
COPY composer.json ./

# Install all dependencies (including dev for testing)
RUN composer update --optimize-autoloader

# Copy project files
COPY . .

# Regenerate autoloader with all files present
RUN composer dump-autoload --optimize

# Create directories for test output
RUN mkdir -p coverage .phpunit.cache

# Default command runs PHPUnit tests
CMD ["composer", "test"]