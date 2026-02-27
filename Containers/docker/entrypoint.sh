#!/bin/bash
set -e

# Generate .env file from Docker environment variables so PHP can read them
cat > /var/www/ephishchk/.env <<EOF
APP_NAME=${APP_NAME:-ephishchk}
APP_ENV=${APP_ENV:-production}
APP_DEBUG=${APP_DEBUG:-false}
APP_TIMEZONE=${APP_TIMEZONE:-UTC}
SECURE_COOKIES=${SECURE_COOKIES:-true}
ENCRYPTION_KEY=${ENCRYPTION_KEY:-change-this-to-a-random-32-character-string}
DB_DRIVER=${DB_DRIVER:-mysql}
DB_HOST=${DB_HOST:-db}
DB_PORT=${DB_PORT:-3306}
DB_DATABASE=${DB_DATABASE:-ephishchk}
DB_USERNAME=${DB_USERNAME:-ephishchk}
DB_PASSWORD=${DB_PASSWORD:-ephishchk_secret}
DNS_CACHE_TTL=${DNS_CACHE_TTL:-300}
MAX_EMAIL_SIZE=${MAX_EMAIL_SIZE:-10485760}
MAX_ATTACHMENT_SIZE=${MAX_ATTACHMENT_SIZE:-33554432}
EOF

# Generate self-signed SSL certificate if not mounted
if [ ! -f /etc/ssl/certs/ephishchk.crt ]; then
    echo "Generating self-signed SSL certificate..."
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout /etc/ssl/private/ephishchk.key \
        -out /etc/ssl/certs/ephishchk.crt \
        -subj "/CN=${SERVER_NAME:-localhost}" \
        -addext "subjectAltName=DNS:${SERVER_NAME:-localhost},DNS:localhost"
fi

# Wait for MySQL to be ready
echo "Waiting for database..."
while ! php -r "try { new PDO('mysql:host=${DB_HOST};port=${DB_PORT}', '${DB_USERNAME}', '${DB_PASSWORD}'); echo 'ok'; } catch(Exception \$e) { exit(1); }" 2>/dev/null; do
    sleep 2
done
echo "Database is ready."

# Run migrations
echo "Running database migrations..."
php database/migrate.php

# Ensure storage directories exist and are writable
mkdir -p storage/logs storage/cache storage/temp
chown -R www-data:www-data storage/

exec apache2ctl -D FOREGROUND
