FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install Apache, PHP 8.3, and required extensions
RUN apt-get update && apt-get install -y \
    apache2 \
    php8.3 \
    php8.3-mysql \
    php8.3-mbstring \
    php8.3-curl \
    php8.3-xml \
    php8.3-dom \
    php8.3-zip \
    php8.3-iconv \
    libapache2-mod-php8.3 \
    composer \
    ssl-cert \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure $_ENV is populated from system environment variables
RUN sed -i 's/^variables_order.*/variables_order = "EGPCS"/' /etc/php/8.3/cli/php.ini \
    && sed -i 's/^variables_order.*/variables_order = "EGPCS"/' /etc/php/8.3/apache2/php.ini

# Enable Apache modules
RUN a2enmod rewrite headers ssl

# Configure Apache virtual host with SSL
RUN a2dissite 000-default.conf
COPY docker/apache-vhost.conf /etc/apache2/sites-available/ephishchk.conf
COPY docker/apache-ssl-vhost.conf /etc/apache2/sites-available/ephishchk-ssl.conf
RUN a2ensite ephishchk.conf ephishchk-ssl.conf

# Set working directory
WORKDIR /var/www/ephishchk

# Copy composer files first for better layer caching
COPY composer.json composer.lock* ./
RUN composer install --no-dev --optimize-autoloader --no-scripts

# Copy application files
COPY . .

# Re-run autoloader with full source
RUN composer dump-autoload --optimize

# Set permissions
RUN chown -R www-data:www-data storage/ \
    && chmod -R 775 storage/

# Entrypoint handles SSL cert generation, DB wait, and migrations
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
