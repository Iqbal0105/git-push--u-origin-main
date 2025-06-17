FROM php:7.4-apache

# Install ModSecurity and cron
RUN apt-get update && \
    apt-get install -y libapache2-mod-security2 cron && \
    a2enmod security2

# Copy ModSecurity configuration and rules
COPY conf/security/mod_security.conf /etc/modsecurity/
COPY conf/security/rules/ /etc/modsecurity/rules.d/

# Secure environment setup
RUN mkdir -p /var/www/html/modules && \
    mkdir -p /secrets && \
    chown -R www-data:www-data /var/www/html && \
    chmod 755 /var/www/html && \
    find /var/www/html -type d -exec chmod 755 {} \; && \
    find /var/www/html -type f -exec chmod 644 {} \; && \
    echo "FLAG_KEY=$(openssl rand -hex 32)" > /secrets/flag_key.txt && \
    chmod 600 /secrets/flag_key.txt

# Copy PHP configuration
COPY conf/php.ini /usr/local/etc/php/conf.d/

# Copy web source
COPY src/ /var/www/html/

# Setup flag rotation
COPY secrets/generate_flag.sh /secrets/generate_flag.sh
RUN chmod 750 /secrets/generate_flag.sh && \
    (crontab -u www-data -l ; echo "*/5 * * * * /secrets/generate_flag.sh") | crontab -u www-data -

# Final setup
RUN mkdir -p /var/log/apache2 && \
    chown www-data:www-data /var/log/apache2 && \
    touch /var/log/apache2/flag_generation.log && \
    chown www-data:www-data /var/log/apache2/flag_generation.log

# Start services
CMD ["sh", "-c", "/secrets/generate_flag.sh && cron && apache2-foreground"]