<?php

declare(strict_types=1);

/**
 * Application Configuration
 */

return [
    // Application name
    'name' => $_ENV['APP_NAME'] ?? 'ephishchk',

    // Debug mode
    'debug' => filter_var($_ENV['APP_DEBUG'] ?? false, FILTER_VALIDATE_BOOLEAN),

    // Environment (development, production)
    'env' => $_ENV['APP_ENV'] ?? 'production',

    // Timezone
    'timezone' => $_ENV['APP_TIMEZONE'] ?? 'UTC',

    // Use secure cookies (requires HTTPS)
    'secure_cookies' => filter_var($_ENV['SECURE_COOKIES'] ?? false, FILTER_VALIDATE_BOOLEAN),

    // Encryption key for sensitive data
    'encryption_key' => $_ENV['ENCRYPTION_KEY'] ?? '',

    // Rate limiting defaults
    'rate_limits' => [
        'virustotal' => [
            'free' => [
                'per_minute' => 4,
                'per_day' => 500,
            ],
            'premium' => [
                'per_minute' => 30,
                'per_day' => 10000,
            ],
        ],
    ],

    // DNS cache TTL in seconds
    'dns_cache_ttl' => (int) ($_ENV['DNS_CACHE_TTL'] ?? 300),

    // Maximum email size for parsing (in bytes)
    'max_email_size' => (int) ($_ENV['MAX_EMAIL_SIZE'] ?? 10485760), // 10MB

    // Maximum attachment size for VirusTotal upload (in bytes)
    'max_attachment_size' => (int) ($_ENV['MAX_ATTACHMENT_SIZE'] ?? 33554432), // 32MB

    // Common DKIM selectors to check
    'dkim_selectors' => [
        'default',
        'google',
        'selector1',
        'selector2',
        's1',
        's2',
        'k1',
        'k2',
        'mail',
        'email',
        'dkim',
        'smtp',
    ],

    // Suspicious header patterns
    'suspicious_patterns' => [
        'x_originating_ip_mismatch' => true,
        'authentication_failures' => true,
        'unusual_routing' => true,
        'domain_mismatch' => true,
    ],

    // Paths
    'paths' => [
        'storage' => BASE_PATH . '/storage',
        'logs' => BASE_PATH . '/storage/logs',
        'cache' => BASE_PATH . '/storage/cache',
        'temp' => BASE_PATH . '/storage/temp',
        'templates' => BASE_PATH . '/templates',
    ],
];
