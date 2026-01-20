<?php

declare(strict_types=1);

/**
 * Database Configuration
 *
 * CONFIGURATION OPTIONS:
 *
 * Option 1: Use .env file (default, recommended)
 *   - Edit the .env file in the project root
 *   - Set DB_HOST, DB_DATABASE, DB_USERNAME, DB_PASSWORD, etc.
 *   - This file will read from .env automatically
 *
 * Option 2: Direct configuration in this file
 *   - Set USE_ENV_CONFIG to false below
 *   - Edit the $config array with your database credentials
 *   - The .env file will be ignored for database settings
 */

// Set to false to use direct configuration below instead of .env
define('USE_ENV_CONFIG', true);

// Direct configuration (only used if USE_ENV_CONFIG is false)
$config = [
    'driver' => 'mysql',
    'host' => '127.0.0.1',
    'port' => 3306,
    'database' => 'ephishchk',
    'username' => 'root',
    'password' => '',
    'charset' => 'utf8mb4',
    'collation' => 'utf8mb4_unicode_ci',
];

// Build final configuration
if (USE_ENV_CONFIG) {
    // Use environment variables from .env file
    $config = [
        'driver' => $_ENV['DB_DRIVER'] ?? $config['driver'],
        'host' => $_ENV['DB_HOST'] ?? $config['host'],
        'port' => (int) ($_ENV['DB_PORT'] ?? $config['port']),
        'database' => $_ENV['DB_DATABASE'] ?? $config['database'],
        'username' => $_ENV['DB_USERNAME'] ?? $config['username'],
        'password' => $_ENV['DB_PASSWORD'] ?? $config['password'],
        'charset' => $_ENV['DB_CHARSET'] ?? $config['charset'],
        'collation' => $_ENV['DB_COLLATION'] ?? $config['collation'],
    ];
}

// Add PDO options
$config['options'] = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES '{$config['charset']}' COLLATE '{$config['collation']}'",
];

return $config;
