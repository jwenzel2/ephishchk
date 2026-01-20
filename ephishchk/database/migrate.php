<?php

declare(strict_types=1);

/**
 * Database Migration Runner
 *
 * Usage: php database/migrate.php
 */

// Define base path if not already defined
if (!defined('BASE_PATH')) {
    define('BASE_PATH', dirname(__DIR__));
}

// Load Composer autoloader
require BASE_PATH . '/vendor/autoload.php';

// Load environment variables
$dotenv = Dotenv\Dotenv::createImmutable(BASE_PATH);
$dotenv->safeLoad();

// Load database config
$config = require BASE_PATH . '/config/database.php';

echo "ephishchk Database Migration\n";
echo "============================\n\n";

try {
    // Connect to database
    $dsn = sprintf(
        '%s:host=%s;port=%d;charset=%s',
        $config['driver'],
        $config['host'],
        $config['port'],
        $config['charset']
    );

    $pdo = new PDO($dsn, $config['username'], $config['password'], $config['options']);

    // Create database if not exists
    $dbName = $config['database'];
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `$dbName` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $pdo->exec("USE `$dbName`");

    echo "Using database: $dbName\n\n";

    // Create migrations tracking table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS migrations (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            migration VARCHAR(255) NOT NULL UNIQUE,
            executed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    // Get already executed migrations
    $stmt = $pdo->query("SELECT migration FROM migrations");
    $executed = $stmt->fetchAll(PDO::FETCH_COLUMN);

    // Get migration files
    $migrationsPath = BASE_PATH . '/database/migrations';
    $files = glob($migrationsPath . '/*.sql');
    sort($files);

    $migrated = 0;

    foreach ($files as $file) {
        $filename = basename($file);

        if (in_array($filename, $executed)) {
            echo "✓ Already executed: $filename\n";
            continue;
        }

        echo "→ Running: $filename ... ";

        $sql = file_get_contents($file);

        // Execute migration
        $pdo->exec($sql);

        // Record migration
        $stmt = $pdo->prepare("INSERT INTO migrations (migration) VALUES (?)");
        $stmt->execute([$filename]);

        echo "Done\n";
        $migrated++;
    }

    echo "\n============================\n";
    if ($migrated > 0) {
        echo "Completed $migrated migration(s)\n";
    } else {
        echo "No new migrations to run\n";
    }

} catch (PDOException $e) {
    echo "\n\nError: " . $e->getMessage() . "\n";
    exit(1);
}
