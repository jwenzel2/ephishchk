<?php

declare(strict_types=1);

/**
 * ephishchk - PHP Email Phishing Checker
 * Front Controller
 */

// Define base paths
define('BASE_PATH', dirname(__DIR__));
define('PUBLIC_PATH', __DIR__);

// Early error display for bootstrap issues
error_reporting(E_ALL);
ini_set('display_errors', '1');

// Check for vendor autoload
if (!file_exists(BASE_PATH . '/vendor/autoload.php')) {
    die('Error: Composer dependencies not installed. Please run: composer install');
}

// Composer autoloader
require BASE_PATH . '/vendor/autoload.php';

// Initialize logger early
use Ephishchk\Core\Logger;

$logPath = BASE_PATH . '/storage/logs';
if (!is_dir($logPath)) {
    mkdir($logPath, 0755, true);
}

// Load environment variables
$dotenv = Dotenv\Dotenv::createImmutable(BASE_PATH);
$dotenv->safeLoad();

// Load configuration
$config = require BASE_PATH . '/config/app.php';

// Set timezone EARLY - before any logging happens
// This will be overridden later by database settings if they exist
date_default_timezone_set($config['timezone'] ?? 'America/Chicago');

// Initialize logger with debug mode
$logger = Logger::getInstance($config['paths']['logs'] ?? $logPath, $config['debug'] ?? true);

$logger->info('Request started', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
    'uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
]);

// Error handling based on environment
if ($config['debug']) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
}

// Start session with secure settings
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => $config['secure_cookies'] ?? false,
        'cookie_samesite' => 'Strict',
        'use_strict_mode' => true,
    ]);
}

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
if ($config['secure_cookies'] ?? false) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// Content Security Policy
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

// Bootstrap and run application
use Ephishchk\Core\Application;
use Ephishchk\Core\Request;

try {
    $app = new Application($config);

    // Load timezone from database settings (overrides config)
    try {
        $db = $app->getDatabase();
        $tzRow = $db->fetchOne('SELECT setting_value FROM settings WHERE setting_key = ?', ['timezone']);
        if ($tzRow && !empty($tzRow['setting_value'])) {
            date_default_timezone_set($tzRow['setting_value']);
        }
    } catch (Throwable $e) {
        // Database not ready or settings table doesn't exist yet - use config timezone
        $logger->debug('Could not load timezone from database: ' . $e->getMessage());
    }

    $request = Request::createFromGlobals();

    // Enforce HTTPS if required (before routing)
    try {
        $db = $app->getDatabase();
        $httpsRow = $db->fetchOne('SELECT setting_value FROM settings WHERE setting_key = ?', ['require_https']);
        $requireHttps = ($httpsRow && $httpsRow['setting_value'] === '1');

        if ($requireHttps && !$request->isSecure()) {
            $httpsUrl = $request->getHttpsUrl();
            $logger->info('Redirecting HTTP to HTTPS', [
                'from' => $request->getFullUrl(),
                'to' => $httpsUrl
            ]);
            header('Location: ' . $httpsUrl, true, 301);
            exit;
        }
    } catch (Throwable $e) {
        // Database not ready or settings table doesn't exist yet - skip HTTPS enforcement
        $logger->debug('Could not check HTTPS requirement: ' . $e->getMessage());
    }
    $response = $app->handle($request);
    $response->send();

    $logger->info('Request completed', [
        'status' => $response->getStatusCode(),
    ]);

} catch (Throwable $e) {
    // Always log the error
    $logger->exception($e, 'Uncaught exception in application');

    // Write to a dedicated error log file as well
    $errorLogFile = ($config['paths']['logs'] ?? $logPath) . '/error_' . date('Y-m-d') . '.log';
    $errorMessage = sprintf(
        "[%s] %s\nFile: %s:%d\nTrace:\n%s\n\n",
        date('Y-m-d H:i:s'),
        $e->getMessage(),
        $e->getFile(),
        $e->getLine(),
        $e->getTraceAsString()
    );
    file_put_contents($errorLogFile, $errorMessage, FILE_APPEND | LOCK_EX);

    http_response_code(500);

    // Always show detailed errors for now to help debugging
    // In production, set APP_DEBUG=false in .env to hide details
    if ($config['debug'] ?? true) {
        echo '<!DOCTYPE html><html><head><title>Error</title>';
        echo '<style>body{font-family:sans-serif;padding:20px;background:#f8f9fa;}';
        echo '.error{background:#fff;border:1px solid #e74c3c;border-radius:8px;padding:20px;max-width:900px;margin:0 auto;}';
        echo 'h1{color:#e74c3c;margin-top:0;}pre{background:#2d2d2d;color:#f8f8f2;padding:15px;border-radius:4px;overflow-x:auto;font-size:13px;}';
        echo '.info{background:#fff3cd;border:1px solid #ffc107;padding:10px;border-radius:4px;margin-top:15px;}</style></head><body>';
        echo '<div class="error">';
        echo '<h1>Application Error</h1>';
        echo '<p><strong>Message:</strong> ' . htmlspecialchars($e->getMessage()) . '</p>';
        echo '<p><strong>File:</strong> ' . htmlspecialchars($e->getFile()) . ':' . $e->getLine() . '</p>';
        echo '<h3>Stack Trace:</h3>';
        echo '<pre>' . htmlspecialchars($e->getTraceAsString()) . '</pre>';
        echo '<div class="info"><strong>Log file:</strong> ' . htmlspecialchars($errorLogFile) . '</div>';
        echo '</div></body></html>';
    } else {
        echo '<!DOCTYPE html><html><head><title>Error</title>';
        echo '<style>body{font-family:sans-serif;padding:40px;text-align:center;}</style></head><body>';
        echo '<h1>An error occurred</h1>';
        echo '<p>Please try again later. The error has been logged.</p>';
        echo '<p><a href="/">Return to home</a></p>';
        echo '</body></html>';
    }
}
