<?php

declare(strict_types=1);

/**
 * ephishchk - PHP Email Phishing Checker
 * Front Controller
 */

// Define base paths
define('BASE_PATH', dirname(__DIR__));
define('PUBLIC_PATH', __DIR__);

// Composer autoloader
require BASE_PATH . '/vendor/autoload.php';

// Load environment variables
$dotenv = Dotenv\Dotenv::createImmutable(BASE_PATH);
$dotenv->safeLoad();

// Load configuration
$config = require BASE_PATH . '/config/app.php';

// Error handling based on environment
if ($config['debug']) {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    error_reporting(0);
    ini_set('display_errors', '0');
}

// Set timezone
date_default_timezone_set($config['timezone']);

// Start session with secure settings
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => $config['secure_cookies'],
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true,
]);

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
if ($config['secure_cookies']) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// Content Security Policy
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

// Bootstrap and run application
use Ephishchk\Core\Application;
use Ephishchk\Core\Request;

try {
    $app = new Application($config);
    $request = Request::createFromGlobals();
    $response = $app->handle($request);
    $response->send();
} catch (Throwable $e) {
    if ($config['debug']) {
        echo '<pre>';
        echo 'Error: ' . htmlspecialchars($e->getMessage()) . "\n";
        echo 'File: ' . htmlspecialchars($e->getFile()) . ':' . $e->getLine() . "\n";
        echo 'Trace: ' . htmlspecialchars($e->getTraceAsString());
        echo '</pre>';
    } else {
        http_response_code(500);
        echo 'An error occurred. Please try again later.';
    }

    // Log error
    error_log(sprintf(
        "[%s] %s in %s:%d\n%s",
        date('Y-m-d H:i:s'),
        $e->getMessage(),
        $e->getFile(),
        $e->getLine(),
        $e->getTraceAsString()
    ));
}
