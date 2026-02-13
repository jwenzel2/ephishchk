<?php

/**
 * Router script for PHP's built-in development server
 *
 * Usage: php -S localhost:8000 -t public public/router.php
 */

$uri = urldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));

// If the request is for a real file, serve it directly
if ($uri !== '/' && file_exists(__DIR__ . $uri)) {
    // Let PHP serve static files
    return false;
}

// Otherwise, route through the front controller
require __DIR__ . '/index.php';
