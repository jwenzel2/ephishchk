<?php

/**
 * ephishchk - PHP Email Phishing Checker
 * Root Bootstrap File
 *
 * This file allows running the application from the project root
 * for development purposes. In production, configure your web server
 * to use the /public directory as the document root.
 */

// Change to public directory and include the front controller
chdir(__DIR__ . '/public');
require __DIR__ . '/public/index.php';
