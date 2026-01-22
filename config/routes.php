<?php

declare(strict_types=1);

/**
 * Route Configuration
 */

use Ephishchk\Controllers\ScanController;
use Ephishchk\Controllers\HistoryController;
use Ephishchk\Controllers\SettingsController;
use Ephishchk\Controllers\AuthController;
use Ephishchk\Controllers\AdminController;
use Ephishchk\Controllers\PreferencesController;

return [
    // Authentication
    ['GET', '/login', [AuthController::class, 'showLogin']],
    ['POST', '/login', [AuthController::class, 'login']],
    ['GET', '/register', [AuthController::class, 'showRegister']],
    ['POST', '/register', [AuthController::class, 'register']],
    ['POST', '/logout', [AuthController::class, 'logout']],

    // Home page - scan form
    ['GET', '/', [ScanController::class, 'index']],

    // Quick check (domain/email)
    ['POST', '/scan/quick', [ScanController::class, 'quickCheck']],

    // Full email analysis
    ['POST', '/scan/full', [ScanController::class, 'fullAnalysis']],

    // Get scan status (for AJAX polling)
    ['GET', '/scan/{id}/status', [ScanController::class, 'status']],

    // View scan result
    ['GET', '/scan/{id}', [ScanController::class, 'show']],

    // Scan history
    ['GET', '/history', [HistoryController::class, 'index']],

    // Delete scan from history
    ['POST', '/history/{id}/delete', [HistoryController::class, 'delete']],

    // Settings page
    ['GET', '/settings', [SettingsController::class, 'index']],

    // Save settings
    ['POST', '/settings', [SettingsController::class, 'save']],

    // Test VirusTotal connection
    ['POST', '/settings/test-virustotal', [SettingsController::class, 'testVirusTotal']],

    // User preferences
    ['GET', '/preferences', [PreferencesController::class, 'index']],
    ['POST', '/preferences', [PreferencesController::class, 'save']],
    ['POST', '/preferences/password', [PreferencesController::class, 'changePassword']],

    // Admin - User Management
    ['GET', '/admin/users', [AdminController::class, 'users']],
    ['POST', '/admin/users/role', [AdminController::class, 'updateRole']],
    ['POST', '/admin/users/toggle-active', [AdminController::class, 'toggleActive']],
];
