<?php

/**
 * ephishchk Installation Script
 *
 * This script guides you through the installation process:
 * 1. Checks PHP requirements
 * 2. Verifies/creates filesystem structure
 * 3. Configures database connection
 * 4. Runs database migrations
 * 5. Configures VirusTotal API (optional)
 * 6. Creates .env configuration file
 */

declare(strict_types=1);

// Prevent timeout during installation
set_time_limit(300);

// Installation configuration
define('INSTALL_VERSION', '1.0.0');
define('MIN_PHP_VERSION', '8.1.0');
define('BASE_PATH', __DIR__);

// Required PHP extensions
$requiredExtensions = [
    'pdo' => 'PDO (Database connectivity)',
    'pdo_mysql' => 'PDO MySQL Driver',
    'openssl' => 'OpenSSL (Encryption)',
    'mbstring' => 'Multibyte String',
    'json' => 'JSON',
    'curl' => 'cURL (VirusTotal API)',
    'dom' => 'DOM (Email parsing)',
    'libxml' => 'LibXML (Email parsing)',
    'iconv' => 'iconv (Character encoding)',
];

// Optional but recommended extensions
$optionalExtensions = [
    'zip' => 'Zip (Attachment handling)',
    'fileinfo' => 'Fileinfo (MIME detection)',
];

// Directory structure to create/verify
$directories = [
    'storage' => 'Storage root',
    'storage/logs' => 'Log files',
    'storage/cache' => 'Cache files',
    'storage/temp' => 'Temporary files',
];

// Start session for storing installation state
session_start();

// Handle AJAX requests
if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
    header('Content-Type: application/json');

    $action = $_POST['action'] ?? '';

    switch ($action) {
        case 'check_requirements':
            echo json_encode(checkRequirements());
            break;

        case 'check_filesystem':
            echo json_encode(checkFilesystem());
            break;

        case 'test_database':
            echo json_encode(testDatabaseConnection($_POST));
            break;

        case 'run_migrations':
            echo json_encode(runMigrations($_POST));
            break;

        case 'test_virustotal':
            echo json_encode(testVirusTotalApi($_POST));
            break;

        case 'save_configuration':
            echo json_encode(saveConfiguration($_POST));
            break;

        case 'finalize':
            echo json_encode(finalizeInstallation());
            break;

        default:
            echo json_encode(['success' => false, 'error' => 'Unknown action']);
    }
    exit;
}

/**
 * Check PHP requirements
 */
function checkRequirements(): array {
    global $requiredExtensions, $optionalExtensions;

    $results = [
        'success' => true,
        'php_version' => [
            'current' => PHP_VERSION,
            'required' => MIN_PHP_VERSION,
            'passed' => version_compare(PHP_VERSION, MIN_PHP_VERSION, '>='),
        ],
        'required_extensions' => [],
        'optional_extensions' => [],
    ];

    // Check required extensions
    foreach ($requiredExtensions as $ext => $description) {
        $loaded = extension_loaded($ext);
        $results['required_extensions'][$ext] = [
            'description' => $description,
            'loaded' => $loaded,
        ];
        if (!$loaded) {
            $results['success'] = false;
        }
    }

    // Check optional extensions
    foreach ($optionalExtensions as $ext => $description) {
        $results['optional_extensions'][$ext] = [
            'description' => $description,
            'loaded' => extension_loaded($ext),
        ];
    }

    // Check if PHP version requirement is met
    if (!$results['php_version']['passed']) {
        $results['success'] = false;
    }

    return $results;
}

/**
 * Check and create filesystem structure
 */
function checkFilesystem(): array {
    global $directories;

    $results = [
        'success' => true,
        'directories' => [],
        'writable' => [],
    ];

    foreach ($directories as $dir => $description) {
        $path = BASE_PATH . '/' . $dir;
        $exists = is_dir($path);
        $created = false;

        if (!$exists) {
            $created = @mkdir($path, 0755, true);
            $exists = $created;
        }

        $writable = $exists && is_writable($path);

        // Create .gitkeep if directory is empty
        if ($exists && $writable) {
            $gitkeep = $path . '/.gitkeep';
            if (!file_exists($gitkeep)) {
                @file_put_contents($gitkeep, '');
            }
        }

        $results['directories'][$dir] = [
            'description' => $description,
            'path' => $path,
            'exists' => $exists,
            'created' => $created,
            'writable' => $writable,
        ];

        if (!$exists || !$writable) {
            $results['success'] = false;
        }
    }

    // Check if config directory is writable (for .env file)
    $results['writable']['base'] = is_writable(BASE_PATH);
    if (!$results['writable']['base']) {
        $results['success'] = false;
    }

    // Check if composer dependencies are installed
    $results['composer_installed'] = file_exists(BASE_PATH . '/vendor/autoload.php');

    return $results;
}

/**
 * Test database connection
 */
function testDatabaseConnection(array $data): array {
    $host = $data['db_host'] ?? '127.0.0.1';
    $port = (int)($data['db_port'] ?? 3306);
    $database = $data['db_name'] ?? '';
    $username = $data['db_user'] ?? '';
    $password = $data['db_pass'] ?? '';

    if (empty($database) || empty($username)) {
        return ['success' => false, 'error' => 'Database name and username are required'];
    }

    try {
        // First try to connect without database to check credentials
        $dsn = "mysql:host=$host;port=$port;charset=utf8mb4";
        $pdo = new PDO($dsn, $username, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        // Check if database exists
        $stmt = $pdo->query("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = " . $pdo->quote($database));
        $dbExists = $stmt->fetch() !== false;

        // Create database if it doesn't exist
        if (!$dbExists) {
            $pdo->exec("CREATE DATABASE `$database` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $dbCreated = true;
        } else {
            $dbCreated = false;
        }

        // Connect to the specific database
        $pdo->exec("USE `$database`");

        // Store connection info in session
        $_SESSION['db_config'] = [
            'host' => $host,
            'port' => $port,
            'database' => $database,
            'username' => $username,
            'password' => $password,
        ];

        return [
            'success' => true,
            'message' => $dbCreated ? 'Database created and connected successfully' : 'Connected to existing database',
            'db_created' => $dbCreated,
        ];

    } catch (PDOException $e) {
        return [
            'success' => false,
            'error' => 'Database connection failed: ' . $e->getMessage(),
        ];
    }
}

/**
 * Run database migrations
 */
function runMigrations(array $data): array {
    $dbConfig = $_SESSION['db_config'] ?? null;

    if (!$dbConfig) {
        return ['success' => false, 'error' => 'Database not configured. Please complete the database step first.'];
    }

    try {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            $dbConfig['host'],
            $dbConfig['port'],
            $dbConfig['database']
        );

        $pdo = new PDO($dsn, $dbConfig['username'], $dbConfig['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

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
        if (!is_dir($migrationsPath)) {
            return ['success' => false, 'error' => 'Migrations directory not found'];
        }

        $files = glob($migrationsPath . '/*.sql');
        sort($files);

        $migrated = [];
        $errors = [];

        foreach ($files as $file) {
            $filename = basename($file);

            if (in_array($filename, $executed)) {
                continue;
            }

            $sql = file_get_contents($file);

            try {
                $pdo->exec($sql);

                $stmt = $pdo->prepare("INSERT INTO migrations (migration) VALUES (?)");
                $stmt->execute([$filename]);

                $migrated[] = $filename;
            } catch (PDOException $e) {
                $errors[] = "$filename: " . $e->getMessage();
            }
        }

        if (!empty($errors)) {
            return [
                'success' => false,
                'error' => 'Some migrations failed',
                'errors' => $errors,
                'migrated' => $migrated,
            ];
        }

        // Create default admin user if not exists
        $adminCreated = createDefaultAdmin($pdo);

        $message = count($migrated) > 0
            ? 'Ran ' . count($migrated) . ' migration(s) successfully'
            : 'Database is up to date';

        if ($adminCreated) {
            $message .= '. Default admin account created (admin@admin.com / admin)';
        }

        return [
            'success' => true,
            'message' => $message,
            'migrated' => $migrated,
            'admin_created' => $adminCreated,
        ];

    } catch (PDOException $e) {
        return [
            'success' => false,
            'error' => 'Migration failed: ' . $e->getMessage(),
        ];
    }
}

/**
 * Create default admin user
 */
function createDefaultAdmin(PDO $pdo): bool {
    try {
        // Check if admin user already exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute(['admin@admin.com']);

        if ($stmt->fetch()) {
            return false; // Already exists
        }

        // Create admin user with bcrypt password hash
        $passwordHash = password_hash('admin', PASSWORD_BCRYPT, ['cost' => 12]);

        $stmt = $pdo->prepare("
            INSERT INTO users (email, password_hash, display_name, is_active, role, created_at, updated_at)
            VALUES (?, ?, ?, 1, 'admin', NOW(), NOW())
        ");
        $stmt->execute(['admin@admin.com', $passwordHash, 'Administrator']);

        return true;

    } catch (PDOException $e) {
        // Table might not exist yet or role column missing - that's ok
        return false;
    }
}

/**
 * Test VirusTotal API connection
 */
function testVirusTotalApi(array $data): array {
    $apiKey = trim($data['vt_api_key'] ?? '');
    $tier = $data['vt_tier'] ?? 'free';

    if (empty($apiKey)) {
        return ['success' => true, 'message' => 'VirusTotal API skipped (no key provided)'];
    }

    // Test the API key
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'https://www.virustotal.com/api/v3/users/current',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTPHEADER => [
            'x-apikey: ' . $apiKey,
            'Accept: application/json',
        ],
        CURLOPT_SSL_VERIFYPEER => true,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        return ['success' => false, 'error' => 'Connection failed: ' . $error];
    }

    if ($httpCode === 401) {
        return ['success' => false, 'error' => 'Invalid API key'];
    }

    if ($httpCode !== 200) {
        return ['success' => false, 'error' => 'API error (HTTP ' . $httpCode . ')'];
    }

    $data = json_decode($response, true);
    $userId = $data['data']['id'] ?? 'Unknown';

    // Store in session
    $_SESSION['vt_config'] = [
        'api_key' => $apiKey,
        'tier' => $tier,
    ];

    return [
        'success' => true,
        'message' => 'API key validated successfully',
        'user' => $userId,
    ];
}

/**
 * Save all configuration
 */
function saveConfiguration(array $data): array {
    $dbConfig = $_SESSION['db_config'] ?? null;

    if (!$dbConfig) {
        return ['success' => false, 'error' => 'Database not configured'];
    }

    // Generate encryption key
    $encryptionKey = bin2hex(random_bytes(16));

    // Get VirusTotal config
    $vtConfig = $_SESSION['vt_config'] ?? ['api_key' => '', 'tier' => 'free'];

    // Build .env content
    $envContent = <<<ENV
# ephishchk Configuration
# Generated by installer on {$_SERVER['REQUEST_TIME']}

# Application Settings
APP_NAME=ephishchk
APP_ENV=production
APP_DEBUG=false
APP_TIMEZONE=UTC

# Security
SECURE_COOKIES=false
ENCRYPTION_KEY={$encryptionKey}

# Database Configuration
DB_DRIVER=mysql
DB_HOST={$dbConfig['host']}
DB_PORT={$dbConfig['port']}
DB_DATABASE={$dbConfig['database']}
DB_USERNAME={$dbConfig['username']}
DB_PASSWORD={$dbConfig['password']}

# DNS Cache TTL (seconds)
DNS_CACHE_TTL=300

# Maximum email size (bytes) - default 10MB
MAX_EMAIL_SIZE=10485760

# Maximum attachment size for VT upload (bytes) - default 32MB
MAX_ATTACHMENT_SIZE=33554432
ENV;

    // Write .env file
    $envPath = BASE_PATH . '/.env';
    if (file_put_contents($envPath, $envContent) === false) {
        return ['success' => false, 'error' => 'Failed to write .env file'];
    }

    // Save VirusTotal settings to database if API key provided
    if (!empty($vtConfig['api_key'])) {
        try {
            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
                $dbConfig['host'],
                $dbConfig['port'],
                $dbConfig['database']
            );

            $pdo = new PDO($dsn, $dbConfig['username'], $dbConfig['password'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            ]);

            // Encrypt the API key
            $encryptedKey = encryptValue($vtConfig['api_key'], $encryptionKey);

            // Update settings
            $stmt = $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'virustotal_api_key'");
            $stmt->execute([$encryptedKey]);

            $stmt = $pdo->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = 'virustotal_tier'");
            $stmt->execute([$vtConfig['tier']]);

        } catch (PDOException $e) {
            return ['success' => false, 'error' => 'Failed to save VirusTotal settings: ' . $e->getMessage()];
        }
    }

    return [
        'success' => true,
        'message' => 'Configuration saved successfully',
    ];
}

/**
 * Encrypt a value using the encryption key
 */
function encryptValue(string $value, string $key): string {
    $cipher = 'aes-256-gcm';
    $key = hash('sha256', $key, true);
    $iv = random_bytes(openssl_cipher_iv_length($cipher));
    $tag = '';

    $encrypted = openssl_encrypt($value, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);

    return base64_encode($iv . $tag . $encrypted);
}

/**
 * Finalize installation
 */
function finalizeInstallation(): array {
    // Create installation lock file
    $lockFile = BASE_PATH . '/storage/.installed';
    $lockContent = json_encode([
        'version' => INSTALL_VERSION,
        'installed_at' => date('Y-m-d H:i:s'),
        'php_version' => PHP_VERSION,
    ]);

    if (file_put_contents($lockFile, $lockContent) === false) {
        return ['success' => false, 'error' => 'Failed to create installation lock file'];
    }

    // Clear session
    session_destroy();

    return [
        'success' => true,
        'message' => 'Installation completed successfully!',
        'redirect' => '/',
    ];
}

// Check if already installed
$isInstalled = file_exists(BASE_PATH . '/storage/.installed');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Install ephishchk</title>
    <style>
        :root {
            --color-primary: #3b82f6;
            --color-primary-dark: #2563eb;
            --color-success: #22c55e;
            --color-warning: #f59e0b;
            --color-error: #ef4444;
            --color-bg: #f8fafc;
            --color-card: #ffffff;
            --color-text: #1e293b;
            --color-text-muted: #64748b;
            --color-border: #e2e8f0;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--color-bg);
            color: var(--color-text);
            line-height: 1.6;
            min-height: 100vh;
            padding: 2rem;
        }

        .installer {
            max-width: 700px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .header h1 {
            font-size: 2rem;
            color: var(--color-primary);
            margin-bottom: 0.5rem;
        }

        .header p {
            color: var(--color-text-muted);
        }

        .card {
            background: var(--color-card);
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        .card h2 {
            font-size: 1.25rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .card h2 .step {
            background: var(--color-primary);
            color: white;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.875rem;
        }

        .card.completed h2 .step {
            background: var(--color-success);
        }

        .card.active {
            border: 2px solid var(--color-primary);
        }

        .card.disabled {
            opacity: 0.6;
            pointer-events: none;
        }

        .check-list {
            list-style: none;
        }

        .check-list li {
            padding: 0.5rem 0;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            border-bottom: 1px solid var(--color-border);
        }

        .check-list li:last-child {
            border-bottom: none;
        }

        .check-icon {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            flex-shrink: 0;
        }

        .check-icon.pass {
            background: #dcfce7;
            color: var(--color-success);
        }

        .check-icon.fail {
            background: #fee2e2;
            color: var(--color-error);
        }

        .check-icon.warn {
            background: #fef3c7;
            color: var(--color-warning);
        }

        .check-icon.pending {
            background: var(--color-border);
            color: var(--color-text-muted);
        }

        .form-group {
            margin-bottom: 1rem;
        }

        .form-group label {
            display: block;
            font-weight: 500;
            margin-bottom: 0.375rem;
        }

        .form-group input,
        .form-group select {
            width: 100%;
            padding: 0.625rem;
            border: 1px solid var(--color-border);
            border-radius: 4px;
            font-size: 1rem;
        }

        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: var(--color-primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }

        .form-group small {
            display: block;
            margin-top: 0.25rem;
            color: var(--color-text-muted);
            font-size: 0.875rem;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.625rem 1.25rem;
            font-size: 1rem;
            font-weight: 500;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .btn-primary {
            background: var(--color-primary);
            color: white;
        }

        .btn-primary:hover {
            background: var(--color-primary-dark);
        }

        .btn-primary:disabled {
            background: var(--color-border);
            cursor: not-allowed;
        }

        .btn-secondary {
            background: var(--color-border);
            color: var(--color-text);
        }

        .btn-success {
            background: var(--color-success);
            color: white;
        }

        .status-message {
            padding: 0.75rem;
            border-radius: 4px;
            margin-top: 1rem;
            font-size: 0.875rem;
        }

        .status-message.success {
            background: #dcfce7;
            color: #166534;
        }

        .status-message.error {
            background: #fee2e2;
            color: #991b1b;
        }

        .status-message.info {
            background: #e0e7ff;
            color: #3730a3;
        }

        .vt-tier-options {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .tier-option {
            flex: 1;
            border: 2px solid var(--color-border);
            border-radius: 8px;
            padding: 1rem;
            cursor: pointer;
            transition: border-color 0.2s;
        }

        .tier-option:hover {
            border-color: var(--color-primary);
        }

        .tier-option.selected {
            border-color: var(--color-primary);
            background: #eff6ff;
        }

        .tier-option input {
            display: none;
        }

        .tier-option h4 {
            margin-bottom: 0.25rem;
        }

        .tier-option p {
            font-size: 0.875rem;
            color: var(--color-text-muted);
            margin: 0;
        }

        .already-installed {
            text-align: center;
            padding: 3rem;
        }

        .already-installed h2 {
            color: var(--color-success);
            margin-bottom: 1rem;
        }

        .spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid var(--color-border);
            border-top-color: var(--color-primary);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 0.5rem;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .hidden {
            display: none;
        }
    </style>
</head>
<body>
    <div class="installer">
        <div class="header">
            <h1>ephishchk Installation</h1>
            <p>PHP Email Phishing Checker</p>
        </div>

        <?php if ($isInstalled): ?>
        <div class="card already-installed">
            <h2>Already Installed</h2>
            <p>ephishchk has already been installed. If you need to reinstall, delete the file:</p>
            <p><code>storage/.installed</code></p>
            <br>
            <a href="/" class="btn btn-primary">Go to Application</a>
        </div>
        <?php else: ?>

        <!-- Step 1: Requirements -->
        <div class="card active" id="step-requirements">
            <h2><span class="step">1</span> System Requirements</h2>
            <div id="requirements-content">
                <p>Checking system requirements...</p>
            </div>
            <div id="requirements-status"></div>
            <div style="margin-top: 1rem;">
                <button class="btn btn-primary" id="btn-check-requirements">Check Requirements</button>
            </div>
        </div>

        <!-- Step 2: Filesystem -->
        <div class="card disabled" id="step-filesystem">
            <h2><span class="step">2</span> Filesystem</h2>
            <div id="filesystem-content">
                <p>Verifying directory structure...</p>
            </div>
            <div id="filesystem-status"></div>
            <div style="margin-top: 1rem;">
                <button class="btn btn-primary" id="btn-check-filesystem">Verify Filesystem</button>
            </div>
        </div>

        <!-- Step 3: Database -->
        <div class="card disabled" id="step-database">
            <h2><span class="step">3</span> Database Configuration</h2>
            <form id="database-form">
                <div class="form-row">
                    <div class="form-group">
                        <label for="db_host">Database Host</label>
                        <input type="text" id="db_host" name="db_host" value="127.0.0.1" required>
                    </div>
                    <div class="form-group">
                        <label for="db_port">Port</label>
                        <input type="number" id="db_port" name="db_port" value="3306" required>
                    </div>
                </div>
                <div class="form-group">
                    <label for="db_name">Database Name</label>
                    <input type="text" id="db_name" name="db_name" value="ephishchk" required>
                    <small>Will be created if it doesn't exist</small>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label for="db_user">Username</label>
                        <input type="text" id="db_user" name="db_user" required>
                    </div>
                    <div class="form-group">
                        <label for="db_pass">Password</label>
                        <input type="password" id="db_pass" name="db_pass">
                    </div>
                </div>
                <div id="database-status"></div>
                <button type="submit" class="btn btn-primary">Test Connection & Create Database</button>
            </form>
        </div>

        <!-- Step 4: Migrations -->
        <div class="card disabled" id="step-migrations">
            <h2><span class="step">4</span> Database Tables</h2>
            <p>Create the required database tables.</p>
            <div id="migrations-status"></div>
            <div style="margin-top: 1rem;">
                <button class="btn btn-primary" id="btn-run-migrations">Run Migrations</button>
            </div>
        </div>

        <!-- Step 5: VirusTotal -->
        <div class="card disabled" id="step-virustotal">
            <h2><span class="step">5</span> VirusTotal API (Optional)</h2>
            <p>Configure VirusTotal integration for file and URL scanning.</p>

            <div class="vt-tier-options">
                <label class="tier-option selected">
                    <input type="radio" name="vt_tier" value="free" checked>
                    <h4>Free Tier</h4>
                    <p>4 requests/min, 500/day</p>
                </label>
                <label class="tier-option">
                    <input type="radio" name="vt_tier" value="premium">
                    <h4>Premium Tier</h4>
                    <p>30 requests/min, 10,000/day</p>
                </label>
            </div>

            <div class="form-group">
                <label for="vt_api_key">API Key</label>
                <input type="password" id="vt_api_key" name="vt_api_key" placeholder="Leave empty to skip">
                <small>Get a free API key at <a href="https://www.virustotal.com/gui/join-us" target="_blank">virustotal.com</a></small>
            </div>

            <div id="virustotal-status"></div>
            <div style="margin-top: 1rem;">
                <button class="btn btn-secondary" id="btn-skip-vt">Skip</button>
                <button class="btn btn-primary" id="btn-test-vt">Test & Save API Key</button>
            </div>
        </div>

        <!-- Step 6: Finalize -->
        <div class="card disabled" id="step-finalize">
            <h2><span class="step">6</span> Complete Installation</h2>
            <p>Save configuration and complete the installation.</p>
            <div id="finalize-status"></div>
            <div style="margin-top: 1rem;">
                <button class="btn btn-success" id="btn-finalize">Complete Installation</button>
            </div>
        </div>

        <?php endif; ?>
    </div>

    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const steps = ['requirements', 'filesystem', 'database', 'migrations', 'virustotal', 'finalize'];
        let currentStep = 0;

        function showStatus(elementId, message, type) {
            const el = document.getElementById(elementId);
            el.innerHTML = `<div class="status-message ${type}">${message}</div>`;
        }

        function clearStatus(elementId) {
            document.getElementById(elementId).innerHTML = '';
        }

        function activateStep(stepIndex) {
            steps.forEach((step, index) => {
                const card = document.getElementById('step-' + step);
                card.classList.remove('active', 'disabled', 'completed');
                if (index < stepIndex) {
                    card.classList.add('completed');
                } else if (index === stepIndex) {
                    card.classList.add('active');
                } else {
                    card.classList.add('disabled');
                }
            });
            currentStep = stepIndex;
        }

        async function makeRequest(action, data = {}) {
            const formData = new FormData();
            formData.append('action', action);
            for (const [key, value] of Object.entries(data)) {
                formData.append(key, value);
            }

            const response = await fetch('install.php', {
                method: 'POST',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
                body: formData
            });

            return response.json();
        }

        // Step 1: Check Requirements
        document.getElementById('btn-check-requirements').addEventListener('click', async function() {
            this.disabled = true;
            this.innerHTML = '<span class="spinner"></span> Checking...';

            const result = await makeRequest('check_requirements');

            let html = '<ul class="check-list">';

            // PHP Version
            const phpClass = result.php_version.passed ? 'pass' : 'fail';
            const phpIcon = result.php_version.passed ? '✓' : '✗';
            html += `<li><span class="check-icon ${phpClass}">${phpIcon}</span> PHP Version: ${result.php_version.current} (requires ${result.php_version.required}+)</li>`;

            // Required extensions
            for (const [ext, info] of Object.entries(result.required_extensions)) {
                const extClass = info.loaded ? 'pass' : 'fail';
                const extIcon = info.loaded ? '✓' : '✗';
                html += `<li><span class="check-icon ${extClass}">${extIcon}</span> ${info.description}</li>`;
            }

            // Optional extensions
            for (const [ext, info] of Object.entries(result.optional_extensions)) {
                const extClass = info.loaded ? 'pass' : 'warn';
                const extIcon = info.loaded ? '✓' : '○';
                html += `<li><span class="check-icon ${extClass}">${extIcon}</span> ${info.description} (optional)</li>`;
            }

            html += '</ul>';
            document.getElementById('requirements-content').innerHTML = html;

            this.disabled = false;
            this.textContent = 'Check Requirements';

            if (result.success) {
                showStatus('requirements-status', 'All requirements met!', 'success');
                activateStep(1);
            } else {
                showStatus('requirements-status', 'Please install missing requirements before continuing.', 'error');
            }
        });

        // Step 2: Check Filesystem
        document.getElementById('btn-check-filesystem').addEventListener('click', async function() {
            this.disabled = true;
            this.innerHTML = '<span class="spinner"></span> Checking...';

            const result = await makeRequest('check_filesystem');

            let html = '<ul class="check-list">';

            for (const [dir, info] of Object.entries(result.directories)) {
                const dirClass = info.exists && info.writable ? 'pass' : 'fail';
                const dirIcon = info.exists && info.writable ? '✓' : '✗';
                let status = info.exists ? (info.writable ? 'OK' : 'Not writable') : 'Missing';
                if (info.created) status = 'Created';
                html += `<li><span class="check-icon ${dirClass}">${dirIcon}</span> ${info.description} (${dir}) - ${status}</li>`;
            }

            const composerClass = result.composer_installed ? 'pass' : 'fail';
            const composerIcon = result.composer_installed ? '✓' : '✗';
            html += `<li><span class="check-icon ${composerClass}">${composerIcon}</span> Composer dependencies ${result.composer_installed ? 'installed' : 'not installed - run: composer install'}</li>`;

            html += '</ul>';
            document.getElementById('filesystem-content').innerHTML = html;

            this.disabled = false;
            this.textContent = 'Verify Filesystem';

            if (result.success && result.composer_installed) {
                showStatus('filesystem-status', 'Filesystem is ready!', 'success');
                activateStep(2);
            } else if (!result.composer_installed) {
                showStatus('filesystem-status', 'Please run "composer install" in the project directory.', 'error');
            } else {
                showStatus('filesystem-status', 'Please fix the directory permissions and try again.', 'error');
            }
        });

        // Step 3: Database
        document.getElementById('database-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const btn = this.querySelector('button');
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Testing...';

            const formData = new FormData(this);
            const data = Object.fromEntries(formData.entries());

            const result = await makeRequest('test_database', data);

            btn.disabled = false;
            btn.textContent = 'Test Connection & Create Database';

            if (result.success) {
                showStatus('database-status', result.message, 'success');
                activateStep(3);
            } else {
                showStatus('database-status', result.error, 'error');
            }
        });

        // Step 4: Migrations
        document.getElementById('btn-run-migrations').addEventListener('click', async function() {
            this.disabled = true;
            this.innerHTML = '<span class="spinner"></span> Running...';

            const result = await makeRequest('run_migrations');

            this.disabled = false;
            this.textContent = 'Run Migrations';

            if (result.success) {
                let msg = result.message;
                if (result.migrated && result.migrated.length > 0) {
                    msg += '<br>Migrations: ' + result.migrated.join(', ');
                }
                showStatus('migrations-status', msg, 'success');
                activateStep(4);
            } else {
                let msg = result.error;
                if (result.errors) {
                    msg += '<br>' + result.errors.join('<br>');
                }
                showStatus('migrations-status', msg, 'error');
            }
        });

        // Step 5: VirusTotal
        document.querySelectorAll('.tier-option').forEach(option => {
            option.addEventListener('click', function() {
                document.querySelectorAll('.tier-option').forEach(o => o.classList.remove('selected'));
                this.classList.add('selected');
                this.querySelector('input').checked = true;
            });
        });

        document.getElementById('btn-skip-vt').addEventListener('click', function() {
            showStatus('virustotal-status', 'VirusTotal integration skipped. You can configure it later in Settings.', 'info');
            activateStep(5);
        });

        document.getElementById('btn-test-vt').addEventListener('click', async function() {
            const apiKey = document.getElementById('vt_api_key').value;
            const tier = document.querySelector('input[name="vt_tier"]:checked').value;

            if (!apiKey) {
                showStatus('virustotal-status', 'Please enter an API key or click Skip.', 'error');
                return;
            }

            this.disabled = true;
            this.innerHTML = '<span class="spinner"></span> Testing...';

            const result = await makeRequest('test_virustotal', { vt_api_key: apiKey, vt_tier: tier });

            this.disabled = false;
            this.textContent = 'Test & Save API Key';

            if (result.success) {
                showStatus('virustotal-status', result.message + (result.user ? ' (User: ' + result.user + ')' : ''), 'success');
                activateStep(5);
            } else {
                showStatus('virustotal-status', result.error, 'error');
            }
        });

        // Step 6: Finalize
        document.getElementById('btn-finalize').addEventListener('click', async function() {
            this.disabled = true;
            this.innerHTML = '<span class="spinner"></span> Saving...';

            // First save configuration
            const saveResult = await makeRequest('save_configuration');

            if (!saveResult.success) {
                showStatus('finalize-status', saveResult.error, 'error');
                this.disabled = false;
                this.textContent = 'Complete Installation';
                return;
            }

            // Then finalize
            const result = await makeRequest('finalize');

            if (result.success) {
                showStatus('finalize-status', result.message + ' Redirecting...', 'success');
                setTimeout(() => {
                    window.location.href = result.redirect || '/';
                }, 2000);
            } else {
                showStatus('finalize-status', result.error, 'error');
                this.disabled = false;
                this.textContent = 'Complete Installation';
            }
        });

        // Auto-start requirements check
        document.getElementById('btn-check-requirements').click();
    });
    </script>
</body>
</html>
