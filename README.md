# ephishchk

A web-based PHP application for checking emails for phishing indicators.

## Features

- **Email Authentication Verification**
  - SPF (Sender Policy Framework) record analysis
  - DKIM (DomainKeys Identified Mail) selector scanning
  - DMARC (Domain-based Message Authentication) policy checking

- **Header Analysis**
  - Domain mismatch detection (From vs Return-Path vs Reply-To)
  - Authentication result parsing
  - Suspicious pattern identification
  - Display name spoofing detection

- **Link/URL Scanning**
  - URL extraction from HTML and plain text
  - Domain reputation analysis
  - Typosquatting detection
  - URL shortener identification

- **Attachment Analysis**
  - File type risk assessment
  - SHA-256 hash calculation
  - VirusTotal integration for malware scanning

- **Scan History**
  - Track all previous scans
  - Risk score trending
  - Detailed result storage

## Requirements

- PHP 8.1 or higher
- MySQL 5.7+ or MariaDB 10.3+
- Composer
- Web server (Apache/Nginx)

### Required PHP Extensions

- pdo
- pdo_mysql
- openssl
- mbstring
- json
- curl
- dom
- libxml
- iconv

### Optional PHP Extensions

- zip (for attachment handling)
- fileinfo (for MIME type detection)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/jwenzel2/ephishchk.git
cd ephishchk/ephishchk
```

### 2. Install Dependencies

```bash
composer install
```

### 3. Web Server Configuration

#### Apache

Point your document root to the `public` directory. The included `.htaccess` file handles URL rewriting.

```apache
<VirtualHost *:80>
    ServerName ephishchk.local
    DocumentRoot /path/to/ephishchkpublic

    <Directory /path/to/ephishchk/public>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

#### Nginx

```nginx
server {
    listen 80;
    server_name ephishchk.local;
    root /path/to/ephishchk/public;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }
}
```

#### PHP Built-in Server (Development Only)

For quick testing without configuring a web server:

```bash
cd ephishchk/
php -S localhost:8000 -t public public/router.php
```

Then open http://localhost:8000 in your browser.

**Note:** The built-in server is for development only. Use Apache or Nginx in production.

### 4. Run the Installer

Navigate to `http://your-domain/install.php` in your browser.

The installation wizard will guide you through:

1. **System Requirements** - Verifies PHP version and extensions
2. **Filesystem** - Creates required directories
3. **Database** - Configures and creates the database
4. **Migrations** - Sets up database tables
5. **VirusTotal** - Optional API configuration
6. **Complete** - Saves configuration and finalizes setup

### 5. Manual Installation (Alternative)

If you prefer manual setup:

#### Create Environment File

```bash
cp .env.example .env
```

Edit `.env` with your settings:

```env
APP_NAME=ephishchk
APP_ENV=production
APP_DEBUG=false
APP_TIMEZONE=UTC

SECURE_COOKIES=false
ENCRYPTION_KEY=your-32-character-random-string

DB_DRIVER=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=ephishchk
DB_USERNAME=your_username
DB_PASSWORD=your_password
```

#### Create Database

```sql
CREATE DATABASE ephishchk CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

#### Run Migrations

```bash
php database/migrate.php
```

## Usage

### Quick Check

Enter an email address or domain to check its email authentication configuration:

1. Go to the home page
2. Select "Quick Check" tab
3. Enter an email address (e.g., `user@example.com`) or domain (e.g., `example.com`)
4. Click "Check Authentication"

Results show SPF, DKIM, and DMARC status with detailed analysis.

### Full Email Analysis

Analyze a complete email including headers, links, and attachments:

1. Go to the home page
2. Select "Full Analysis" tab
3. Paste the raw email source (including headers)
4. Click "Analyze Email"

**How to get raw email source:**

- **Gmail**: Open email → Click ⋮ menu → "Show original"
- **Outlook**: Open email → File → Properties → "Internet headers"
- **Apple Mail**: View → Message → Raw Source

### VirusTotal Integration

To enable file and URL scanning via VirusTotal:

1. Get a free API key at [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Go to Settings in ephishchk
3. Enter your API key
4. Select your tier (Free or Premium)

**Rate Limits:**
- Free: 4 requests/minute, 500 requests/day
- Premium: 30 requests/minute, 10,000 requests/day

## Project Structure

```
/
├── public/                     # Web root
│   ├── index.php               # Front controller
│   ├── .htaccess               # Apache rewrite rules
│   └── assets/
│       ├── css/style.css
│       └── js/app.js
├── src/
│   ├── Core/                   # Framework classes
│   │   ├── Application.php
│   │   ├── Database.php
│   │   ├── Router.php
│   │   ├── Request.php
│   │   └── Response.php
│   ├── Controllers/            # Request handlers
│   │   ├── ScanController.php
│   │   ├── HistoryController.php
│   │   └── SettingsController.php
│   ├── Models/                 # Data models
│   │   ├── Scan.php
│   │   ├── ScanResult.php
│   │   └── Setting.php
│   ├── Services/
│   │   ├── Authentication/     # SPF, DKIM, DMARC
│   │   ├── Email/              # Parser, analyzer
│   │   ├── Scanner/            # Link analysis
│   │   ├── VirusTotal/         # API client
│   │   └── ScanOrchestrator.php
│   └── Security/               # CSRF, sanitization
├── templates/                  # View templates
├── config/                     # Configuration files
├── database/
│   ├── migrations/             # SQL schema files
│   └── migrate.php             # Migration runner
├── storage/
│   ├── logs/                   # Application logs
│   ├── cache/                  # DNS cache
│   └── temp/                   # Temporary files
├── composer.json
├── .env.example
├── index.php                   # Root bootstrap
└── install.php                 # Installation wizard
```

## Security Features

- **CSRF Protection**: All forms include CSRF tokens
- **SQL Injection Prevention**: PDO prepared statements throughout
- **XSS Prevention**: Output encoding on all user data
- **Content Security Policy**: Restrictive CSP headers
- **Secure Sessions**: HttpOnly, SameSite cookies
- **Input Sanitization**: All user input is sanitized
- **Encrypted Storage**: Sensitive settings (API keys) are encrypted

## Database Schema

### scans
Stores scan metadata and overall results.

| Column | Type | Description |
|--------|------|-------------|
| id | INT | Primary key |
| scan_type | ENUM | 'quick' or 'full' |
| input_identifier | VARCHAR | Email/domain scanned |
| status | ENUM | pending/processing/completed/failed |
| risk_score | TINYINT | Overall risk 0-100 |
| created_at | TIMESTAMP | Scan start time |
| completed_at | TIMESTAMP | Scan end time |

### scan_results
Stores individual check results.

| Column | Type | Description |
|--------|------|-------------|
| id | INT | Primary key |
| scan_id | INT | Foreign key to scans |
| check_type | VARCHAR | spf/dkim/dmarc/header/links/etc |
| status | ENUM | pass/fail/warning/info/error |
| score | TINYINT | Check score 0-100 |
| summary | VARCHAR | Brief result |
| details | JSON | Full analysis data |

### settings
Application configuration storage.

### rate_limits
VirusTotal API rate limit tracking.

## Troubleshooting

### "Class not found" errors
Run `composer install` to install dependencies.

### Database connection errors
- Verify credentials in `.env`
- Ensure MySQL/MariaDB is running
- Check that the database exists

### Permission errors
Ensure the web server can write to:
- `storage/logs/`
- `storage/cache/`
- `storage/temp/`

```bash
chmod -R 755 storage/
chown -R www-data:www-data storage/
```

### VirusTotal not working
- Verify API key is correct
- Check rate limit status in Settings
- Ensure cURL extension is enabled

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Credits

- [zbateson/mail-mime-parser](https://github.com/zbateson/mail-mime-parser) - Email parsing
- [vlucas/phpdotenv](https://github.com/vlucas/phpdotenv) - Environment configuration
- [VirusTotal API](https://www.virustotal.com/) - Malware scanning
