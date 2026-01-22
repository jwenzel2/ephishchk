-- Migration: Create settings table
-- Date: 2024-01-01

CREATE TABLE IF NOT EXISTS settings (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT DEFAULT NULL,
    setting_type ENUM('string', 'integer', 'boolean', 'json') NOT NULL DEFAULT 'string',
    is_encrypted TINYINT(1) NOT NULL DEFAULT 0,
    description VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE INDEX idx_setting_key (setting_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default settings
INSERT INTO settings (setting_key, setting_value, setting_type, is_encrypted, description) VALUES
('virustotal_api_key', NULL, 'string', 1, 'VirusTotal API key for file/URL scanning'),
('virustotal_tier', 'free', 'string', 0, 'VirusTotal API tier (free or premium)'),
('scan_retention_days', '30', 'integer', 0, 'Number of days to retain scan history'),
('max_links_per_scan', '50', 'integer', 0, 'Maximum number of links to analyze per email'),
('enable_vt_file_scan', '1', 'boolean', 0, 'Enable VirusTotal file scanning for attachments'),
('enable_vt_url_scan', '1', 'boolean', 0, 'Enable VirusTotal URL scanning for links')
ON DUPLICATE KEY UPDATE setting_key = setting_key;
