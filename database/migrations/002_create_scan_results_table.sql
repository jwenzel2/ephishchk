-- Migration: Create scan_results table
-- Date: 2024-01-01

CREATE TABLE IF NOT EXISTS scan_results (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id INT UNSIGNED NOT NULL,
    check_type VARCHAR(50) NOT NULL COMMENT 'spf, dkim, dmarc, header, link, attachment',
    status ENUM('pass', 'fail', 'warning', 'info', 'error') NOT NULL,
    score TINYINT UNSIGNED DEFAULT NULL COMMENT 'Individual check score 0-100',
    summary VARCHAR(255) NOT NULL COMMENT 'Brief result summary',
    details JSON DEFAULT NULL COMMENT 'Detailed findings in JSON format',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    INDEX idx_scan_id (scan_id),
    INDEX idx_check_type (check_type),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
