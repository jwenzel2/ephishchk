-- Migration: Create scans table
-- Date: 2024-01-01

CREATE TABLE IF NOT EXISTS scans (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_type ENUM('quick', 'full') NOT NULL,
    input_identifier VARCHAR(255) NOT NULL COMMENT 'Email address, domain, or filename',
    input_hash CHAR(64) NOT NULL COMMENT 'SHA-256 hash of input for deduplication',
    status ENUM('pending', 'processing', 'completed', 'failed') NOT NULL DEFAULT 'pending',
    risk_score TINYINT UNSIGNED DEFAULT NULL COMMENT 'Overall risk score 0-100',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL DEFAULT NULL,
    ip_address VARCHAR(45) NOT NULL COMMENT 'Client IP address (IPv4 or IPv6)',

    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    INDEX idx_input_hash (input_hash),
    INDEX idx_ip_address (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
