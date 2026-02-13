-- Migration: Create malicious_domains table for known malicious domain tracking
-- This table stores domains known to be malicious. Any match during scanning
-- automatically flags the email as a confirmed phish with maximum risk score (100).

CREATE TABLE IF NOT EXISTS malicious_domains (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    added_by_user_id INT UNSIGNED NOT NULL,
    added_by_username VARCHAR(50) NOT NULL DEFAULT 'System',
    notes TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_domain (domain),
    INDEX idx_added_by (added_by_user_id),
    INDEX idx_added_by_username (added_by_username),

    CONSTRAINT fk_malicious_domains_user
        FOREIGN KEY (added_by_user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
