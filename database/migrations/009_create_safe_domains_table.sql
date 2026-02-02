-- Migration: Create safe_domains table for typosquatting detection
-- This table stores trusted domains that will be used to detect potential typosquatting attempts

CREATE TABLE IF NOT EXISTS safe_domains (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    added_by_user_id INT UNSIGNED NOT NULL,
    added_by_username VARCHAR(50) NOT NULL DEFAULT 'System',
    notes TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_domain (domain),
    INDEX idx_added_by (added_by_user_id),
    INDEX idx_added_by_username (added_by_username),

    CONSTRAINT fk_safe_domains_user
        FOREIGN KEY (added_by_user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Note: Pre-populated domains are added by the installer after admin user creation
