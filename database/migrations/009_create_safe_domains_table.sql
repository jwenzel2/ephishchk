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

-- Pre-populate with common legitimate domains that are frequently targeted by typosquatting
INSERT INTO safe_domains (domain, added_by_user_id, added_by_username, notes) VALUES
    ('google.com', 1, 'admin', 'Pre-populated: Major search engine and tech company'),
    ('microsoft.com', 1, 'admin', 'Pre-populated: Major software company'),
    ('apple.com', 1, 'admin', 'Pre-populated: Major tech company'),
    ('amazon.com', 1, 'admin', 'Pre-populated: Major e-commerce platform'),
    ('paypal.com', 1, 'admin', 'Pre-populated: Payment processing service'),
    ('facebook.com', 1, 'admin', 'Pre-populated: Social media platform'),
    ('linkedin.com', 1, 'admin', 'Pre-populated: Professional networking platform'),
    ('twitter.com', 1, 'admin', 'Pre-populated: Social media platform'),
    ('instagram.com', 1, 'admin', 'Pre-populated: Social media platform'),
    ('netflix.com', 1, 'admin', 'Pre-populated: Streaming service'),
    ('dropbox.com', 1, 'admin', 'Pre-populated: Cloud storage service'),
    ('github.com', 1, 'admin', 'Pre-populated: Software development platform'),
    ('yahoo.com', 1, 'admin', 'Pre-populated: Web services provider'),
    ('ebay.com', 1, 'admin', 'Pre-populated: E-commerce platform'),
    ('wells-fargo.com', 1, 'admin', 'Pre-populated: Banking institution'),
    ('chase.com', 1, 'admin', 'Pre-populated: Banking institution'),
    ('bankofamerica.com', 1, 'admin', 'Pre-populated: Banking institution');
