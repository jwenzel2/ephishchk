-- Migration: Add HTTPS requirement setting
-- Date: 2026-01-31

-- Insert require_https setting
INSERT INTO settings (setting_key, setting_value, setting_type, is_encrypted, description) VALUES
('require_https', '0', 'boolean', 0, 'Redirect all HTTP requests to HTTPS (requires SSL certificate)')
ON DUPLICATE KEY UPDATE setting_key = setting_key;
