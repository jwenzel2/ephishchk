-- Migration: Create rate_limits table
-- Date: 2024-01-01

CREATE TABLE IF NOT EXISTS rate_limits (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    api_name VARCHAR(50) NOT NULL,
    window_type ENUM('minute', 'day') NOT NULL,
    request_count INT UNSIGNED NOT NULL DEFAULT 0,
    window_start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE INDEX idx_api_window (api_name, window_type),
    INDEX idx_window_start (window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Initialize VirusTotal rate limit counters
INSERT INTO rate_limits (api_name, window_type, request_count, window_start) VALUES
('virustotal', 'minute', 0, CURRENT_TIMESTAMP),
('virustotal', 'day', 0, CURRENT_TIMESTAMP)
ON DUPLICATE KEY UPDATE api_name = api_name;
