-- Migration: Add user_id to scans table
-- Date: 2024-01-01

ALTER TABLE scans
ADD COLUMN user_id INT UNSIGNED NULL AFTER id,
ADD INDEX idx_user_id (user_id),
ADD CONSTRAINT fk_scans_user_id
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE SET NULL;
