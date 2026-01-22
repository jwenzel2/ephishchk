-- Migration: Add role column to users table
-- Date: 2024-01-01

ALTER TABLE users
ADD COLUMN role ENUM('user', 'admin') NOT NULL DEFAULT 'user' AFTER is_active,
ADD INDEX idx_role (role);
