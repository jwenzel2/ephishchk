-- Migration: Switch from email-based to username-based authentication
-- Date: 2026-01-30

-- Step 1: Add username column to users table (nullable initially)
ALTER TABLE users
ADD COLUMN username VARCHAR(50) NULL
AFTER email;

-- Step 2: Migrate display_name to username for existing users
-- If display_name is null or empty, use email prefix as username
UPDATE users
SET username = COALESCE(
    NULLIF(TRIM(display_name), ''),
    SUBSTRING_INDEX(email, '@', 1)
)
WHERE username IS NULL;

-- Step 3: Ensure all usernames are unique by appending numbers to duplicates
-- This handles edge cases where multiple users might have the same display_name
SET @row_number = 0;
UPDATE users u1
JOIN (
    SELECT
        id,
        username,
        @row_number := IF(@current_username = username, @row_number + 1, 0) AS row_num,
        @current_username := username
    FROM users
    ORDER BY username, id
) u2 ON u1.id = u2.id
SET u1.username = IF(u2.row_num > 0, CONCAT(u1.username, u2.row_num), u1.username)
WHERE u2.row_num > 0;

-- Step 4: Make username NOT NULL and add UNIQUE constraint
ALTER TABLE users
MODIFY COLUMN username VARCHAR(50) NOT NULL;

ALTER TABLE users
ADD CONSTRAINT uk_users_username UNIQUE (username);

-- Step 5: Add index on username for performance
CREATE INDEX idx_username ON users(username);

-- Step 6: Update safe_domains usernames to match current user data
-- Note: added_by_username column already exists from migration 009
UPDATE safe_domains sd
LEFT JOIN users u ON sd.added_by_user_id = u.id
SET sd.added_by_username = COALESCE(u.username, 'System')
WHERE u.username IS NOT NULL OR sd.added_by_username = 'admin';

-- Migration complete!
-- Notes:
-- - Users now log in with username instead of email
-- - Email can be changed in preferences
-- - Username cannot be changed after registration
-- - Safe domains show username instead of email in "added by" column
-- - Duplicate usernames were automatically resolved by appending numbers
