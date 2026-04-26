-- Add is_admin column to users
ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0;

-- Set specific user as admin
UPDATE users SET is_admin = 1 WHERE email = 'ksssh@ksmail.io';
