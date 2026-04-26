-- Rename video_logs to earnings_logs and add type
ALTER TABLE video_logs RENAME TO earnings_logs;
ALTER TABLE earnings_logs ADD COLUMN type TEXT DEFAULT 'video';

-- Ensure ksssh is admin
UPDATE users SET is_admin = 1 WHERE username = 'ksssh';
