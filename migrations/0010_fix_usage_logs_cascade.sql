-- Recreate usage_logs with ON DELETE CASCADE for terminal_id
CREATE TABLE IF NOT EXISTS usage_logs_new (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    terminal_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL, -- 'terminal_usage'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (terminal_id) REFERENCES terminals(id) ON DELETE CASCADE
);

INSERT INTO usage_logs_new SELECT * FROM usage_logs;
DROP TABLE usage_logs;
ALTER TABLE usage_logs_new RENAME TO usage_logs;
