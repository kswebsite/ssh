CREATE TABLE IF NOT EXISTS usage_logs (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    terminal_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL, -- 'terminal_usage'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (terminal_id) REFERENCES terminals(id)
);
