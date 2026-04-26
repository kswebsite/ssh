-- Coupons Table
CREATE TABLE IF NOT EXISTS coupons (
    id TEXT PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    reward INTEGER NOT NULL,
    max_uses INTEGER DEFAULT 1,
    current_uses INTEGER DEFAULT 0,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Coupon Usage tracking
CREATE TABLE IF NOT EXISTS coupon_usage (
    coupon_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (coupon_id, user_id),
    FOREIGN KEY (coupon_id) REFERENCES coupons(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Global Config Table
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Initial Config
INSERT OR IGNORE INTO config (key, value) VALUES ('afk_rate', '10'); -- credits per hour
INSERT OR IGNORE INTO config (key, value) VALUES ('afk_max_hours', '24');
INSERT OR IGNORE INTO config (key, value) VALUES ('video_reward', '5');
INSERT OR IGNORE INTO config (key, value) VALUES ('video_cooldown_hours', '24');
INSERT OR IGNORE INTO config (key, value) VALUES ('video_daily_max', '50');

-- User Earnings Stats (for daily limits)
CREATE TABLE IF NOT EXISTS user_stats (
    user_id INTEGER PRIMARY KEY,
    daily_video_earnings INTEGER DEFAULT 0,
    last_video_claim DATETIME,
    last_reset DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Video Logs
CREATE TABLE IF NOT EXISTS video_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    earned INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
