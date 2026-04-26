-- Videos Table
CREATE TABLE IF NOT EXISTS videos (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    video_id TEXT NOT NULL, -- YouTube ID
    reward INTEGER NOT NULL,
    duration_seconds INTEGER NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Seed an initial video
INSERT OR IGNORE INTO videos (id, title, video_id, reward, duration_seconds)
VALUES ('initial-video', 'Welcome to KS SSH', 'dQw4w9WgXcQ', 10, 30);
