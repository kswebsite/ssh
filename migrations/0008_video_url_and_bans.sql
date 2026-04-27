-- Add URL to videos and is_banned to users
ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0;

-- Fix videos table: Make video_id nullable by recreating it (SQLite limitation for ALTER COLUMN)
CREATE TABLE videos_new (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    video_id TEXT, -- Made nullable
    url TEXT,
    reward INTEGER NOT NULL,
    duration_seconds INTEGER NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO videos_new (id, title, video_id, reward, duration_seconds, is_active, created_at)
SELECT id, title, video_id, reward, duration_seconds, is_active, created_at FROM videos;

DROP TABLE videos;
ALTER TABLE videos_new RENAME TO videos;

-- Update existing videos to have a YouTube URL if they have a video_id
UPDATE videos SET url = 'https://www.youtube.com/watch?v=' || video_id WHERE video_id IS NOT NULL AND url IS NULL;
