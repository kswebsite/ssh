-- Migration to add granular terminal permissions
ALTER TABLE workspace_members ADD COLUMN terminal_access_type TEXT DEFAULT 'all';

CREATE TABLE IF NOT EXISTS member_terminal_access (
  workspace_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  terminal_id TEXT NOT NULL,
  PRIMARY KEY (workspace_id, user_id, terminal_id),
  FOREIGN KEY (workspace_id, user_id) REFERENCES workspace_members(workspace_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (terminal_id) REFERENCES terminals(id) ON DELETE CASCADE
);
