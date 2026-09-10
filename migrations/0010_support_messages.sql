-- 0010_support_messages: хранение истории сообщений чата удаленной поддержки
CREATE TABLE IF NOT EXISTS support_messages (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id  UUID NOT NULL REFERENCES support_sessions(id) ON DELETE CASCADE,
    sender      TEXT NOT NULL, -- 'user' | 'operator'
    sender_name TEXT NOT NULL DEFAULT '',
    text        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS support_messages_session_idx ON support_messages(session_id, created_at ASC);
