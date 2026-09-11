-- 0013_support_fsm_hardening: серверная машина состояний support_sessions.
-- Аудит «обращения» (удалённая помощь): строгая последовательность действий,
-- одна живая сессия на пользователя, счётчик попыток number-match.

-- 1. Одна живая сессия на пользователя (partial unique index). Перед
-- накатом гасим исторические дубликаты: живой остаётся самый свежий
-- обращение, остальные переводятся в cancelled.
UPDATE support_sessions s
SET status = 'cancelled',
    ended_at = now(),
    updated_at = now()
WHERE s.status IN ('requested', 'connecting', 'authorizing', 'approved', 'active', 'transferred')
  AND EXISTS (
      SELECT 1 FROM support_sessions s2
      WHERE s2.user_id = s.user_id
        AND s2.id <> s.id
        AND s2.status IN ('requested', 'connecting', 'authorizing', 'approved', 'active', 'transferred')
        AND s2.created_at > s.created_at
  );

CREATE UNIQUE INDEX IF NOT EXISTS support_sessions_one_live_per_user
    ON support_sessions (user_id)
    WHERE status IN ('requested', 'connecting', 'authorizing', 'approved', 'active', 'transferred');

-- 2. Счётчик неудачных попыток ввода контрольного числа number-match:
-- после 3 несовпадений сессия гасится (защита от перебора 2-значного кода).
ALTER TABLE support_sessions
    ADD COLUMN IF NOT EXISTS nm_attempts INT NOT NULL DEFAULT 0;
