-- 0015_ldap_locked: флаг блокировки или отключения учётной записи в Active Directory / LDAP.
-- Позволяет администраторам мгновенно видеть заблокированных в домене пользователей,
-- фильтровать их и автоматически отзывать доступ.

ALTER TABLE users ADD COLUMN IF NOT EXISTS ldap_locked BOOL NOT NULL DEFAULT false;
