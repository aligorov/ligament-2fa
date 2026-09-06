-- 0002_ldap: источник учётной записи и отображаемое имя — бэкенд
-- LDAP/Active Directory (T-ldap). source: 'local' (локальный argon2id-хеш)
-- или 'ldap' (пароль проверяется bind-ом в каталоге, строка создаётся
-- авто-провижинингом при первом входе). display_name синхронизируется из
-- атрибута каталога (displayName по умолчанию) и показывается в web-UI.

ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
