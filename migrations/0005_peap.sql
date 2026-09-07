-- 0005_peap: пароль, зашифрованный AES-256-GCM под master_key с AAD username.
-- Необходим для аутентификации MS-CHAPv2 (PEAPv0) на iPhone/iPad/Windows,
-- где клиент проверяет challenge-response на базе NT-Hash без отправки открытого пароля.
-- В открытом виде пароль в БД не хранится (защищен аналогично totp_secrets).

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_enc BYTEA;
