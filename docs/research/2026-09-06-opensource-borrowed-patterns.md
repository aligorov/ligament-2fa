# Заимствованные паттерны из opensource (исследование 2026-09-06)

Основа дизайна twofa — проверенные решения Authelia (Go), Casdoor (Go) и
privacyIDEA (Python). Ниже — что именно заимствуем (полные отчёты агентов —
в истории сессии; здесь рабочая выжимка для исполнителей).

## Из Authelia (github.com/authelia/authelia)

1. **Схема TOTP**: отдельная таблица с `username UNIQUE, issuer, algorithm,
   digits, period, secret BYTEA (зашифрован), created_at, last_used_at`;
   replay-защита через историю принятых step. Мы: `totp_secrets` +
   `last_timestep` (достаточно при последовательных логинах одного юзера).
2. **Плоские колонки webauthn_credentials** (НЕ JSON-блоб): kid/rpid/
   sign_count/clone_warning/aaguid/attestation_*/attachment/transports/
   flags(present,verified,backup_eligible,backup_state)/public_key —
   реконструкция `webauthn.Credential` в `ToCredential()`. **Принято в схему.**
3. **Обновление SignCount/CloneWarning после каждого логина** — иначе
   сломается следующий вход. **Принято** (WACredUpdateSignIn).
4. **AAD-привязанное шифрование**: AES-GCM, AAD = `twofa:storage:<table>:
   <username>` — шифротекст не переносим между строками. **Принято** (Box.EncryptAAD).
5. **Regulation (анти-брутфорс)**: счёт неуспехов по логу + временнáя
   блокировка (у них 3/2мин/5мин). **Принято через audit_log** (см. privacyIDEA).
6. **Сессии**: регенерация ID после повышения привилегий; Secure+SameSite=Lax;
   сенситив-действия — через одноразовый код, не через CSRF-токен. Частично
   принято (у нас CSRF-токен в формах остаётся, коды для sensitive уже есть).
7. **Миграции**: go:embed, имя `V%04d.Name.up.sql`, таблица версий с
   application_version. Упрощено: 0001_init.sql + schema_migrations.

## Из Casdoor (github.com/casdoor/casdoor)

1. **Единый счётчик неудач для пароля И кода**: per-user `wrong_times` +
   last_wrong_time, лимит 5, заморозка 15 мин, сброс при успехе. **Принято
   (через audit_log, без колонок): policy.max_fail/fail_window/ban_time.**
2. **VerificationRecord** как единая таблица одноразовых кодов: dest-индекс,
   crypto/rand 6 цифр, IsUsed, timeout, 60s resend-throttle, RemoteAddr.
   Наш `challenges` покрывает это (+ channel, push_state, purpose).
3. **MFA-интерфейс Initiate/SetupVerify/Enable/Verify** на канал + фабрика.
   Наш эквивалент: Channel + delivery.Sender + auth.Core; энроллмент
   TOTP «покажи QR → код → confirm» = их stateless verify→enable. Совпадает.
4. **RADIUS Access-Challenge (двухпакетный)**: пароль в #1 → Challenge+State
   (120 c, single-use) → OTP в #2. Для challenge-способных NAS. **Отложено в
   v2** (нативные MikroTik VPN-клиенты не поддерживают). У них же — баги
   для избежания: missing return после Challenge, только-TOTP в challenge-пути.
5. **Кастомный HTTP-SMS-провайдер**: плейсхолдеры, headers, body-mapping —
   наш sms.gateway эквивалентен. Их библиотека go-sms-sender (19 провайдеров)
   — опция на будущее, не тащим в v1.
6. **RadiusAccounting-таблица** (Start/Interim/Stop сессии NAS) — v2; у нас
   acct логируется.

## Из privacyIDEA (github.com/privacyidea/privacyidea)

1. **push_wait — серверное удержание RADIUS-запроса**: блокируем
   Access-Request, опрашиваем challenge раз в 1 c до таймаута (~20 c),
   отвечаем Accept/Reject одним пакетом; NAS timeout > push_wait.
   **Принято вместо «Reject → переподключение».**
2. **Семантика сплита**: никакой магии разделителей — глобальный флаг
   prepend/append + длина кода; перебор длины кода у нас покрывает то же
   (коды 6/8), дешёвая проверка кода до argon2. Подтверждает наш подход.
3. **challenge-таблица**: transaction_id 20 случайных цифр, received_count,
   otp_valid, lazy-janitor (чистка истёкших при каждом касании), отмена всей
   транзакции при успехе. **Lazy-janitor принят** (чистка в ChallengeCreate).
4. **auth_max_fail по audit-логу**: аудит = источник для rate-limit —
   «одна таблица, три работы». **Принято** (регламент Authelia + это = одно
   решение: считаем неуспехи из audit_log).
5. **otppin = tokenpin|userstore|none**: где живёт первый фактор. Наш
   PasswordVerifier (+LDAP позже) — тот же паттерн.
6. **BlastRADIUS (CVE-2024-3596)**: эхо Message-Authenticator; layeh/radius
   заморожен — проверить при реализации, иначе README-заметка/форк maddsua.

## Сводка изменений против прежней версии спеки/плана

- RADIUS push: reject-режим → **push_wait удержание** (radius.push_wait 20s).
- webauthn_credentials: JSON-блоб → **плоские колонки**.
- secrets: + **EncryptAAD/DecryptAAD**.
- Анти-брутфорс: разрозненные механизмы → **единый счётчик по audit_log**
  (policy.max_fail=5, fail_window=5m, ban_time=15m), проверка перед
  проверкой пароля/кода и в RADIUS.
- v2-бэклог: Access-Challenge двухпакетный, RadiusAccounting-таблица,
  go-sms-sender, ротация мастер-ключа.
