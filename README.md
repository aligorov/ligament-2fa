# twofa

Автономный сервер двухфакторной аутентификации на Go: **RADIUS-сервер для
MikroTik/RouterOS** (L2TP/PPTP/PPPoE/вход в роутер), **REST API** для
интеграции сторонних сервисов и **web-интерфейс** (кабинет пользователя +
админка). Хранение — PostgreSQL.

Поддерживаемые факторы: **email**, **SMS**, **TOTP** (Google Authenticator и
др.), **passkeys** (WebAuthn/FIDO2), **Telegram-push** (подтверждение входа
кнопкой в боте) и **резервные коды**.

Вся конфигурация (SMTP, SMS-шлюз, Telegram-бот, RADIUS-секрет, политика
кодов) хранится в БД и меняется через админку — у процесса ровно одна
переменная окружения: `TWOFA_DB_DSN`.

- Спецификация: [docs/superpowers/specs/2026-09-05-twofa-server-design.md](docs/superpowers/specs/2026-09-05-twofa-server-design.md)
- Обзор библиотек: [docs/research/2026-09-06-library-references.md](docs/research/2026-09-06-library-references.md)
- Заимствованные паттерны: [docs/research/2026-09-06-opensource-borrowed-patterns.md](docs/research/2026-09-06-opensource-borrowed-patterns.md)

## Быстрый старт (Docker)

```sh
cp .env.example .env         # укажите TWOFA_PG_PASSWORD
docker compose up -d
docker compose logs twofa 2>&1 | grep "ADMIN PASSWORD"
```

При **первом** старте на пустой базе создаётся администратор `admin`, его
пароль печатается в лог **один раз** (`ADMIN PASSWORD: ...`) и больше не
показывается. Вход в web-интерфейс: <http://localhost:8080> (логин/пароль →
код не требуется, второй фактор у админа ещё не настроен).

Сразу после первого входа: **/admin → Настройки** задайте `radius.secret`
(или сгенерируйте), SMTP/Telegram и включите TOTP для своей учётки.

## Настройка факторов (/admin → Настройки)

Все ключи — JSON; секретные значения показываются маской, редактируются
точечно. Политики и параметры TOTP применяются на лету; доставка (SMTP,
SMS-шлюз, Telegram) перестраивается по SIGHUP (смена токена Telegram-бота —
перезапуск); `listen.*` и `webauthn.rp_id` — только после рестарта процесса.

**SMTP (email-коды):**

```json
{"host":"smtp.example.com","port":587,"starttls":true,"user":"noreply@example.com","password":"...","from":"noreply@example.com","subject":"Код подтверждения"}
```

**SMS-шлюз** — любой HTTP-шлюз: метод, URL/тело с плейсхолдерами
`{phone}/{text}`, заголовки и правило успеха. Пресеты: `smsc`, `twilio`.

```json
{"preset":"smsc","headers":{"login":"user","psw":"pass"}}
```

```json
{"preset":"twilio","headers":{"sid":"AC...","token":"...","from":"+15550001111"}}
```

Custom-шлюз (JSONPath-правило успеха и т.п. — см. спеку §8):

```json
{"method":"POST","url":"https://sms.example.com/send","content_type":"application/json","headers":{"Authorization":"Bearer ..."},"body":"{\"to\":\"{phone}\",\"text\":\"{text}\"}","success":{"http_status":200,"body_contains":"OK"}}
```

**Telegram** (коды в чат + push-подтверждения): создайте бота у
[@BotFather](https://t.me/BotFather), токен — в ключ `telegram`:

```json
{"bot_token":"123456:AA..."}
```

Пользователь привязывает чат в кабинете (/me → Telegram): сервер выдаёт код
`XXXX-XXXX`, который нужно отправить боту.

**WebAuthn/passkeys:** ключ `webauthn`:

```json
{"rp_id":"2fa.example.com","rp_name":"My 2FA"}
```

`rp_id` — домен, с которого открывается web-UI (localhost для локальных
тестов). Регистрация passkey — в кабинете /me → Passkeys.

## MikroTik (RouterOS)

RADIUS-секрет возьмите в админке (Настройки → radius.secret):

```routeros
/radius add address=<ip-сервера> secret=<radius.secret> service=ppp,login timeout=30s
```

Порты: auth 1812/udp, acct 1813/udp. Ответ Access-Accept несёт
reply-атрибуты: глобальные (`radius.reply_attributes`, напр.
`Mikrotik-Group`) и per-user (поле пользователя в админке).

**ВАЖНО — PAP и «код в пароле».** Нативные L2TP/PPTP-клиенты Windows/macOS
шлют пароль по PAP и не умеют второй фактор отдельным полем. Сервер
принимает код, приклеенный к паролю **одной строкой**: если пароль
`hunter2` и код `123456`, в клиенте вводите `hunter2123456`. Число цифр
кода — 6 или 8 (настройка `radius.code_lengths`).

**Push-режим (без кода).** Пользователю в админке включите `radius_push` и
привяжите Telegram: VPN-подключение выполняется **только с паролем**, а на
телефон приходит запрос — кнопки «Подтвердить»/«Это не я» в боте. Сервер
удерживает RADIUS-запрос до `radius.push_wait` (по умолчанию 20 с) —
ставьте на роутере `timeout=30s` и больше.

## REST API

Публичное API (JSON, без сессий — для интеграций):

```sh
# Шаг 1: пароль → челлендж (код уходит по prefer-каналу пользователя)
curl -s localhost:8080/api/v1/auth/start -d '{"username":"user1","password":"hunter2"}'
# → {"challenge_id":"...","channel":"email","expires_in":300}

# Шаг 2: код
curl -s localhost:8080/api/v1/auth/verify -d '{"challenge_id":"...","code":"123456"}'

# Комбинированный вход одним вызовом (код — доставленный, TOTP или резервный)
curl -s localhost:8080/api/v1/auth/combined -d '{"username":"user1","password":"hunter2","code":"123456"}'

# Статус push-челленджа (poll, пока status=pending)
curl -s localhost:8080/api/v1/auth/poll -d '{"challenge_id":"..."}'

# WebAuthn-вход: begin (после пароля) → клиент подписывает → finish
curl -s localhost:8080/api/v1/auth/webauthn/begin -d '{"username":"user1","password":"hunter2"}'
curl -s "localhost:8080/api/v1/auth/webauthn/finish?handle=..." -d @credential.json
```

Web-сессии: `POST /api/v1/login` → `{"two_factor":"required"}` →
`POST /api/v1/login/2fa` (или `POST /api/v1/auth/webauthn/finish` + пустой
код) — cookie `twofa_session` + CSRF-токен; кабинет `/api/v1/me/*` (TOTP
enroll/confirm, passkeys, Telegram, устройства), админ `/api/v1/admin/*` по
`Authorization: Bearer <admin_token>` (токен в админке, Настройки).
Полный список — спека §7.

Ошибки: 401 `bad_credentials`/`bad_code` (с `attempts_left`), 410 `expired`,
423 `locked` (fail-лок), 429 `rate_limited`/`cooldown`, 409 `no_channel`.

## Безопасность

- Пароли — **argon2id**; TOTP-секреты — AES-256-**GCM** с AAD-привязкой к
  username (секрет, украденный из БД, не расшифровывается без master_key и
  не переносится на другого пользователя).
- Все события (входы, коды, изменения) — в `audit_log`; единый per-user
  fail-счётчик: **5 неудач / 5 минут → блок 15 минут**.
- Челленджи одноразовые (атомарный claim), коды — SHA-256 в БД, TOTP —
  replay-защита по счётчику окна.
- RADIUS: **Message-Authenticator реализован** (RFC 3579) — ответы подписаны,
  митигация BlastRADIUS; шифрование пароля PAP стандартное.
- Rate-limit: публичный API ~10 start/мин по username и по IP; веб-логин —
  аналогично; push — cooldown 30 с и не более 10/час.

## Ограничения v1

- **RP ID и passkeys**: ключи привязаны к домену (`webauthn.rp_id`) — смена
  домена ломает зарегистрированные passkeys (потребуется повторная
  регистрация).
- **LDAP / внешние каталоги пользователей** — в будущих версиях (спека §12).
- Смена `listen.*` требует рестарта процесса.

## Сборка и разработка

```sh
make build   # go build -o twofa ./cmd/twofa
make test    # юнит-тесты
make lint    # go vet
make docker  # docker build -t twofa:latest .
make e2e     # E2E-сценарий (Docker): testcontainer PG + HTTP + RADIUS
```

Структура репозитория:

```
cmd/twofa/       композиция и запуск (main)
internal/api/    REST API + web-страницы (chi)
internal/auth/   ядро аутентификации (челленджи, сплиты, TOTP)
internal/radiusserver/  RADIUS auth/acct (layeh.com/radius)
internal/store/  PostgreSQL (pgx) — пользователи, челленджи, аудит...
internal/settings/ конфигурация в БД (defaults, hot-reload)
internal/delivery/ email/SMS-отправка (пресеты smsc/twilio)
internal/telegram/ бот: коды, push-подтверждения, привязка
internal/webauthn/ passkeys (go-webauthn)
internal/secrets/ argon2id, AES-GCM+AAD, генерация кодов
internal/web/    HTML-шаблоны и статика
internal/e2e/    сквозной сценарий (build tag integration)
migrations/      SQL-миграции (embedded в бинарник)
deploy/          systemd unit
```

Системный деплой без Docker: `deploy/twofa.service` (см. комментарии в
файле).
