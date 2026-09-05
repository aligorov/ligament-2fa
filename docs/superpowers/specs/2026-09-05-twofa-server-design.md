# Дизайн: `twofa` — сервер двухфакторной аутентификации (email / SMS / TOTP)

Дата: 2026-09-05
Статус: согласован с пользователем (устно), ожидает ревью спеки
Проект: standalone-репозиторий `2fa/` (не подпроект routeros-aligorov)

## 1. Цель

Универсальный шлюз двухфакторной аутентификации:

- **RADIUS** — аутентификация VPN и сетевого оборудования (MikroTik RouterOS и
  любое другое, говорящее по RADIUS);
- **REST API** — подключение собственных приложений.

Второй фактор — три канала:

- **Email** — одноразовый код по SMTP;
- **SMS** — одноразовый код через настраиваемый HTTP-шлюз (любой провайдер);
- **TOTP** — RFC 6238 (Google Authenticator и совместимые) + резервные коды.

Стек: **Go**, монолит (один бинарник), хранилище **PostgreSQL**, web-интерфейс
на серверных шаблонах, встроенный в бинарник.

### Не-цели (v1)

- LDAP/AD-бэкенд паролей — архитектурно заложен интерфейс `PasswordVerifier`,
  реализация позже;
- WebAuthn / push-уведомления;
- MS-CHAPv2 / EAP в RADIUS (несовместимы с проверкой одноразового кода;
  используется PAP);
- HA/репликация, мульти-тенантность;
- RADIUS Accounting — пакеты на :1813 принимаются и только логируются;
- i18n web-UI — интерфейс на русском.

## 2. Архитектура

Один процесс `twofa`, три слушателя:

| Слушатель | Назначение |
|---|---|
| UDP :1812 | RADIUS Access-Request (PAP) |
| UDP :1813 | RADIUS Accounting (только лог) |
| TCP :8080 | HTTP: REST API + web-UI (`/login`, `/admin`, `/me`) + метрики `/healthz` |

Единственная внешняя зависимость — PostgreSQL. **Вся конфигурация хранится
в самой БД** (таблица `settings`, редактируется через админку/API).
Переменная окружения ровно одна — `TWOFA_DB_DSN` (строка подключения);
то же самое можно передать флагом `-dsn`.

```
                 ┌────────────────────────────────────────────┐
 MikroTik VPN ──▶│ RADIUS :1812/udp                           │
 оборудование   │   └─ PAP «пароль+код»                       │
                 │                                            │    ┌────────────┐
 Приложения ────▶│ REST /api/v1/auth/* ──┐                    │───▶│ PostgreSQL │
                 │                       ├─ AuthCore ──▶ Delivery ──▶ SMTP /    │
 Браузер ───────▶│ Web-UI /admin /me ────┘   (challenges,     │    HTTP-SMS │
                 │                            TOTP, хеши)     │    шлюзы    │
                 └────────────────────────────────────────────┘    └────────────┘
```

### 2.1 Слой паролей (расширение под LDAP)

Интерфейс `PasswordVerifier.Verify(ctx, username, password) (User, error)`:
v1 — единственная реализация `LocalVerifier` (argon2id по таблице `users`).
LDAP-реализация добавляется позже без изменения AuthCore.

## 3. Флоу аутентификации

### 3.1 RADIUS (режим «код приклеен к паролю»)

Нативные VPN-клиенты не поддерживают RADIUS Access-Challenge, поэтому
пользователь вводит в поле пароля VPN-клиента `пароль + код` одной строкой.

Парсер Access-Request:

1. Прочитать `User-Name` и `User-Password` (PAP, секрет RADIUS-shared-secret).
2. Для каждой длины кода `L` из настроек `radius.code_lengths: [6, 8]`
   (перебор по порядку): разбить строку на `pass = s[:len-L]`, `code = s[len-L:]`.
3. Для каждого разбиения **сначала дёшево проверить код**: TOTP пользователя,
   затем активные challenge-коды (email/SMS, запрошенные заранее), затем
   резервные коды. Криптография кодов дешёвая — перебор вариантов допустим.
4. Для разбиения с подошедшим кодом — один вызов argon2id-проверки пароля.
5. Совпало и то и другое → Access-Accept (+ reply-атрибуты, см. 3.4);
   иначе → Access-Reject. Всё — в аудит.

Коды email/SMS для RADIUS-подключения запрашиваются заранее: в кабинете `/me`
кнопкой «Отправить код» или через `POST /api/v1/auth/start` (приложением).
TOTP-коду предварительный запрос не нужен.

Троттлинг: не более `radius.max_fail_per_user` неуспешных Access-Request на
пользователя в окно `radius.fail_window` (по умолчанию 10 / 5 мин), иначе
Reject без проверки.

### 3.2 REST API (приложения)

Двухшаговый флоу:

```
POST /api/v1/auth/start    {username, password}
  → 200 {challenge_id, channel, expires_in}   # код отправлен пользователю
                                                # (channel=totp — код не отправляется,
                                                #  пользователь берёт его из приложения)
  → 401 (плохой пароль / пользователь выключен)
  → 409 no_channel (нет ни одного привязанного канала доставки)
  → 429 (троттлинг; Retry-After)

POST /api/v1/auth/verify   {challenge_id, code}
  → 200 {ok: true, username}
  → 401 {ok: false, attempts_left}            # неверный код
  → 410                                      # истёк / израсходован
```

Комбинированный (одним вызовом, для простых клиентов):

```
POST /api/v1/auth/combined  {username, password, code}
  → 200 {ok: true, username} | 401
```

Выбор канала доставки в `start`: политика пользователя — порядок приоритета
каналов (например `["totp-or-email"]`; точнее: `prefer: [totp, email, sms]`,
берётся первый привязанный и разрешённый). В ответе `channel` сообщает
приложению, куда ушёл код (чтобы показать подсказку), но не адрес.

TOTP в REST-флоу: `start` не высылает код — возвращает
`{challenge_id, channel: "totp"}`; `verify` проверяет код против TOTP-секрета
в окне ±1 шаг. Резервные коды принимаются наравне.

### 3.3 Web-интерфейс

- `/login` — логин+пароль → session-cookie. Пользователь с ролью `admin`
  попадает в `/admin`, обычный — в `/me`. **Вход в сам web-UI без 2FA**
  (кабинет защищён первым фактором; 2FA-код требуется на sensitive-действия:
  смена email/телефона, подтверждение TOTP, регенерация резервных кодов —
  поле «код из приложения/SMS» прямо в форме).
- `/admin` — таблица пользователей (создать/редактировать/вкл-выкл, сбросить
  TOTP, политика каналов), аудит-лог, список активных challenge,
  **страница «Настройки»** (SMTP, SMS-шлюз, TOTP, политики, порты,
  `admin_token`; секреты показаны маской, смена — вводом нового значения).
- `/me` — профиль: email/телефон (смена с кодом подтверждения на старый
  канал), привязка TOTP: показать QR (otpauth://) → ввести код → подтверждено;
  резервные коды (показ один раз при регенерации); «отправить тестовый код».

### 3.4 RADIUS reply-атрибуты

Глобальный список пар `имя: значение` в настройках БД
(`radius.reply_attributes`, например `Framed-IP-Address`, MikroTik
vendor-атрибуты), применяется ко всем Access-Accept. Per-user override:
колонка `radius_reply` (JSON) у пользователя заменяет глобальный список.

## 4. Каналы доставки

| Канал | Механизм | Ключи настроек в БД |
|---|---|---|
| Email | SMTP, STARTTLS/TLS, логин/пароль; письмо из шаблона | `smtp.*` |
| SMS | Универсальный HTTP-шлюз: метод, URL-шаблон с `{phone}` `{text}`, заголовки, тело-шаблон, Success-критерий (HTTP-код / подстрока / JSON-path) | `sms.gateway.*` + именованные пресеты `sms.presets.*` |
| TOTP | RFC 6238, SHA-1, 6 цифр, 30 с, окно ±1; секрет 20 байт base32 | `totp:` |

Пресеты в комплекте: `smsc`, `twilio`. Выбор пресета: `sms.gateway.preset: smsc`
(значения-переменные пресета перекрываются полями `sms.gateway`).

Лимиты кода: длина 6 цифр, генерация crypto/rand; TTL 5 мин; максимум
5 попыток; повторная отправка не раньше чем через 60 с; код одноразовый
(помечается использованным при успехе). Все значения — в настройках
`policy.*` с безопасными дефолтами.

## 5. Модель данных (PostgreSQL)

| Таблица | Ключевые поля |
|---|---|
| `users` | id UUID PK, username UNIQUE, password_hash (argon2id), role (`admin`\|`user`), enabled bool, email, phone, prefer_channels JSONB (`["totp","email"]`), radius_reply JSONB NULL, created_at, updated_at |
| `totp_secrets` | user_id PK/FK, secret_enc BLOB (AES-GCM), digits, period, confirmed_at NULL, drift_step INT |
| `backup_codes` | id, user_id FK, code_hash SHA-256 UNIQUE, used_at NULL |
| `challenges` | id UUID PK, user_id FK, channel, code_hash SHA-256 **NULL для channel=totp** (код не хранится, проверяется против TOTP-секрета), expires_at, attempts_left, used_at NULL, purpose (`api`\|`radius_prefetch`\|`ui_confirm`), created_at |
| `sessions` | token_hash PK, user_id FK, csrf, expires_at, created_at |
| `settings` | key TEXT PK, value JSONB — **вся конфигурация сервера** (см. §8); секретные ключи помечены и маскируются в API/UI |
| `audit_log` | id BIGSERIAL, ts, username, event (`login_ok`, `login_fail`, `code_sent`, `code_ok`, `code_fail`, `totp_enroll`, `admin_action`, …), detail JSONB, src_ip, result |

Индексы: `challenges(user_id, expires_at)`, `audit_log(ts)`,
`audit_log(username, ts)`.

Коды и сессии хранятся **хешами** — компромисс БД не раскрывает действующие
коды. TOTP-секреты шифруются AES-GCM мастер-ключом (см. §6).
Строка подключения к БД (`TWOFA_DB_DSN`) — единственная настройка вне БД:
без неё сервер не найдёт саму базу. Всё остальное живёт в `settings`.

## 6. Безопасность

- Пароли: argon2id (m=64 МБ, t=1, p=4 — фиксируется в коде, параметры в хеше).
- TOTP-секреты: AES-256-GCM. Мастер-ключ 32 байта генерируется при первом
  старте и хранится в `settings` (ключ `master_key`). Компромисс осознан:
  ключ лежит рядом с данными, шифрование защищает от частичных утечек
  (дамп отдельных таблиц/колонок), полная защита — доступ к БД (см. §12).
- Секретные настройки (`smtp.password`, SMS-токены, `radius.secret`,
  `admin_token`) хранятся в `settings` в открытом виде (граница доверия —
  доступ к БД), но **никогда не возвращаются** API/UI — только маска
  `••••` и флаг «задано»; запись — только через PUT.
- Резервные коды: 10 шт., формат `XXXXX-XXXXX` (алфавит без 0/O/1/I),
  хранятся SHA-256, показываются один раз.
- Сессии web-UI: cookie `twofa_session` (HttpOnly, Secure, SameSite=Lax),
  в БД хеш токена; CSRF-токен для форм; TTL 12 ч.
- Троттлинг: `/auth/start` — per-username и per-IP token bucket;
  RADIUS — окно отказов (§3.1); `/auth/verify` — счётчик попыток challenge.
- Аудит всех событий аутентификации и админ-действий, ответ на bad-credentials
  единообразен по времени (фиксированная задержка при отсутствии пользователя).
- Экспорт метрик не входит в v1; `/healthz` — проверка БД.

## 7. REST API (полный список)

Публичные: `POST /api/v1/auth/start`, `POST /api/v1/auth/verify`,
`POST /api/v1/auth/combined` (см. §3.2).

Админ (`Authorization: Bearer <admin_token>`; токен хранится в настройках
БД, генерируется при первом старте, виден/перегенерируется в админке):

```
GET    /api/v1/admin/users            список
POST   /api/v1/admin/users            создать {username, password, email?, phone?, role?, prefer_channels?}
GET    /api/v1/admin/users/{id}
PATCH  /api/v1/admin/users/{id}       смена полей, enabled, password
DELETE /api/v1/admin/users/{id}
POST   /api/v1/admin/users/{id}/reset-totp     отвязать TOTP + регенерировать резервные коды
GET    /api/v1/admin/audit?username=&event=&since=&until=&limit=
GET    /api/v1/admin/challenges       активные challenge (без кодов, только метаданные)
GET    /api/v1/admin/settings         все настройки (секреты — маской)
PUT    /api/v1/admin/settings         частичное обновление; пустое/маскированное значение = «не менять»
POST   /api/v1/admin/settings/regenerate  {key: "admin_token"|"radius.secret"|...}
```

Кабинет (session-cookie):

```
GET  /api/v1/me                       профиль + статус каналов
PUT  /api/v1/me/contacts              смена email/phone (требует код на старый канал или резервный)
POST /api/v1/me/totp/enroll           → {secret, otpauth_url, qr_png_base64}
POST /api/v1/me/totp/confirm          {code} → подтверждение привязки
POST /api/v1/me/backup-codes/regenerate  → {codes[]} (показ один раз)
POST /api/v1/me/send-code             {channel} — тестовая/предварительная отправка
```

## 8. Конфигурация (в БД, таблица `settings`)

Единственная внешняя настройка — строка подключения: env `TWOFA_DB_DSN`
или флаг `-dsn`. Всё остальное — ключи в `settings`, при первом старте
инициализируются дефолтами (см. §10), затем редактируются через
`/admin → Настройки` или `PUT /api/v1/admin/settings`. Изменения применяются
на лету, кроме `listen.*` (порты — перезапуск; UI помечает это явно).

Ключи (value — JSON):

```
listen.http ":8080"        listen.radius_auth ":1812"   listen.radius_acct ":1813"
master_key "<base64, gen>" admin_token "<gen>"          radius.secret "<gen>"
radius.code_lengths [6,8]  radius.max_fail_per_user 10  radius.fail_window "5m"
radius.reply_attributes {}
smtp {host, port, starttls, user, password, from, subject, timeout}
sms.gateway {preset, method, url, headers, body, content_type, success}
sms.presets {smsc: {...}, twilio: {...}}
totp {issuer, digits, period, skew}
policy {code_ttl, code_length, max_attempts, resend_cooldown, default_prefer_channels}
web.session_ttl "12h"
```

`<gen>` — случайное значение, сгенерированное при первом старте
(crypto/rand) и доступное админу в UI (admin_token, radius.secret) —
то, что нужно сразу для подключения MikroTik и API. Пример SMS-шлюза
(руками, без пресета) и success-критерия:

```
sms.gateway = {
  "preset": "",
  "method": "POST",
  "url": "https://sms.example.com/send",
  "headers": {"Authorization": "Bearer <токен>"},
  "body": "{\"phone\": \"{phone}\", \"text\": \"{text}\"}",
  "content_type": "application/json",
  "success": {"http_status": 200}
}
```

`success` — любой набор из `http_status` / `body_contains` /
`{json_path, equals}`; всё перечисленное должно сойтись.

## 9. Структура репозитория

```
2fa/
  cmd/twofa/main.go              # флаги: -dsn (или env TWOFA_DB_DSN), миграции при старте
  internal/
    settings/                    # настройки в БД: дефолты, чтение/запись, маскировка секретов
    store/                       # pgx, миграции (embedded SQL), запросы
    auth/                        # PasswordVerifier, AuthCore: challenges,
    │                            # TOTP, резервные коды, сплит «пароль+код»
    delivery/                    # Interface Sender: EmailSender, SMSSender, LogSender
    radiusserver/                # layeh.com/radius: Access-Request, accounting-лог
    api/                         # chi: публичные/админ/me роуты, JSON
    web/                         # html/template + static, go:embed
    audit/                       # запись в audit_log
  migrations/0001_init.sql …
  web/templates/…, web/static/…  # исходники UI (в бинарник через embed)
  Dockerfile                     # multi-stage → gcr.io/distroless/static
  docker-compose.yml             # twofa + postgres:16-alpine
  README.md                      # настройка, пример MikroTik, API
  Makefile                       # build / test / lint / docker
```

Зависимости (минимум): `layeh.com/radius`, `github.com/go-chi/chi/v5`,
`github.com/jackc/pgx/v5`, `github.com/pquerna/otp`,
`golang.org/x/crypto` (argon2), `github.com/google/uuid`.

## 10. Развёртывание

- **docker-compose** (основной путь): `twofa` + `postgres:16-alpine`,
  том на pgdata, порты 8080/tcp, 1812/udp, 1813/udp. Env приложения —
  только `TWOFA_DB_DSN`; у контейнера postgres — свой стандартный
  `POSTGRES_PASSWORD` (бутстрап самой базы).
- Голый бинарник: `-dsn`/`TWOFA_DB_DSN`; systemd-unit в `deploy/twofa.service`.
- **Первый запуск:** миграции применяются автоматически; `settings`
  инициализируются дефолтами, `master_key`/`admin_token`/`radius.secret`
  генерируются; если `users` пуст — создаётся `admin` со случайным паролем,
  который **один раз печатается в лог** (стиль MinIO/Jenkins). Дальше —
  вход в `/admin → Настройки` и конфигурация SMTP/SMS через UI.
- Пример настройки MikroTik (`/radius` → новый сервер, secret из админки,
  timeout) и замечание про PAP — в README.

## 11. Тестирование

- **Unit:** сплит «пароль+код» (все длины, пароль кончается цифрами);
  генерация/проверка кода (TTL, попытки, одноразовость, cooldown);
  рендер SMS/Email-шаблонов (включая подстановку `{phone}`/`{text}`,
  URL-encoding); парсер success-критерия шлюза; TOTP-окно; argon2-хелперы.
- **Интеграция** (`go test`, ephemeral Postgres через testcontainers):
  флоу start→verify (email через LogSender/SMTP-sink), combined,
  сброс попыток, аудит-записи; RADIUS: реальный UDP Access-Request
  (accept/reject/троттлинг) клиентом из `layeh.com/radius`.
- **E2E вручную:** docker-compose up → /login → /me → привязка TOTP →
  код через API; Winbox → Radius → VPN-подключение с `пароль+код`.

## 12. Риски и решения

| Риск | Решение |
|---|---|
| SMS-шлюз у каждого провайдера свой | Шаблонный HTTP-шлюз + success-критерий + пресеты; LogSender для локальной отладки |
| Неоднозначный сплит пароль/код | Перебор длин кода, дешёвая проверка кода до argon2; длины настраиваются |
| Пользователь без привязанных каналов | Политика `prefer` + явная ошибка в `start` (`409 no_channel`), в RADIUS — Reject c аудитом |
| Потеря TOTP | Резервные коды + админский reset-totp |
| Утечка БД | Пароли argon2id, коды/сессии хешами, TOTP-секреты AES-GCM |
| Секреты в `settings` в открытом виде | Граница доверения — доступ к Postgres; API/UI их не отдаёт (маска); при желании ключ шифрования TOTP позже выносится в env без смены схемы |
