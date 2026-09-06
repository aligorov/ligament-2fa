# Ligament

> **Ligament** (связка) — то, что соединяет части в единую конструкцию:
> пользователь ↔ роутер (RADIUS), пользователь ↔ сервис (REST), пользователь ↔
> телефон (TOTP/Telegram-push), админ ↔ факторы, политики и шлюзы.
> Технические имена (бинарник `twofa`, compose-сервис, go-модуль) сохранены
> для совместимости.

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
`{phone}/{text}`, заголовки и правило успеха. Готовые пресеты — в списке
«Пресет шлюза» на странице настроек (выбор заполняет JSON — останется
вписать креды); полный список — в разделе [SMS-шлюзы](#sms-шлюзы-пресеты).

```json
{
  "preset": "smsc",
  "method": "GET",
  "url": "https://smsc.ru/sys/send.php?login={login}&psw={psw}&phones={phone}&mes={text}&fmt=3&charset=utf-8",
  "headers": {"login": "ЛОГИН", "psw": "ПАРОЛЬ"},
  "body": "",
  "content_type": "",
  "success": {"http_status": 200, "json_path": "$.cnt", "equals": "1"}
}
```

Поле `preset` — памятка для админа; отправка строится из полной конфигурации
(проще взять готовую выбором в «Пресет шлюза»).

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

## SMS-шлюзы (пресеты)

Девять готовых пресетов (Настройки → SMS-шлюз → «Пресет шлюза»). Данные
сверены живыми запросами к шлюзам — [research-док](docs/research/2026-09-06-sms-gateways-ru.md).

| Пресет | Креды (headers) | Телефон | Тест-режим | Цена ~ |
|---|---|---|---|---|
| `smsc` (SMSC.ru) | `login`, `psw` | любой, дефолт страны | `cost=1` (прайс без отправки) | 3.8–11 ₽ |
| `smsru` (SMS.ru) | `api_id` | 11 цифр, с `7` | `test=1` | ~8.4 ₽ |
| `smsaero` (SMS Aero) | `auth_base64`, `sender` | 11 цифр без `+` | имя «SMS Aero» | 1.95–3.3 ₽ |
| `mainsms` (MainSMS) | `project`, `api_key` | E.164 (`+7…`) | `test=1` | от ~1.3 ₽ |
| `bytehand` (ByteHand) | `id`, `key`, `sender` | `+7…` | нет | 7–9 ₽ |
| `prostor` (Простор-СМС) | `login`, `password`, `sender` | `+7…` | 50 дней / 10 SMS | от 1.49 ₽ |
| `unisender` (Unisender) | `api_key`, `sender` | `7…` (`+` опционален) | нет (`checkSms`) | 8–37 ₽ |
| `smsgateway24` | `token`, `device_id` | `+7…` — **с плюсом** | trial 5 дней | $38/мес без лимита |
| `twilio` (Twilio) | `sid`, `token`, `from` | E.164 | нет | по тарифу |

Нюансы правил успеха: `smsc`, `smsgateway24` и `smsru` возвращают ошибки
с HTTP 200 — успех проверяется по JSON-полю (`$.cnt=="1"`, `$.error=="0"`,
`$.status=="OK"`); `bytehand` отвечает числовым статусом `0`; `smsaero` и
`unisender` ошибками отвечают не-200; `twilio` на успех отвечает 201 —
успехом считается любой 2xx.

**SMS Aero — auth_base64.** Шлюз авторизуется заголовком
`Authorization: Basic …`, где после `Basic ` — base64 от `email:API-ключ`.
Вычислите один раз и положите в headers:

```sh
echo -n 'user@example.com:API_KEY' | base64
```

**Почему нет ePochta.** API v3 ePochta (Atompark) требует MD5-подпись
`sum` от отсортированных параметров (включая текст SMS) на каждый запрос —
шаблонный движок с подстановкой плейсхолдеров такое не умеет, пресет
невозможен по построению.

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
enroll/confirm, `POST /api/v1/me/backup-codes/regenerate` — новая партия
резервных кодов с кодом подтверждения, показ один раз; passkeys, Telegram,
устройства), админ `/api/v1/admin/*` по
`Authorization: Bearer <admin_token>` (токен в админке, Настройки →
«Перегенерировать admin_token»; новое значение показывается один раз).
Полный список — спека §7.

Ошибки: 401 `bad_credentials`/`bad_code` (с `attempts_left`), 410 `expired`,
423 `locked` (fail-лок), 429 `rate_limited`/`cooldown`, 409 `no_channel`.

## API-документация (OpenAPI)

Полный контракт REST API (все 41 операция `/api/v1/*` + `/healthz`, схемы
запросов/ответов, коды ошибок, примеры) — OpenAPI 3.0.3:

- **`/openapi.yaml`** — сама спецификация (встроена в бинарник,
  `Content-Type: text/yaml`);
- **`/api/docs`** — компактная встроенная страница: эндпоинты по группам
  (Public Auth / Web Session / Me / Admin) с методами, путями и кодами
  ответов (ссылка «API» в админ-разделе бокового меню).

Импорт в Postman: **Import → File** (или ссылку `http://localhost:8080/openapi.yaml`),
в Insomnia: **Create → Import From URL**. Swagger UI/editor — «openapi 3.0»
из URL `/openapi.yaml`.

Замечания по авторизации при импорте:

- админ-эндпоинты `/api/v1/admin/*` — заголовок `Authorization: Bearer
  <admin_token>` (в Postman — тип Auth **Bearer Token**);
- кабинет `/api/v1/me/*` и `POST /api/v1/logout` — cookie `twofa_session`
  (Auth **API Key** → тип Cookie, значение из ответа `/api/v1/login`);
  мутации (POST/PUT/PATCH/DELETE) дополнительно требуют заголовок
  `X-CSRF-Token` со значением `csrf` из ответа входа — иначе 403 `csrf`;
- cookie выпускается с флагом Secure — при импорте через plain HTTP
  используйте `localhost` или TLS-прокси.

## Лицензирование (реализация)

Модель утверждена в `docs/reports/2026-09-06-licensing.md`: оффлайн
подписанный license-файл (Ed25519), без activation-сервера и phone-home —
интернет на площадке клиента не нужен.

### Режимы и лимиты

| Режим | Условие | Лимит активных пользователей |
|---|---|---|
| **free** | лицензии нет (или отозвана/истекла) | **5**, навсегда |
| **trial** | первый старт сервера | без лимита, **30 дней** full-featured (старт демо персистится в БД — `settings.license.trial_started`; сбрасывается только с БД) |
| **licensed** | загружен валидный файл | `user_limit` из лицензии |

Что блокируется: **только создание и включение пользователей сверх лимита**
(JSON API → 403 `license_limit`, форма /admin/users → флеш-ошибка; событие
`license_limit` в аудите). **Вход/аутентификация существующих пользователей
(RADIUS, REST, web) не блокируется никогда** — организация не теряет доступ.
Истечение демо/подписки — тихая деградация в free (не хард-блок): баннер в
админке при достижении лимита, демо ≤7 дн., подписке ≤14 дн. (или в grace),
окне обновлений ≤30 дн., отзыве/истечении.

Подписка (`expires_at` ≤ 13 мес.) гаснет через **grace-окно 5 дней** после
`expires_at`; perpetual — бессрочная, обновления до `maintenance_expires`.

### Формат файла

```
-----BEGIN LIGAMENT LICENSE-----
<base64(canonical JSON payload)>.<base64(Ed25519-подпись)>
-----END LIGAMENT LICENSE-----
```

Payload: `lic_id` (UUID), `customer`, `plan` (`subscription`|`perpetual`),
`user_limit`, `issued_at`, `expires_at` (только подписка), `maintenance_expires`,
`features`, `kid` (ID ключа подписи — ротация), `notes`. Канонический JSON —
отсортированные ключи без пробелов (стабильные байты для подписи). Публичные
ключи зашиты в бинарник (`internal/license`, `trustedKeys`); подделка без
приватного ключа вендора невозможна.

Загрузка: **Админ → Лицензия** (`/admin/license`) — вставка файла в textarea
или `PUT /api/v1/admin/license {"blob": ...}` (статус — `GET`, снятие —
`DELETE`; все действия в аудите). Ошибки: `invalid_format`,
`invalid_signature`, `revoked`.

### Гейт обновлений (build-date)

Дата сборки вшивается в бинарник: `make build` / `make docker` добавляют
`-ldflags "-X main.BuildDate=$(date +%F)"` (в Docker — `ARG BUILD_DATE`).
Licensed-сервер **не стартует**, если сборка новее `maintenance_expires`
лицензии: «версия новее окна обновлений лицензии — откатитесь или продлите
maintenance». Free/trial не ограничены; perpetual сохраняет вечное право на
версии, выпущенные до конца maintenance (версионный пиннинг).

### Отзыв (CRL)

Досрочный отзыв подписки — подписанный блоб, загружается отдельно или с новой
лицензией (`PUT /api/v1/admin/license/crl`):

```
-----BEGIN LIGAMENT REVOCATION-----
<base64({"lic_id":...,"revoked_at":...,"kid":...})>.<base64(sig)>
-----END LIGAMENT REVOCATION-----
```

Совпадение `lic_id` с загруженной лицензией переводит сервер в free (статус
показывает `revoked: true`). Perpetual технически не отзывается (только
юридически).

### licgen (генератор вендора)

`cmd/licgen` в этом же репозитории — публичность безопасна: без приватного
ключа вендора генератор бесполезен.

```sh
# пара ключей: приватный PKCS8 PEM (хранить офлайн!), публичный PEM + hex
go run ./cmd/licgen -genkey

# подписка на 12 мес, 50 пользователей
go run ./cmd/licgen -key vendor.pem -kid 2026-09 \
    -customer "ООО Ромашка" -plan subscription -users 50 -months 12 -out lic.pem

# perpetual с 12 мес обновлений
go run ./cmd/licgen -key vendor.pem -kid 2026-09 \
    -customer "ООО Ромашка" -plan perpetual -users 100 -maintenance-months 12

# CRL-отзыв
go run ./cmd/licgen -key vendor.pem -kid 2026-09 -crl -revoke <lic_id>
```

### Ключи выпуска

В `internal/license/file.go` зашит ПЛЕЙСХОЛДЕР (`dev-1`) для разработки.
Перед релизом вендор обязан: (1) `licgen -genkey` — сгенерировать пару,
(2) hex публичного ключа вписать в `trustedKeys` с новым `kid` (можно 2–3
ключа для ротации), (3) приватный ключ — офлайн-хранилище (HSM/шифрованный
носитель), НЕ в репозиторий. Сгенерированные ранее плейсхолдером лицензии
перестанут проходить проверку — это ожидаемо.

### LDAP-провижининг

Авторизация через LDAP (внешний каталог) при автоматическом создании
пользователей **пока не блокируется лимитом** — только учитывается в счётчике
активных (интеграционная проверка — отдельным коммитом).

## Безопасность

- Пароли — **argon2id**; TOTP-секреты — AES-256-**GCM** с AAD-привязкой к
  username (секрет, украденный из БД, не расшифровывается без master_key и
  не переносится на другого пользователя).
- Все события (входы, коды, изменения) — в `audit_log`; единый per-user
  fail-счётчик: **5 неудач / 5 минут → блок 15 минут**. Семантика: счётчик
  сбрасывается сам через `policy.fail_window` после последней неудачи
  (окно скользящее от последней попытки), а каждая новая неудача внутри
  блокировки продлевает её — «отсидеть» бан, продолжая брут, нельзя; бан
  кончается через `policy.ban_time` после ПОСЛЕДНЕЙ неудачи. RADIUS-поток
  имеет отдельный лимит `radius.max_fail_per_user` за `radius.fail_window`
  в дополнение к общему.
- Челленджи одноразовые (атомарный claim), коды — SHA-256 в БД, TOTP —
  replay-защита по счётчику окна (CAS: одна попытка — одно окно, повтор
  того же кода и параллельные предъявления rejected). Коды изолированы по
  назначению (purpose): экранный код привязки Telegram и код подтверждения
  операций кабинета не работают как второй фактор входа.
- RADIUS: **Message-Authenticator реализован** (RFC 3579) — ответы подписаны,
  митигация BlastRADIUS; шифрование пароля PAP стандартное. Смена
  `radius.secret` применяется на лету (новые пакеты проверяются новым
  секретом, рестарт не нужен).
- Rate-limit: публичный API и веб-логин — token bucket **burst 5, далее
  12 запросов/мин** sustained (по username и по IP независимо, окна
  изолированы); RADIUS-попытки ограничены своим fail-счётчиком (см. выше),
  а не HTTP-лимитом; push — cooldown 30 с и не более 10/час.

## Ограничения v1

- **RP ID и passkeys**: ключи привязаны к домену (`webauthn.rp_id`) — смена
  домена ломает зарегистрированные passkeys (потребуется повторная
  регистрация).
- **LDAP / внешние каталоги пользователей** — в будущих версиях (спека §12).
- Смена `listen.*` требует рестарта процесса.
- Passkey-вход в web-UI выполняется REST-церемонией
  (`/api/v1/auth/webauthn/begin` → `finish`): кнопки браузерного autofill
  (Conditional UI) нет.
- Эндпоинт отправки кода подтверждения фактически называется
  `PUT /api/v1/me/contacts/send-code` (в спеке фигурирует как
  `/api/v1/me/send-code`).
- Настройки через API асимметричны: `GET /api/v1/admin/settings` отдаёт
  ДЕРЕВО по секциям (секреты — масками `{"set":…,"value":"••••"}`), а
  `PUT` принимает ПЛОСКИЕ известные ключи (`{"radius.secret":"…",
  "smtp":{"host":"…"}}`); объекты мержатся с текущим значением, маска или
  пустая строка на любом уровне = «не менять поле».
- QR для REST-энролла TOTP рендерится клиентом по `otpauth_url` из ответа
  enroll (поля `qr_png_base64` в API нет; web-UI рисует QR сам).
- Cookie web-сессий выпускаются с флагом Secure — web-UI по plain HTTP
  работает только на localhost либо за TLS-прокси.

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
api/             OpenAPI-спецификация (openapi.yaml + go:embed)
internal/api/    REST API + web-страницы (chi)
internal/auth/   ядро аутентификации (челленджи, сплиты, TOTP)
internal/radiusserver/  RADIUS auth/acct (layeh.com/radius)
internal/store/  PostgreSQL (pgx) — пользователи, челленджи, аудит...
internal/settings/ конфигурация в БД (defaults, hot-reload)
internal/delivery/ email/SMS-отправка (9 пресетов шлюзов: smsc, sms.ru,
                 smsaero, mainsms, bytehand, prostor, unisender,
                 smsgateway24, twilio)
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
