# twofa — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Go-монолит `twofa`: RADIUS (MikroTik VPN) + REST API + web-UI, второй фактор — email/SMS/TOTP/passkeys/Telegram(код+push), PostgreSQL, вся конфигурация в БД (единственный env — `TWOFA_DB_DSN`).

**Architecture:** Один бинарник, слушатели HTTP :8080 / RADIUS :1812 (auth, PAP) / :1813 (acct, лог). Слои: `store` (pgx+миграции) → `settings` (конфиг в БД) → `auth` (ядро: challenges/TOTP/сплиты) + `delivery` (senders) + `telegram` (bot) + `webauthn` → `api` (chi) / `radiusserver` / `web` (html/template, go:embed).

**Tech Stack:** Go 1.25+, chi v5, pgx v5, layeh.com/radius (+ vendors/mikrotik), pquerna/otp v1.5, go-webauthn v0.18, x/crypto argon2. Точные API — **docs/research/2026-09-06-library-references.md** (обязателен к прочтению каждому агенту). Спека — **docs/superpowers/specs/2026-09-05-twofa-server-design.md**.

## Global Constraints

- Go 1.25+; зависимости только из §9 спеки (+testcontainers-go для тестов).
- Секреты: пароли argon2id (m=64MB,t=1,p=4), TOTP-секреты AES-256-GCM (master_key в settings), коды/сессии/резервные коды — только SHA-256-хеши в БД.
- TOTP: SHA1/6/30с/skew±1 **+ собственная replay-защита** (last_timestep).
- API/UI никогда не возвращают секретные настройки (маска `••••`+флаг set).
- Аудит каждого события аутентификации/админ-действия (таблица audit_log).
- Код-стайл: стандартный gofmt, комментарии по-русски только где неочевидно; коммиты после каждой зелёной задачи.
- Все тесты: `go test ./...` (unit — без внешних зависимостей; БД-тесты — build tag `integration`, поднимают Postgres testcontainers; Skip, если Docker недоступен).

## Волны параллельного исполнения

```
W1: T1
W2: T2, T3
W3: T4, T5, T6
W4: T7, T9  (+T8 сразу за T7, интерфейс фиксирован ниже)
W5: T10, T12, T8-доделка, T11(за T10)
W6: T13
W7: T14
W8: T15
```

Общие контракты (видны всем задачам; менять сигнатуры нельзя):

```go
type Channel string // "totp"|"email"|"sms"|"telegram"|"telegram_push"|"webauthn"

type User struct {
    ID uuid.UUID; Username string; Role string; Enabled bool
    Email, Phone string; TelegramChatID *int64
    PreferChannels []Channel; RadiusPush bool
    RadiusReply map[string]string // JSONB, может быть nil
    WebAuthnID []byte // генерируется при первом webauthn-enroll
    PasswordHash string
}
```

---

### Task 1: Каркас

**Files:** Create: `go.mod`, `cmd/twofa/main.go`, `internal/api/router.go`, `internal/api/health.go`, `Makefile`, `.gitignore` (дополнить), `README.md` (заглушка).
**Interfaces (Produces):** `api.NewRouter() http.Handler` c `GET /healthz → {"status":"ok"}`; main читает `-dsn`/`TWOFA_DB_DSN` (пока не подключает БД, только парсит).

- [ ] `go mod init github.com/aligorov/twofa`; go 1.25; chi v5.
- [ ] Тест `internal/api/health_test.go`: httptest → GET /healthz → 200 + `{"status":"ok"}` (код теста — стандартный httptest.NewServer).
- [ ] Реализовать router+health до зелёного.
- [ ] `Makefile`: `build` (`go build -o twofa ./cmd/twofa`), `test` (`go test ./...`), `lint` (`go vet ./...`).
- [ ] Commit: `feat: каркас, healthz`.

### Task 2: Миграции и store

**Files:** Create: `migrations/0001_init.sql`, `internal/store/store.go`, `internal/store/migrate.go`, `internal/store/migrate_test.go`.
**Interfaces (Produces):** `store.Open(ctx, dsn) (*Store, error)` (pgxpool, пинг), `(*Store).Migrate(ctx) error` (embedded FS, таблица `schema_migrations(version int pk, applied_at)`), `(*Store).Close()`; `(*Store).Pool() *pgxpool.Pool`.
**Consumes:** —

Схема 0001 (полностью; индексы из §5 спеки):

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
  enabled BOOL NOT NULL DEFAULT true, email TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '', telegram_chat_id BIGINT,
  prefer_channels JSONB NOT NULL DEFAULT '["totp","email","sms"]',
  radius_push BOOL NOT NULL DEFAULT false, radius_reply JSONB,
  webauthn_id BYTEA UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE totp_secrets (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret_enc BYTEA NOT NULL, digits INT NOT NULL DEFAULT 6,
  period INT NOT NULL DEFAULT 30, confirmed_at TIMESTAMPTZ,
  last_timestep BIGINT NOT NULL DEFAULT 0);
CREATE TABLE backup_codes (
  id BIGSERIAL PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  code_hash BYTEA NOT NULL UNIQUE, used_at TIMESTAMPTZ);
CREATE TABLE challenges (
  id UUID PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  channel TEXT NOT NULL, code_hash BYTEA, push_state TEXT,
  expires_at TIMESTAMPTZ NOT NULL, attempts_left INT NOT NULL DEFAULT 5,
  used_at TIMESTAMPTZ, purpose TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX ON challenges(user_id, expires_at);
CREATE TABLE sessions (
  token_hash BYTEA PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE settings (key TEXT PRIMARY KEY, value JSONB NOT NULL);
CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  username TEXT, event TEXT NOT NULL, detail JSONB, src_ip TEXT, result TEXT);
CREATE INDEX ON audit_log(ts); CREATE INDEX ON audit_log(username, ts);
CREATE TABLE trusted_devices (
  id BIGSERIAL PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL UNIQUE, ua TEXT, ip TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL);
CREATE TABLE webauthn_credentials (
  id BIGSERIAL PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  credential_id BYTEA NOT NULL UNIQUE, credential_json JSONB NOT NULL,
  name TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ);
```

- [ ] Тест (integration): testcontainer Postgres 16 → Open+Migrate → повторный Migrate идемпотентен; SELECT из всех таблиц без ошибок.
- [ ] Реализовать, зелёный, commit `feat: store+миграции`.

### Task 3: secrets (крипто-примитивы)

**Files:** Create: `internal/secrets/password.go`, `box.go`, `codes.go` (+`*_test.go`).
**Interfaces (Produces):**

```go
func HashPassword(pw string) string                          // argon2id, m=1<<26, t=1, p=4, salt 16B, формат RFC
func VerifyPassword(hash, pw string) bool                    // constant-time
func NewMasterKeyB64() string                                // 32B crypto/rand → base64
func NewBox(keyB64 string) (*Box, error)
func (b *Box) Encrypt(p []byte) []byte                       // 12B nonce || AES-GCM
func (b *Box) Decrypt(c []byte) ([]byte, error)
func GenDigits(n int) string                                 // crypto/rand, ведущие нули разрешены
func SHA256(s string) []byte
func GenBackupCodes() []string                               // 10 шт "XXXXX-XXXXX", алфавит ABCDEFGHJKMNPQRSTUVWXYZ23456789
func RandomToken(n int) string                               // base64url
```

- [ ] TDD-цикл на каждую функцию (тест: roundtrip Encrypt/Decrypt, неверный ключ → ошибка, VerifyPassword на неверном хеше из другого пароля, формат backup-кодов регексом `^[A-Z2-9]{5}-[A-Z2-9]{5}$`, GenDigits(6) всегда 6 символов).
- [ ] Commit `feat: крипто-примитивы`.

### Task 4: settings

**Files:** Create: `internal/settings/settings.go`, `defaults.go`, `settings_test.go`.
**Interfaces (Consumes):** store. **(Produces):**

```go
type T struct { // снимок настроек, читается конкурентно
    Listen struct{ HTTP, RadiusAuth, RadiusAcct string }
    MasterKeyB64, AdminToken, RadiusSecret string
    Radius struct{ CodeLengths []int; MaxFailPerUser int; FailWindow time.Duration; ReplyAttributes map[string]string }
    SMTP struct{ Host string; Port int; StartTLS bool; User, Password, From, Subject string; Timeout time.Duration }
    SMS   sms.GatewayConfig   // из Task 6 — см. ниже; здесь хранить как json.RawMessage + метод
    TOTP  struct{ Issuer string; Digits, Period int; Skew uint }
    TG    struct{ BotToken string }
    WebAuthn struct{ RPID, RPName string }
    Policy struct{ CodeTTL, ResendCooldown, PushTTL, PushCooldown, TrustedDeviceTTL, SessionTTL time.Duration; CodeLength, MaxAttempts, PushPerHour int; DefaultPrefer []Channel }
}
func Load(ctx, st *store.Store) (*T, error)  // читает settings; отсутствующие ключи → дефолты из defaults.go; при пустой таблице INSERT'ит дефолты и генерирует master_key/admin_token/radius.secret (secrets.NewMasterKeyB64 / RandomToken(32))
type M struct{ /*...*/ }
func NewManager(ctx, st) (*M, error)         // хранит atomic.Pointer[T]
func (m *M) Get() *T
func (m *M) Reload(ctx) error                // перечитать; listen.* применяются после рестарта
func (m *M) Put(ctx, key string, val json.RawMessage) error // точечная запись + Reload
func (m *M) Masked(ctx) (map[string]any, error)             // всё, секреты → {"set":true,"value":"••••"}
```

Дефолты: listen как в спеке; policy: CodeTTL 5m, ResendCooldown 60s, PushTTL 2m, PushCooldown 30s, TrustedDeviceTTL 720h, SessionTTL 12h, CodeLength 6, MaxAttempts 5, PushPerHour 10, DefaultPrefer ["totp","telegram","email","sms"].

- [ ] integration-тест: Load на пустой БД создаёт ключи (master_key — валидный base64 32B), повторный Load даёт те же значения; Put("smtp", ...) → Get().SMTP изменился; Masked не содержит реального admin_token.
- [ ] Commit `feat: settings в БД`.

### Task 5: репозитории

**Files:** Create: `internal/store/users.go`, `challenges.go`, `totp.go`, `sessions.go`, `devices.go`, `audit.go`, `webauthn.go` (+`integration_test.go` на каждый).
**Interfaces (Produces) — точные:**

```go
// users.go
func (s *Store) UserByUsername(ctx, name string) (*User, error)      // ErrNotFound
func (s *Store) UserByID(ctx, id uuid.UUID) (*User, error)
func (s *Store) UserCreate(ctx, u *User) error
func (s *Store) UserUpdate(ctx, u *User) error                       // все поля кроме id/created
func (s *Store) UserDelete(ctx, id uuid.UUID) error
func (s *Store) UserCount(ctx) (int, error)
func (s *Store) UserList(ctx) ([]*User, error)
// challenges.go
type Challenge struct { ID uuid.UUID; UserID uuid.UUID; Channel Channel; CodeHash []byte; PushState *string; ExpiresAt time.Time; AttemptsLeft int; UsedAt *time.Time; Purpose string; CreatedAt time.Time }
func (s *Store) ChallengeCreate(ctx, c *Challenge) error
func (s *Store) ChallengeGet(ctx, id uuid.UUID) (*Challenge, error)
func (s *Store) ChallengeMarkUsed(ctx, id uuid.UUID) error
func (s *Store) ChallengeDecrAttempt(ctx, id uuid.UUID) (left int, err error)
func (s *Store) ChallengeSetPush(ctx, id uuid.UUID, state string) error // pending|approved|denied
func (s *Store) ActiveCodeChallenges(ctx, userID uuid.UUID) ([]*Challenge, error) // not expired, not used, code_hash not null
func (s *Store) FreshApprovedPush(ctx, userID uuid.UUID, maxAge time.Duration) (*Challenge, error)
func (s *Store) LastPushAt(ctx, userID uuid.UUID) (time.Time, error)   // для cooldown/лимита в час
func (s *Store) PushCountSince(ctx, userID uuid.UUID, since time.Time) (int, error)
// totp.go
func (s *Store) TOTPSave(ctx, userID uuid.UUID, secretEnc []byte, digits, period int) error // confirmed_at=NULL
func (s *Store) TOTPConfirm(ctx, userID uuid.UUID) error
func (s *Store) TOTPGet(ctx, userID uuid.UUID) (secretEnc []byte, digits, period int, confirmed bool, lastTimestep int64, err error)
func (s *Store) TOTPSetTimestep(ctx, userID uuid.UUID, ts int64) error
func (s *Store) TOTPDelete(ctx, userID uuid.UUID) error
// backup-коды: BackupReplace(ctx, userID, hashes [][]byte) error; BackupConsume(ctx, userID, hash []byte) (bool, error)
// sessions.go: SessionCreate(ctx, tokenHash []byte, userID, csrf string, ttl) error; SessionGet(ctx, tokenHash) (userID, csrf, error); SessionDelete(ctx, tokenHash) error; SessionDeleteAllForUser(ctx, userID)
// devices.go: DeviceCreate/DeviceGet/DeviceTouch/DeviceDelete/DeviceListForUser/DeviceDeleteAllForUser
// audit.go: Audit(ctx, username, event string, detail map[string]any, ip, result string) error; AuditList(ctx, filter) ([]AuditRow, error)
// webauthn.go: WACredUpsert(ctx, userID, credID []byte, credJSON []byte, name string); WACredListForUser(ctx, userID) ([]WACred); WACredUpdate(ctx, id int64, credJSON, lastUsed) ; WACredDelete(ctx, id, userID); WACredsDeleteForUser(ctx, userID)
```

- [ ] integration-тест на каждый репозиторий (CRUD + граничные: не найдено → ErrNotFound; BackupConsume дважды → второй false).
- [ ] Commit `feat: репозитории`.

### Task 6: delivery

**Files:** Create: `internal/delivery/delivery.go`, `email.go`, `sms.go`, `sms_test.go`, `log.go`, `presets.go`.
**Interfaces (Produces):**

```go
type Sender interface { Name() Channel; Send(ctx context.Context, to, code string) error }
func NewEmail(host string, port int, startTLS bool, user, pass, from, subject string, timeout time.Duration) Sender // net/smtp, STARTTLS при 587
func NewSMS(gw GatewayConfig, hc *http.Client) Sender
func NewLog() Sender // пишет код в лог (тесты/отладка)
type GatewayConfig struct { Preset, Method, URL, Body, ContentType string; Headers map[string]string; Success SuccessRule }
type SuccessRule struct { HTTPStatus int; BodyContains string; JSONPath, Equals string } // выполнены все непустые
```

- [ ] Unit-тесты (httptest): success по статусу/подстроке/JSON-path (`{"status":"ok"}` + path `$.status`); подстановка `{phone}`/`{text}` в URL и тело (QueryEscape для URL); preset `smsc` и `twilio` рендерятся в корректный запрос (свёрстано по их публичным API: smsc `GET /sys/send.php?login=&psw=&phones=&mes=`; twilio `POST /2010-04-01/Accounts/{sid}/Messages.json` basic-auth + form).
- [ ] Email — таблица-тест на построение сообщения (без реальной отправки: интерфейс должен позволять подсунуть mock — Send через функцию `sendFn` полем).
- [ ] Commit `feat: senders (email/sms/log)`.

### Task 7: auth-ядро

**Files:** Create: `internal/auth/auth.go`, `split.go`, `split_test.go`, `totp.go`, `core.go`, `core_test.go`.
**Interfaces (Consumes):** store (T5), secrets (T3), settings (T4), delivery (T6). **(Produces):**

```go
type PasswordVerifier interface { Verify(ctx context.Context, username, password string) (*store.User, error) }
func NewLocalVerifier(st *store.Store) PasswordVerifier

func SplitCandidates(s string, lengths []int) []Split // Split{Password, Code string}; пароль может кончаться цифрами — вернуть все разбиения по порядку длин

type Core struct { /* st *store.Store, set *settings.M, box *secrets.Box, senders map[Channel]delivery.Sender, pv PasswordVerifier */ }
func NewCore(deps ...) *Core

func (c *Core) Start(ctx, user *store.User, purpose string) (*store.Challenge, error)
// политика: по PreferChannels (или дефолту) первый привязанный+включённый канал:
// totp → challenge{channel:totp} без code_hash; email/sms/telegram(код) → генерация кода, sender.Send, code_hash;
// ни одного → ErrNoChannel
func (c *Core) VerifyChallengeCode(ctx, ch *store.Challenge, code string) (bool, error)
// code-каналы: сравнение хеша, DecrAttempt, single-use; totp: ValidateCustom + last_timestep replay-защита (обновлять после успеха)
func (c *Core) VerifyAnyCode(ctx, user *store.User, code string) (Channel, error)
// последовательность: backup-код → totp (c replay) → активные code-challenges пользователя
func (c *Core) VerifyPasswordAndCode(ctx, username, password, code string) (*store.User, bool, error)
// для RADIUS/combined: сначала по code выбрать split-кандидата (SplitCandidates), VerifyAnyCode, затем ОДИН VerifyPassword на пароль кандидата
func (c *Core) RADIUSAuth(ctx, username, papString, srcIP string) (accept bool, reason string)
// полный алгоритм §3.1+§3.6: сплит-кандидаты → VerifyAnyCode → VerifyPassword; push-режим (radius_push): FreshApprovedPush → accept; иначе создать push (cooldown PushCooldown + лимит PushPerHour) → reject("push_sent")
```

TOTP replay: `totp.ValidateCustom(...)` из research-дока; после успеха вычислить counter=t.Unix()/period принятого окна и `TOTPSetTimestep(max(counter, last))`; отвергать counter ≤ last (с учётом skew — хранить counter фактически принятого кода).

- [ ] Unit: SplitCandidates("secret123456",[6,8]) → 2 кандидата; TOTP replay — один и тот же код принимается один раз (мок времени не нужен: Generate рядом кодов); cooldown resend; ErrNoChannel.
- [ ] Integration (build tag): полный Start→VerifyChallengeCode по email через delivery.NewLog (код берём из лог-хука), VerifyAnyCode по backup-коду, VerifyPasswordAndCode.
- [ ] Commit `feat: auth-ядро (challenges, totp+replay, сплиты)`.

### Task 8: telegram-бот

**Files:** Create: `internal/telegram/client.go`, `bot.go`, `client_test.go`, `fake_test.go`.
**Interfaces (Consumes):** store (link-коды = Challenge{purpose:"tg_link", code_hash, attempts}), auth (ChallengeSetPush). **(Produces):**

```go
type Bot struct{ /* cl *Client, st *store.Store, set *settings.M, notify func(ctx, challengeID, userID uuid.UUID, ip, ua string) error */ }
func New(apiBase, token string, st *store.Store, set *settings.M) *Bot
func (b *Bot) Run(ctx context.Context) error // long polling: offset=last+1, timeout 50, allowed_updates=["message","callback_query"], http.Client 60s
// сообщения: /start <code> или текст-код → проверка активного tg_link-challenge (хеш), привязка telegram_chat_id
// callback approve:<uuid>|deny:<uuid> → ChallengeSetPush + answerCallbackQuery + editMessageText(итог)
func (b *Bot) SendCode(ctx, chatID int64, code string) error
func (b *Bot) SendPush(ctx, chatID int64, who, ip, ua string, challengeID uuid.UUID) error // inline-кнопки из research-дока
```

- [ ] Fake API (httptest-сервер, раздаёт getUpdates/sendMessage) — тест: привязка по коду; approve/deny меняют push_state; 429 → ожидание retry_after (мок-сон).
- [ ] Commit `feat: telegram-бот (код+push)`.

### Task 9: webauthn

**Files:** Create: `internal/webauthn/wa.go`, `wa_test.go`, `adapter.go`.
**Interfaces (Consumes):** store (T5), settings. **(Produces):**

```go
type Svc struct{ /* w *webauthn.Webauthn, st *store.Store, set *settings.M */ }
func New(st *store.Store, set *settings.M) (*Svc, error) // webauthn.New(&webauthn.Config{RPDisplayName: set.RPName, RPID, RPOrigins: ["https://"+RPID]}) — по research-доку
// user-адаптер: WebAuthnID() = users.webauthn_id (лениво генерировать+сохранить), Name=Username, DisplayName=Username, Credentials() из WACredListForUser (credential_json → webauthn.Credential)
func (s *Svc) BeginRegister(ctx, user *store.User) (opts json.RawMessage, session []byte, err error) // session — webauthn.SessionData JSON; хранит в challenges{purpose:"webauthn_session", code_hash: SHA256(случайный handle), expires 5m} — handle отдаётся клиенту
func (s *Svc) FinishRegister(ctx, user *store.User, handle, name string, r *http.Request) error // достать session по handle, FinishRegistration(user, session, r), WACredUpsert; CloneWarning→аудит
func (s *Svc) BeginLogin(ctx, user *store.User) (opts json.RawMessage, handle string, err error)
func (s *Svc) FinishLogin(ctx, user *store.User, handle string, r *http.Request) error // + ОБЯЗАТЕЛЬНО WACredUpdate с новым SignCount (research-док!)
```

- [ ] Тест с go-webauthn (в репо есть примеры эмуляции; минимально — конфиг валиден, Begin* возвращает challenge с rpId; полный e2e-кэйлейб в T15 вручную).
- [ ] Commit `feat: webauthn-сервис`.

### Task 10: публичный REST API

**Files:** Create: `internal/api/public.go`, `ratelimit.go`, `public_test.go`.
**Interfaces (Consumes):** auth.Core, webauthn.Svc, store. Роуты (§3.2, §7): `POST /api/v1/auth/start|verify|combined|poll`, `POST /api/v1/auth/webauthn/begin|finish`. Rate-limit: token bucket per username+IP (golang.org/x/time/rate, in-memory map+RWMutex, очистка).
Ответы: 200 `{challenge_id, channel, expires_in}` / 401 / 409 `{"error":"no_channel"}` / 429+Retry-After; verify: 200 `{ok:true,username}` / 401 `{ok:false,attempts_left}` / 410; poll: `{status}`.
push-канал в Start: создать challenge{channel:telegram_push, push_state:pending}, SendPush, вернуть channel="telegram_push".
- [ ] httptest-тесты всех ответных кодов (email через LogSender: код вытаскиваем из захваченного лога), 429 при спаме start, poll: pending→approved после ChallengeSetPush.
- [ ] Commit `feat: публичный API`.

### Task 11: admin/me API + сессии web

**Files:** Create: `internal/api/admin.go`, `me.go`, `session.go`, `admin_test.go`.
**Interfaces (Consumes):** всё выше. Добавляет в router: middleware `RequireAdminToken` (Bearer, из settings) и `RequireSession` (cookie twofa_session; CSRF для форм).
Admin-роуты — §7 спеки (users CRUD, reset-totp, reset-webauthn, unlink-telegram, devices DELETE, audit, challenges, settings GET/PUT/regenerate). Me-роуты — §7 (profile, contacts, totp enroll/confirm, backup-codes, send-code, webauthn register begin/finish + delete cred, telegram link, devices).
Вход web: `POST /login` {username,password} → при валидном доверенном устройстве сразу сессия; иначе passkey (если есть) или код (Start+VerifyChallengeCode в форме); `remember_device` → DeviceCreate + cookie `twofa_device` (HttpOnly,Secure,SameSite=Lax). Смена пароля → SessionDeleteAllForUser + DeviceDeleteAllForUser.
- [ ] Тесты: сессия после входа, admin-token 401/200, маскировка секретов в GET settings, PUT не меняет секрет при передаче маски.
- [ ] Commit `feat: admin/me API и web-сессии`.

### Task 12: RADIUS-сервер

**Files:** Create: `internal/radiusserver/server.go`, `server_test.go`.
**Interfaces (Consumes):** auth.Core (`RADIUSAuth`), settings, store (аудит, throttle-счётчик через PushCountSince-like запросы + собственная таблица-без-таблицы: in-memory окно отказов `map[string][]time.Time` под мьютексом — per-username, окно FailWindow, лимит MaxFailPerUser).
PacketServer-ы (research-док): auth :1812 (handler: UserName_LookupString+UserPassword_LookupString → RADIUSAuth → r.Response(CodeAccessAccept)+ReplyMessage+reply-атрибуты: сначала per-user RadiusReply, иначе глобальные; имена атрибутов: строка "Mikrotik-Group" → mt.MikrotikGroup_SetString, "Reply-Message"→rfc2865, прочие стандартные через rfc2865 `Attr(*)` по имени через radius.AttributesType lookup; неизвестные → скип+лог) ; acct :1813 → CodeAccountingResponse + лог.
SecretSource: StaticSecretSource(radius.secret). Accept-путь: ChallengeMarkUsed для потраченного push.
- [ ] Integration-тест: поднять сервер на 127.0.0.1:0 (Serve на net.ListenConfig().ListenPacket), radius.Exchange: пароль+код (accept), неверный код (reject), push-окно (reject → approve → accept), throttle (11-й reject без проверки — по времени выполнения/счётчику).
- [ ] Commit `feat: RADIUS auth+acct`.

### Task 13: Web-UI

**Files:** Create: `web/templates/*.gohtml` (base, login, admin/users, admin/audit, admin/challenges, admin/settings, me), `web/static/style.css`, `internal/web/web.go` (go:embed, render-хелперы), `internal/web/pages.go`.
**Interfaces (Consumes):** api-хендлеры уже есть — страницы рендерят формы на те же POST-роуты (прогресс-UX: после POST редирект). Требования: русский язык, minimal CSS без фреймворков, QR для TOTP — картинка через `otp.Key.Image(200,200)` → PNG в base64 (pquerna/otp умеет) ИЛИ сторонний генератор нельзя — используем key.Image.
- [ ] Тест: рендер всех страниц без ошибок (template execute с мок-данными), embed собирается.
- [ ] Commit `feat: web-ui`.

### Task 14: сборка main

**Files:** Modify: `cmd/twofa/main.go`.
**Interfaces (Consumes):** все. Порядок: parse -dsn/env → store.Open+Migrate → settings.Load (бутстрап) → если UserCount==0: создать `admin` c RandomToken(12)-паролем и ОДИН раз напечатать в лог `ADMIN PASSWORD: ...` → построить Core/Senders/Bot/WebAuthn/API/RADIUS → goroutines: http, radius auth, radius acct, (telegram Run если token задан), settings hot-reload по SIGHUP + после PUT → graceful shutdown по SIGTERM.
- [ ] `make build` зелёный, `go vet ./...` чистый.
- [ ] Commit `feat: main-композиция`.

### Task 15: деплой и E2E

**Files:** Create: `Dockerfile` (multi-stage golang:1.25-alpine → gcr.io/distroless/static, CGO_DISABLED, копирует migrations через embed), `docker-compose.yml` (twofa + postgres:16-alpine, pgdata volume, ports 8080/1812/1813, env TWOFA_DB_DSN), `deploy/twofa.service`, `README.md` (полный: настройка, MikroTik `/radius add ... service=ppp login`, PAP-примечание, API-примеры curl, привязка Telegram/TOTP/passkey, миграция RP ID).
**E2E (integration-тест `e2e_test.go`, build tag):** поднять compose-less: тестовый сервер in-process на ephemeral портах + testcontainer PG → полный цикл: bootstrap admin → /login → создать юзера → /me TOTP enroll+confirm (код из расшифрованного secret) → auth/start(totp)+verify → combined → RADIUS пароль+код → telegram push (fake API) approve → RADIUS accept.
- [ ] Вручную проверить: `docker compose up` поднимается, /healthz 200.
- [ ] Commit `feat: деплой+e2e`. Финальный тег `v0.1.0`.

---

## Self-review

- Spec coverage: §2 слушатели (T1,T12,T14), §3.1 сплит+троттлинг (T7,T12), §3.2 API (T10), §3.3 UI (T11,T13), §3.4 reply-атрибуты (T12), §3.5 webauthn (T9), §3.6 telegram (T8), §3.7 устройства (T11), §4 каналы (T6), §5 таблицы (T2), §6 безопасность (T3,T4,T7,T11), §7 API (T10,T11), §8 settings (T4), §9 структура (все), §10 деплой (T15), §11 тесты (в каждой задаче+T15), §12 риски (push-fatigue T7/T8, fallback T7, RP ID — README T15). Пробелов нет.
- Типы/имена согласованы: `Channel`, `store.Challenge.PushState`, `settings.M.Get()`, `Core.RADIUSAuth` используются одинаково в T7/T8/T10/T12.
