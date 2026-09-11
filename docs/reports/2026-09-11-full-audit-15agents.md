# Полный аудит проекта — 15 агентов по подсистемам (2026-09-11)

Контекст: HEAD `7f8df5f`, релиз v0.4.69 (RDP 2FA работает). 15 параллельных
ревью-агентов (только чтение), каждый — своя подсистема, вывод — только
доказанные P0/P1 с file:line. Сводка ниже; формулировки сжаты до сути.

## Вердикты по подсистемам

| # | Подсистема | Вердикт | P0 | P1 |
|---|---|---|---|---|
| 1 | Auth core | **СРОЧНО** | 1 | 2 |
| 2 | RADIUS (PAP/EAP) | ВНИМАНИЕ | 0 | 4 |
| 3 | OIDC Provider | ВНИМАНИЕ | 0 | 1 |
| 4 | Лицензирование | ВНИМАНИЕ | 0 | 1 |
| 5 | Store/миграции | ВНИМАНИЕ | 0 | 2 |
| 6 | HTTP API/Admin | ВНИМАНИЕ | 0 | 1 (+3 набл.) |
| 7 | Delivery (email/SMS/TG/WS) | ВНИМАНИЕ | 0 | 1 |
| 8 | Firewall/fail2ban | ВНИМАНИЕ | 0 | 3 |
| 9 | Web UI/CSP | ВНИМАНИЕ | 0 | 2 |
| 10 | Flutter-клиент | ВНИМАНИЕ | 0 | 3 |
| 11 | Windows CP | ВНИМАНИЕ | 0 | 5 |
| 12 | Крипто/TOTP | ВНИМАНИЕ | 0 | 1 |
| 13 | Backup/restore | **СРОЧНО** | 1 | 0 |
| 14 | Bootstrap/CI/Deploy | ВНИМАНИЕ | 0 | 1 |
| 15 | Тесты/контракты | ВНИМАНИЕ | 0 | 4 |

---

## P0 — критично (2)

### P0-1. Обход 2FA через `/api/v1/app/login` (Auth core)
`internal/api/app.go:210-331` — вход в приложение (`POST /api/v1/app/login`)
проверяет ТОЛЬКО пароль (`pv.Verify`) и сразу выдаёт device-токен с правом
**approve** push-челленджей (`Active: true`, TTL 90д). Полная цепочка одним
паролем, без второго фактора: login → `/auth/start` (number_match приходит в
ответе) → `GET /app/challenges/pending` → `POST /app/challenges/{id}/decision
approve` → `push_claim` в web-логине (пароль не проверяется) → сессия.
2FA вырождается в пароль для любого аккаунта.
**Фикс:** требовать код второго фактора в app/login (`VerifyAnyCode` с
LoginCodePurposes) либо энроллить устройство только из аутентифицированной
web-сессии / по одноразовому инвайту.

### P0-2. Restore из бэкапа убивает master_key (Backup)
`internal/backup/backup.go:141` — дамп эмитит безусловный
`DELETE FROM settings;`, при этом INSERT строк settings генерируется БЕЗ
`master_key`. Восстановление на живую инсталляцию (штатный DR-путь из README)
удаляет ключ; при следующей загрузке `generatedKeys` молча создаёт НОВЫЙ — все
`totp_secrets.secret_enc` и `users.password_enc` (AES-GCM под старым ключом)
становятся мусором. Тихий отложенный отказ 2FA/PEAP. Интеграционный тест
восстанавливает в чистую БД — не ловит.
**Фикс:** `DELETE FROM settings WHERE key <> 'master_key';`

---

## P1 — важно (по подсистемам)

### Auth core
1. `app.go:584-591` — **number_match перебор**: несовпадение не расходует
   attempts, не гасит челлендж, decision-эндпоинт без rate-limit; 2 цифры =
   100 вариантов за TTL 5 мин (подтверждено независимо агентами 1 и 12).
   Фикс: гасить челлендж после 1–3 промахов (по образцу support-флоу) +
   rate-limit на decision.
2. `core.go:899-918` — `livePendingPush` без purpose-фильтра: RADIUS
   резюмирует и потребляет approval ЧУЖОГО web-челленджа (purpose='api').
   Фикс: `AND purpose NOT IN ('api','ui_confirm','tg_link')`.

### RADIUS
1. `eapauth.go:716-718` — PEAP без `UserEffectiveRadiusPush`: верный пароль →
   Access-Accept БЕЗ второго фактора (PAP/TTLS тому же юзелю Reject). Wi-Fi по
   умолчанию = 1FA на самом массовом методе. Фикс: убрать ветку password_ok.
2. `eapauth.go:812` — user enumeration: внутренняя причина отказа уходит
   клиенту в `M=` MSCHAPv2-failure + тайминг-различие веток. Фикс: статическое
   `E=691 R=0`, выровнять стоимость.
3. `eapauth.go:240-253` — `pendingInner` без капа и без TTL: memory DoS при
   неполных AVP-блоках в поднятом TLS-туннеле. Фикс: лимит размера.
4. `eapsession.go:199-207` — гонки на общей EAP-сессии (библиотека зовёт
   хендлер в горутине на пакет; разные Identifier = конкурентный доступ к
   состоянию). Фикс: `sync.Mutex` на сессию.

### OIDC
1. `pages.go:409-414` + `static/webauthn.js:325` — обход safeNext через `/\`:
   `Location: /\evil.com` / `window.location.href="/\evil.com"` = открытый
   редирект после логина. Фикс: `strings.Contains(next,"\\")` → reject +
   та же проверка в JS.

### Лицензирование
1. `internal/auth/ldap.go:313` — LDAP-автопровижининг создаёт пользователей
   без проверки лимита лицензии (проверка есть только в admin/pages). Обход
   free=5. Фикс: колбэк-проверка лицензии в ветке create.

### Store
1. `support.go:246-263` + `app.go:858-896` — залежавшаяся (>15 мин) заявка
   навсегда блокирует создание нового обращения (unique index + stale-фильтр
   расходятся; sweep только из GET /support/current). Фикс: при 23505
   переводить stale live-строки в expired и ретраить INSERT.
2. `support.go:514-549` — SupportSessionConnect мутирует ЧУЖУЮ сессию
   (перезаписывает number_match, сбрасывает счётчик попыток) до проверки
   владения. Фикс: условие владения в самом UPDATE.

### HTTP API/Admin
1. `admin.go:2054-2095` (signal) и `admin.go:2472-2551` (операторский WS) —
   без проверки категории/назначения: инженер категории «1c» шлёт WebRTC-сигналы
   в чужую «it»-сессию, в т.ч. неподтверждённую. Фикс: проверка как в connect.
2. Наблюдения: `?token=` (device-токен) принимается на нестимовых JSON-запросах
   (`admin.go:2388,2450`; `isStreamRequest` определён по заголовкам,
   `ratelimit.go:156-161` — `Upgrade: foo` на JSON открывает query-аутентификацию);
   `Access-Control-Allow-Origin: *` на SSE (`app.go:792`); `/auth/verify` без
   purpose-фильтра (`public.go:310`).

### Delivery
1. `email.go:84-100,147-165` — SMTP без дедлайнов: зависший сервер оставляет
   вечную горутину+коннект на каждую отправку. Фикс: dialer timeout +
   SetDeadline.

### Firewall
1. `server.go:273` + `core.go:627` — **самобан NAS**: PAP-неудачи считаются по
   IP маршрутизатора → 10 опечаток за 5 мин банят NAS на 30 мин ВСЕМ
   пользователям. Фикс: не подавать radius_fail в IP-счётчик (ключ по
   username/Calling-Station-Id).
2. `eapauth.go:689,711` — EAP-неудачи вообще не кормят fail2ban (пишут audit
   в обход core.audit).
3. `store/firewall.go:100-123` — ip_bans без ретеншна: неограниченный рост
   (ротация IPv6 /64). Фикс: ежедневная чистка просроченных.

### Web UI
1. `router.go:41-57,200` — ads-CSP применяется ко ВСЕМ ответам (включая
   админку), если настроен хоть один слот: `unsafe-inline` + сторонние скрипты
   Яндекса в авторизованной сессии. Фикс: per-page решение по фактически
   отрендеренным слотам.
2. Наблюдение: branding.logo сломан (data:URI → `#ZgotmplZ`, https-URL режет
   строгая CSP img-src) — белый лейбл фактически не показывает свой логотип.

### Flutter
1. `support_operator_screen.dart:176` — device-токен в query WS-URL (оседает в
   логах прокси), хотя сервер принимает Bearer. Фикс: headers.
2. `auth_state.dart:461,471,481,710` — 401 в течение сессии проглатывается:
   «зомби»-сессия при истечении/ревокации токена. Фикс: logout по 401.
3. `auth_state.dart:502-505` — челлендж помечается resolved ДО отправки
   решения: сетевой сбой = потерянное подтверждение, запрос исчезает из UI.
   Фикс: помечать после успешного await.

### Windows CP
1. `LigamentCredential.cpp:723-745` — **sam-probe амплифицирует лок-аут x3**
   (каждый промах пароля = +2..3 к счётчику SAM; при пороге ≤4 вторая попытка
   блокирует учётку; выполняется даже при STATUS_LOCKED_OUT). Фикс: одна проба
   `L"."`, флаг `SamProbeEnabled` (по умолчанию выкл), skip при 0xC0000234.
2. `LigamentCredential.cpp:290` — `m_password = psz` без затирания старого
   буфера (префиксы пароля в куче при перенаборе). Фикс: zero-before-assign.
3. `:159-163,508-517` — SetDeselected/ResetAuthState не затирают пароль.
4. `HttpApiClient.cpp:152,220,250` — UTF-8 копии пароля не затираются после
   отправки.
5. `common.h:120-137` — cp.log: имя пользователя в world-readable файле
   без ротации; разные share-флаги у двух писателей (потери строк). Фикс:
   убрать user= из лога, DACL на каталог, truncate >5МБ, единые флаги.

### Крипто
1. = Auth-1 (number_match без лимита; подтверждено независимо). Плюс
   наблюдение: `bytes.Equal` для хешей кодов вместо constant-time (не
   эксплуатируемо, но непоследовательно).

### Bootstrap/CI
1. `deploy.yml:44` — bootstrap-деплой на чистом сервере падает: curl приватного
   raw-URL без токена → 404 → set -e. Фикс: заголовок Authorization или доставка
   compose отдельно.
2. Наблюдения: `ci.yml go-version '1.24'` при `go.mod 1.27` (пин не работает);
   теоретический race `bot` при старте (main.go:334-362); секреты в рабочем
   дереве (lic.pem, snapshot.json) — в git-индексе НЕ значатся (gitignore
   работает), но старая история могла их сохранить (известный отложенный
   вопрос: filter-repo purge по решению вендора).

### Тесты/контракты
1. `ci.yml:27` — **CI не запускает ни одного интеграционного теста** (нет
   `-tags integration`): 35 файлов вне CI — OIDC code flow, полный EAP-обмен,
   support FSM, license-эндпоинты, LDAP, e2e. Ложная зелёность.
2. OIDC/Guard-интеграция молча skip без TWOFA_TEST_DSN (у остальных
   testcontainers) — даже с тегом покрытие будет дырявым.
3. `GET /ca.crt` вне спеки (контракт-тест исключает не-/api/v1 роуты);
   ACME-роут вообще не собирается в тестовом роутере.
4. Новые секции настроек (fail2ban/ads/branding/proxy) без полевых ассертов
   (TestDefaultsCoverKnownKeys проверяет только наличие ключей).

---

## Что проверено и чисто (короткий список)
- Store: SQL-инъекций нет, UPSERT-гоны закрыты, транзакции корректны, TTL в
  TIMESTAMPTZ/SQL-времени.
- RADIUS: Reply-MA корректен, EAP без MA всегда discard, PAP тайминг-выровнен,
  секрет не утекает.
- OIDC: redirect_uri точный матч, replay кода атомарным UPDATE, PKCE S256 для
  public, constant-time секреты, JWT RS256 зафиксирован.
- Лицензии: canonical JSON верифицируется по переканонизации (не подделать),
  dev-ключ вне прод-сборки (build-tag + тест), CRL до demo-ветки, демо не
  воскрешается.
- API: admin-роуты под RequireAdminToken, IDOR в /me нет, mass assignment
  закрыт IsImportExcluded (все 4 секрета), CSRF двойная отправка везде.
- Delivery: template injection нет ({code} последним, однопроходный подстановщик),
  перекрёстной доставки нет, WS-writer без гонок (race-тесты).
- Firewall: XFF-спуфинг из интернета не работает, IPv6-маппинг канонизирован,
  приоритеты верны (тест).
- WebUI: XSS через шаблоны нет (автоэкранирование, urlFilter), 62/62 POST-форм
  с CSRF.
- Крипто: argon2id 64MiB, GCM со свежим nonce, TOTP CAS-replay,
  crypto/rand везде, master_key не бывает пустым.
- Backup: SQLi через `$$` нет (уникальные теги+тест), лицензия через import не
  обходится, экспорт без 4 секретов.
- Bootstrap: порядок старта корректен, пароль админа только в файле 0600, все
  25 actions запинены SHA, distroless nonroot, порты БД не торчат.
- CP: аварийный вход при падении DLL работает, poll-thread без гонок,
  install.bat чужие настройки не трогает.
