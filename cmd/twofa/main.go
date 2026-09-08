// Композиция сервера twofa: подключение к PostgreSQL и миграции, бутстрап
// настроек (генерация master_key/admin_token/radius.secret) и первого
// администратора, сборка ядра аутентификации (каналы доставки, Telegram-бот,
// WebAuthn), HTTP-сервер (JSON API + HTML-страницы + статика) и RADIUS.
// Запуск: SIGINT/SIGTERM — graceful shutdown, SIGHUP — горячая перезагрузка
// настроек: политики/TOTP — сразу, слой доставки (SMTP/SMS/Telegram) —
// пересборкой senders; listen.* и webauthn.rp_id — после рестарта процесса.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aligorov/twofa/internal/acme"
	"github.com/aligorov/twofa/internal/api"
	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/backup"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/firewall"
	"github.com/aligorov/twofa/internal/license"
	"github.com/aligorov/twofa/internal/oidc"
	"github.com/aligorov/twofa/internal/radiusserver"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
	"github.com/aligorov/twofa/internal/telegram"
	"github.com/aligorov/twofa/internal/web"
	"github.com/aligorov/twofa/internal/webauthn"
)

// telegramRestartBackoff — пауза перед перезапуском упавшего бота.
const telegramRestartBackoff = 30 * time.Second

// BuildDate — дата сборки бинарника (YYYY-MM-DD), вшивается
// -ldflags "-X main.BuildDate=$(date +%F)" (Makefile/Dockerfile). Гейт
// обновлений: licensed-сборка новее maintenance_expires лицензии не
// стартует (report §3.4); пустая — сборка без релизной даты, гейт выключен.
var BuildDate string

// VendorAdsJSON — предзаполненные настройки рекламы РСЯ вендорской сборки
// (ключ ads целиком, JSON: enabled/blocks[login_left,login_right,sidebar]
// и опционально oauth_token для статистики). Вшивается в ВЕНДОРСКИЙ билд:
// -ldflags "-X main.VendorAdsJSON='{…}'" (Makefile, переменная ADS_CONFIG);
// в публичном репозитории значение пусто — секретов нет. Применяется один
// раз при первом старте, если реклама ещё не настраивалась.
var VendorAdsJSON string

// seedVendorAds засевает вендорские РСЯ-креды в настройках, когда ключ ads
// ещё не трогали (enabled=false и все ID блоков пусты). Осознанный выбор
// владельца инсталляции позже перезаписывает значения через админку.
func seedVendorAds(ctx context.Context, m *settings.M) {
	if VendorAdsJSON == "" || m == nil {
		return
	}
	snap := m.Get()
	if snap == nil || snap.Ads.Enabled || snap.Ads.Blocks.LoginLeft != "" ||
		snap.Ads.Blocks.LoginRight != "" || snap.Ads.Blocks.Sidebar != "" {
		return // уже настроено (или включено) — не трогаем
	}
	if !json.Valid([]byte(VendorAdsJSON)) {
		slog.Warn("main: VendorAdsJSON не валиден — пропуск")
		return
	}
	if err := m.Put(ctx, "ads", json.RawMessage(VendorAdsJSON)); err != nil {
		slog.Warn("main: засев вендорских РСЯ-кредов не удался", "error", err)
		return
	}
	slog.Info("main: реклама РСЯ преднастроена вендорской сборкой")
}

func main() {
	dsnFlag := flag.String("dsn", "", "PostgreSQL DSN (приоритет над env TWOFA_DB_DSN)")
	addrFlag := flag.String("addr", "", "адрес HTTP-слушателя (переопределяет listen.http)")
	backupFlag := flag.String("backup", "", "логический дамп БД в SQL: путь файла или «-» (stdout); восстановление — psql (README «Бэкап и перенос»)")
	backupAuditFlag := flag.Bool("backup-audit", true, "включать audit_log в дамп -backup (false — переносить без журнала событий)")
	setPassFlag := flag.String("set-password", "", "установить пароль пользователя: -set-password username:password")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	dsn := *dsnFlag
	if dsn == "" {
		dsn = os.Getenv("TWOFA_DB_DSN")
	}
	if dsn == "" {
		slog.Error("main: не задан DSN — укажите флаг -dsn или переменную TWOFA_DB_DSN")
		os.Exit(1)
	}

	// Режим бэкапа: полный логический дамп и выход (сервер не поднимается).
	// Дамп psql-совместим и не содержит master_key — см. README.
	if *backupFlag != "" {
		if err := runBackup(dsn, *backupFlag, *backupAuditFlag); err != nil {
			slog.Error("main: бэкап", "error", err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Хранилище и настройки: Load создаёт отсутствующие ключи, на первом
	// старте генерирует master_key/admin_token/radius.secret.
	st, err := store.Open(ctx, dsn)
	if err != nil {
		slog.Error("main: подключение к БД", "error", err)
		os.Exit(1)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		slog.Error("main: миграции", "error", err)
		os.Exit(1)
	}
	m, err := settings.NewManager(ctx, st)
	if err != nil {
		slog.Error("main: настройки", "error", err)
		os.Exit(1)
	}
	seedVendorAds(ctx, m)

	box, err := secrets.NewBox(m.Get().MasterKeyB64)
	if err != nil {
		slog.Error("main: мастер-ключ", "error", err)
		os.Exit(1)
	}
	if err := bootstrapAdmin(ctx, st, box); err != nil {
		slog.Error("main: бутстрап администратора", "error", err)
		os.Exit(1)
	}

	if *setPassFlag != "" {
		parts := strings.SplitN(*setPassFlag, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			slog.Error("main: формат флага: -set-password username:password")
			os.Exit(1)
		}
		u, err := st.UserByUsername(ctx, parts[0])
		if err != nil {
			slog.Error("main: пользователь не найден", "user", parts[0], "error", err)
			os.Exit(1)
		}
		u.PasswordHash = secrets.HashPassword(parts[1])
		u.PasswordEnc = box.EncryptAAD(u.Username, []byte(parts[1]))
		if err := st.UserUpdate(ctx, u); err != nil {
			slog.Error("main: сохранение пароля", "error", err)
			os.Exit(1)
		}
		slog.Info("main: пароль пользователя успешно обновлен", "user", u.Username)
		return
	}

	// Лицензирование: первый старт отмечает начало 30-дневного демо
	// (персист в БД, сбрасывается только с ней; загрузка лицензии ставит
	// неотзываемый license.trial_used — после удаления лицензии демо не
	// воскрешается); гейт обновлений не пускает
	// сборку новее maintenance_expires лицензии (perpetual-версионный
	// пиннинг, report §3.4). free/trial не ограничены.
	lic := license.NewManager(st)

	// Рекламная подпись email/Telegram: только free/trial и при
	// заполненном ads.message_footer; {url} — случайная ссылка пула.
	adLine := func() string {
		snap := m.Get()
		if snap == nil || !snap.Ads.Enabled || snap.Ads.MessageFooter == "" {
			return ""
		}
		if lic != nil {
			ctxQ, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if st, err := lic.Effective(ctxQ); err == nil && st.Mode == license.ModeLicensed {
				return ""
			}
		}
		footer := snap.Ads.MessageFooter
		pool := snap.Ads.Direct.URLs
		if len(pool) == 0 && snap.Ads.Direct.URL != "" {
			pool = []string{snap.Ads.Direct.URL}
		}
		if len(pool) > 0 {
			footer = strings.ReplaceAll(footer, "{url}", pool[rand.Intn(len(pool))])
		}
		return footer
	}
	licStatus, err := lic.Effective(ctx)
	if err != nil {
		slog.Error("main: чтение состояния лицензии", "error", err)
		os.Exit(1)
	}
	if err := license.CheckBuildAllowed(BuildDate, licStatus); err != nil {
		slog.Error("main: " + err.Error())
		os.Exit(1)
	}
	slog.Info("main: лицензия", "mode", string(licStatus.Mode),
		"user_limit", licStatus.UserLimit, "build_date", BuildDate)

	// Каналы доставки кодов и Telegram-бот (он же PushNotifier).
	// botToken — токен, из которого собран текущий бот (для повторного
	// использования при неизменном токене после SIGHUP).
	senders, bot, botToken := rebuildSenders(st, m, nil, "", adLine)
	var push auth.PushNotifier
	if bot != nil {
		push = bot
	}
	// Первый фактор: локальный argon2id + внешний каталог LDAP/AD
	// (CompositeVerifier). Конфигурация LDAP читается из снимка настроек
	// при каждой проверке — SIGHUP применяется без пересборки.
	pvLocal := auth.NewLocalVerifier(st)
	pv := auth.NewCompositeVerifier(st, pvLocal, auth.NewLdapVerifier(st, m))
	core := auth.NewCore(st, m, box, senders, pv, push)
	guard := firewall.New(st, m)
	core.SetFirewall(guard)

	// WebAuthn необязателен: без webauthn.rp_id сервер работает, роуты
	// отвечают 503 (смена RPID требует рестарта — как listen.*).
	wa, err := webauthn.New(st, m)
	if err != nil {
		slog.Warn("main: WebAuthn выключен", "error", err)
		wa = nil
	}
	waRPID := m.Get().WebAuthn.RPID
	waOrigins := fmt.Sprint(m.Get().WebAuthn.Origins)

	rend, err := web.New()
	if err != nil {
		slog.Error("main: шаблоны web-интерфейса", "error", err)
		os.Exit(1)
	}
	web.SetLocationFunc(func() *time.Location {
		return m.Get().Location()
	})
	// OIDC Provider: ключ подписи ID-токенов читается из настроек
	// (oidc.keys) и при первом старте генерируется и сохраняется.
	oidcMgr, err := oidc.NewManager(ctx, st, m, rend)
	if err != nil {
		slog.Error("main: OIDC-провайдер", "error", err)
		os.Exit(1)
	}
	radius := radiusserver.New(core, st, m)
	radius.SetFirewall(guard)

	// Сертификат EAP-TTLS (WPA2/WPA3-Enterprise): self-signed пара
	// создаётся при первом старте и хранится в настройках (radius.eap_cert)
	// или читается из файлов radius.cert_file / radius.key_file.
	if err := radius.EnsureEAPCert(ctx); err != nil {
		slog.Warn("main: сертификат EAP-TTLS не создан — 802.1X временно отключён", "error", err)
	}

	acmeMgr := acme.NewManager(acme.Config{
		GetSettings: func() (bool, string, string, bool) {
			s := m.Get().ACME
			return s.Enabled, s.Domain, s.Email, s.Staging
		},
		CurrentCertPEM: func() []byte {
			return radius.CurrentEAPCertPEM()
		},
		OnCertRenewed: func(ctx context.Context, certPEM, keyPEM []byte) error {
			tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return fmt.Errorf("разбор полученного сертификата: %w", err)
			}
			radius.SetEAPCertificate(&tlsCert, certPEM)
			payload, err := json.Marshal(struct {
				CertPEM string `json:"cert_pem"`
				KeyPEM  string `json:"key_pem"`
			}{
				CertPEM: string(certPEM),
				KeyPEM:  string(keyPEM),
			})
			if err != nil {
				return fmt.Errorf("сериализация eap_cert: %w", err)
			}
			if err := m.Put(ctx, "radius.eap_cert", payload); err != nil {
				slog.Error("acme: сохранение radius.eap_cert в настройки", "error", err)
				return err
			}
			slog.Info("acme: новый сертификат успешно установлен для EAP и сохранен в базе")
			return nil
		},
	})
	go acmeMgr.Run(ctx)

	rt := api.BuildRouter(api.Deps{
		Core: core, WA: wa, St: st, Box: box, PV: pv, M: m, Rend: rend, Lic: lic,
		FW: guard, Oidc: oidcMgr, ACME: acmeMgr, Radius: radius,
	})
	defer rt.Stop()

	addr := *addrFlag
	if addr == "" {
		addr = m.Get().Listen.HTTP
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           rt.Handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// SIGHUP — горячая перезагрузка настроек. Политики и параметры TOTP
	// подхватываются снимком; слой доставки (SMTP/SMS/Telegram-бот)
	// пересобирается заново и подменяется в ядре; настройки LDAP читаются
	// верификатором из свежего снимка при каждом входе; listen.* и
	// webauthn.rp_id/origins применяются после рестарта процесса.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				rctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				if err := m.Reload(rctx); err != nil {
					slog.Warn("main: перезагрузка настроек (SIGHUP) не удалась", "error", err)
					cancel()
					continue
				}
				senders, bot, botToken = rebuildSenders(st, m, bot, botToken, adLine)
				var push auth.PushNotifier
				if bot != nil {
					push = bot
				}
				core.SetSenders(senders, push)
				if c := m.Get().WebAuthn; c.RPID != waRPID || fmt.Sprint(c.Origins) != waOrigins {
					slog.Warn("main: webauthn.rp_id/origins изменён — применяется после перезапуска (смена rp_id отвязывает существующие passkeys)")
				}
				slog.Info("main: настройки перечитаны (SIGHUP); доставка пересобрана; listen.* — после рестарта")
				cancel()
			}
		}
	}()

	// Telegram-бот: long polling; краш — перезапуск с backoff 30 с.
	if bot != nil {
		go func() {
			for {
				if err := bot.Run(ctx); err != nil {
					slog.Error("main: telegram-бот остановлен с ошибкой, перезапуск",
						"after", telegramRestartBackoff.String(), "error", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(telegramRestartBackoff):
				}
			}
		}()
	}

	// RADIUS auth+acct: слушатели поднимаются в ListenAndServe, Shutdown —
	// по отмене ctx (grace внутри radiusserver).
	radiusDone := make(chan struct{})
	go func() {
		defer close(radiusDone)
		if err := radius.ListenAndServe(ctx); err != nil {
			slog.Error("main: RADIUS-сервер остановлен с ошибкой", "error", err)
		}
	}()

	// HTTP.
	errCh := make(chan error, 1)
	go func() {
		slog.Info("main: HTTP-слушатель запущен", "addr", addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			slog.Error("main: HTTP-сервер", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		slog.Info("main: сигнал завершения — graceful shutdown")
	}

	shCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shCtx); err != nil {
		slog.Warn("main: HTTP shutdown", "error", err)
	}
	// Даём RADIUS завершить in-flight запросы (grace 30 с внутри).
	select {
	case <-radiusDone:
	case <-time.After(35 * time.Second):
		slog.Warn("main: RADIUS не остановился вовремя, продолжаю")
	}
	rt.Stop()
	slog.Info("main: сервер остановлен")
}

// runBackup выполняет логический дамп БД (twofa -backup): opens store,
// генерирует SQL-скрипт backup.Dump и пишет его в файл out («-» — stdout).
// Файл создаётся с правами 0600: дамп содержит шифротексты TOTP, сессии и
// секреты настроек. Сервер при этом не запускается.
func runBackup(dsn, out string, includeAudit bool) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	st, err := store.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("подключение к БД: %w", err)
	}
	defer st.Close()

	dump, err := backup.Dump(ctx, st.Pool(), backup.Options{IncludeAudit: includeAudit})
	if err != nil {
		return err
	}

	w, closeFn, err := openBackupOutput(out)
	if err != nil {
		return err
	}
	defer closeFn()
	if _, err := w.Write(dump); err != nil {
		return fmt.Errorf("запись дампа в %s: %w", out, err)
	}
	slog.Info("main: бэкап готов", "out", out, "bytes", len(dump), "audit", includeAudit)
	return nil
}

// openBackupOutput открывает приёмник дампа: «-» — стандартный вывод, иначе
// файл с правами 0600 (дамп секретен). Возвращает writer и функцию закрытия.
func openBackupOutput(out string) (io.Writer, func(), error) {
	if out == "-" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("открыть файл дампа %s: %w", out, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// bootstrapAdmin создаёт первого администратора на пустой базе: пароль
// RandomToken(12) печатается в лог ОДИН раз (повторно не восстанавливается —
// только сброс через БД или другого админа).
func bootstrapAdmin(ctx context.Context, st *store.Store, box *secrets.Box) error {
	n, err := st.UserCount(ctx)
	if err != nil {
		return fmt.Errorf("подсчёт пользователей: %w", err)
	}
	if n != 0 {
		return nil
	}
	pwd := secrets.RandomToken(12)
	u := &store.User{
		Username:     "admin",
		Role:         "admin",
		Enabled:      true,
		PasswordHash: secrets.HashPassword(pwd),
	}
	if box != nil {
		u.PasswordEnc = box.EncryptAAD("admin", []byte(pwd))
	}
	if err := st.UserCreate(ctx, u); err != nil {
		return fmt.Errorf("создание администратора: %w", err)
	}
	slog.Info("ADMIN PASSWORD: " + pwd + " (сохраните, больше не покажется)")
	return nil
}

// rebuildSenders собирает каналы доставки кодов из текущего снимка настроек:
// email при настроенном SMTP и SMS при настроенном шлюзе — всегда свежие
// экземпляры (горячая перезагрузка доставки по SIGHUP). Telegram-бот
// переиспользуется при неизменном токене; смена/появление токена требует
// перезапуска (long polling живёт в своей горутине). Возвращает карту
// отправителей, бота и токен, из которого бот собран. Ненастроенные каналы
// просто отсутствуют в карте — Core их пропускает при выборе.
func rebuildSenders(st *store.Store, m *settings.M, existing *telegram.Bot, existingToken string, adLine func() string) (map[channel.Channel]delivery.Sender, *telegram.Bot, string) {
	t := m.Get()
	senders := make(map[channel.Channel]delivery.Sender)

	if t.SMTP.Host != "" {
		senders[channel.Email] = delivery.NewEmail(t.SMTP.Host, t.SMTP.Port, t.SMTP.StartTLS,
			t.SMTP.User, t.SMTP.Password, t.SMTP.From, t.SMTP.Subject,
			t.Messages.EmailBody, t.MessageVars(), adLine, t.SMTP.Timeout)
	}
	if gw, err := t.SMSGateway(); err != nil {
		slog.Warn("main: sms.gateway не разобран — SMS выключен", "error", err)
	} else if gw.URL != "" || gw.Preset != "" {
		senders[channel.SMS] = delivery.NewSMS(delivery.GatewayConfig{
			Preset:      gw.Preset,
			Method:      gw.Method,
			URL:         gw.URL,
			Headers:     gw.Headers,
			Body:        gw.Body,
			ContentType: gw.ContentType,
			Success: delivery.SuccessRule{
				HTTPStatus:   gw.Success.HTTPStatus,
				BodyContains: gw.Success.BodyContains,
				JSONPath:     gw.Success.JSONPath,
				Equals:       gw.Success.Equals,
			},
			TextTpl: t.Messages.SMSText,
			Vars:    t.MessageVars(),
		}, nil)
	}
	switch {
	case t.TG.BotToken == "":
		// Токен убран: канал telegram отключается. Работающий бот не
		// останавливается (push продолжает жить до рестарта).
	case existing != nil && t.TG.BotToken == existingToken:
		senders[channel.Telegram] = existing // токен не менялся — переиспользуем
	case existing != nil:
		slog.Warn("main: токен telegram-бота изменён — требуется перезапуск для telegram; работает прежний бот")
		senders[channel.Telegram] = existing
	default:
		existing = telegram.New(st, m)
		existing.SetAdLine(adLine)
		existingToken = t.TG.BotToken
		senders[channel.Telegram] = existing
	}
	return senders, existing, existingToken
}
