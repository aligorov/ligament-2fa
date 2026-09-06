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
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aligorov/twofa/internal/api"
	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/backup"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/delivery"
	"github.com/aligorov/twofa/internal/license"
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

func main() {
	dsnFlag := flag.String("dsn", "", "PostgreSQL DSN (приоритет над env TWOFA_DB_DSN)")
	addrFlag := flag.String("addr", "", "адрес HTTP-слушателя (переопределяет listen.http)")
	backupFlag := flag.String("backup", "", "логический дамп БД в SQL: путь файла или «-» (stdout); восстановление — psql (README «Бэкап и перенос»)")
	backupAuditFlag := flag.Bool("backup-audit", true, "включать audit_log в дамп -backup (false — переносить без журнала событий)")
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
	box, err := secrets.NewBox(m.Get().MasterKeyB64)
	if err != nil {
		slog.Error("main: мастер-ключ", "error", err)
		os.Exit(1)
	}
	if err := bootstrapAdmin(ctx, st); err != nil {
		slog.Error("main: бутстрап администратора", "error", err)
		os.Exit(1)
	}

	// Лицензирование: первый старт отмечает начало 30-дневного демо
	// (персист в БД, сбрасывается только с ней; загрузка лицензии ставит
	// неотзываемый license.trial_used — после удаления лицензии демо не
	// воскрешается); гейт обновлений не пускает
	// сборку новее maintenance_expires лицензии (perpetual-версионный
	// пиннинг, report §3.4). free/trial не ограничены.
	lic := license.NewManager(st)
	if err := lic.Init(ctx); err != nil {
		slog.Error("main: инициализация лицензии", "error", err)
		os.Exit(1)
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
	senders, bot, botToken := rebuildSenders(st, m, nil, "")
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
	rt := api.BuildRouter(api.Deps{
		Core: core, WA: wa, St: st, Box: box, PV: pv, M: m, Rend: rend, Lic: lic,
	})
	defer rt.Stop()

	radius := radiusserver.New(core, st, m)

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
				senders, bot, botToken = rebuildSenders(st, m, bot, botToken)
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
func bootstrapAdmin(ctx context.Context, st *store.Store) error {
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
func rebuildSenders(st *store.Store, m *settings.M, existing *telegram.Bot, existingToken string) (map[channel.Channel]delivery.Sender, *telegram.Bot, string) {
	t := m.Get()
	senders := make(map[channel.Channel]delivery.Sender)

	if t.SMTP.Host != "" {
		senders[channel.Email] = delivery.NewEmail(t.SMTP.Host, t.SMTP.Port, t.SMTP.StartTLS,
			t.SMTP.User, t.SMTP.Password, t.SMTP.From, t.SMTP.Subject,
			t.Messages.EmailBody, t.MessageVars(), t.SMTP.Timeout)
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
		existingToken = t.TG.BotToken
		senders[channel.Telegram] = existing
	}
	return senders, existing, existingToken
}
