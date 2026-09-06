//go:build integration

// Интеграционный roundtrip-тест логического дампа (Docker, testcontainers):
// накат данных (юзеры с кириллицей + TOTP-шифротекст + challenge + setting +
// сессии/устройства/passkeys/аудит со спецсимволами $lig$) → Dump →
// применение файла целиком через pgx Exec в ЧИСТУЮ вторую БД того же
// контейнера → дампы идентичны байт-в-байт, шифротекст TOTP расшифровывается
// мастер-ключом первой БД, последовательности BIGSERIAL живы после setval.
package backup

import (
	"context"
	"encoding/json"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aligorov/twofa/internal/auth"
	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// secondDBName — имя чистой БД для восстановления в том же контейнере.
const secondDBName = "twofa_restore"

func dockerUp() bool { return exec.Command("docker", "info").Run() == nil }

// dsnWithDB заменяет имя базы в DSN postgres://...
func dsnWithDB(t *testing.T, dsn, db string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("разбор DSN %q: %v", dsn, err)
	}
	u.Path = "/" + db
	return u.String()
}

// TestBackupRoundtrip — полный цикл: данные → дамп → чистая БД → идентичность.
func TestBackupRoundtrip(t *testing.T) {
	if !dockerUp() {
		t.Skip("docker недоступен (docker info завершается с ошибкой) — интеграционный тест пропущен")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pg, err := tcpostgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		tcpostgres.WithDatabase("twofa"),
		tcpostgres.WithUsername("twofa"),
		tcpostgres.WithPassword("twofa"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("запуск testcontainer postgres: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		if err := pg.Terminate(stopCtx); err != nil {
			t.Logf("остановка контейнера: %v", err)
		}
	}()
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	// ---- первая БД: схема + настройки + данные ----
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("миграции: %v", err)
	}
	set, err := settings.NewManager(ctx, st)
	if err != nil {
		t.Fatalf("настройки: %v", err)
	}

	// Настройка с кириллицей (jsonb).
	if err := set.Put(ctx, "totp", json.RawMessage(
		`{"issuer":"Ромашка-2FA","digits":8,"period":60,"skew":2}`)); err != nil {
		t.Fatalf("totp override: %v", err)
	}

	box, err := secrets.NewBox(set.Get().MasterKeyB64)
	if err != nil {
		t.Fatalf("box: %v", err)
	}

	chatID := int64(424242)
	u1 := &store.User{
		Username: "иван.петров", Role: "admin", Enabled: true,
		Email: "иван@пример.рф", Phone: "+7 900 000-00-00",
		DisplayName:    "Иван Петров (секрет $lig$ в имени)",
		PasswordHash:   "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		PreferChannels: []channel.Channel{channel.TOTP, channel.Telegram},
		RadiusReply:    map[string]string{"Mikrotik-Group": "vpn-админы"},
		WebAuthnID:     []byte{0x00, 0x01, 0xfe, 0xff},
		Source:         store.SourceLocal,
	}
	if err := st.UserCreate(ctx, u1); err != nil {
		t.Fatalf("UserCreate: %v", err)
	}
	u2 := &store.User{
		Username: "maria", Role: "user", Enabled: true,
		PasswordHash: "x", TelegramChatID: &chatID,
	}
	if err := st.UserCreate(ctx, u2); err != nil {
		t.Fatalf("UserCreate u2: %v", err)
	}

	// TOTP-шифротекст (должен расшифровываться тем же master_key после
	// восстановления).
	totpSecret := []byte("JBSWY3DPEHPK3PXP")
	enc := box.EncryptAAD(auth.AADTOTP(u1.Username), totpSecret)
	if err := st.TOTPSave(ctx, u1.ID, enc, 8, 60); err != nil {
		t.Fatalf("TOTPSave: %v", err)
	}
	if err := st.TOTPConfirm(ctx, u1.ID); err != nil {
		t.Fatalf("TOTPConfirm: %v", err)
	}
	if err := st.BackupReplace(ctx, u1.ID, [][]byte{
		secrets.SHA256("код-1"), secrets.SHA256("код-2")}); err != nil {
		t.Fatalf("BackupReplace: %v", err)
	}

	// Челлендж с push_state (текст) и code_hash (байты).
	pushState := "pending"
	if err := st.ChallengeCreate(ctx, &store.Challenge{
		UserID: u1.ID, Channel: channel.Telegram,
		CodeHash:     secrets.SHA256("12345678"),
		PushState:    &pushState,
		ExpiresAt:    time.Now().Add(5 * time.Minute),
		AttemptsLeft: 5, Purpose: "api",
	}); err != nil {
		t.Fatalf("ChallengeCreate: %v", err)
	}

	if err := st.SessionCreate(ctx, secrets.SHA256("session-token"), u1.ID,
		"csrf-токен", time.Hour); err != nil {
		t.Fatalf("SessionCreate: %v", err)
	}
	if err := st.DeviceCreate(ctx, &store.Device{
		UserID: u1.ID, TokenHash: secrets.SHA256("device-token"),
		UA: "Mozilla/5.0 (кириллица в UA)", IP: "10.0.0.1",
		ExpiresAt: time.Now().Add(720 * time.Hour),
	}); err != nil {
		t.Fatalf("DeviceCreate: %v", err)
	}
	if err := st.WACredUpsert(ctx, u1.ID, &store.WACred{
		CredentialID: []byte{0x00, 0xde, 0xad, 0xbe, 0xef, 0x00},
		RPID:         "2fa.example.com",
		PublicKey:    []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07},
		SignCount:    42, Transports: "usb,nfc", Name: "YubiKey №5",
		Present: true, Verified: true, BackupEligible: true,
	}); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}
	if err := st.Audit(ctx, "иван.петров", "login_ok",
		map[string]any{"note": "строка со $lig$ внутри\nи переносом", "float": 1.5},
		"10.0.0.1", "ok"); err != nil {
		t.Fatalf("Audit: %v", err)
	}

	// ---- дамп ----
	dump1, err := Dump(ctx, st.Pool(), Options{IncludeAudit: true})
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	s1 := string(dump1)

	// Шапка: предупреждение про master_key, транзакция целиком.
	if !strings.HasPrefix(s1, "--") || !strings.Contains(s1, "master_key НЕ входит в дамп") {
		t.Fatalf("шапка дампа не содержит предупреждения о master_key:\n%.200s", s1)
	}
	if !strings.Contains(s1, "BEGIN;") || !strings.HasSuffix(s1, "COMMIT;\n") {
		t.Fatal("дамп не обёрнут в BEGIN;/COMMIT;")
	}
	// Сам master_key в дамп не утёк.
	if strings.Contains(s1, set.Get().MasterKeyB64) {
		t.Fatal("дамп содержит значение master_key")
	}
	for _, frag := range []string{
		"DELETE FROM users;", "INSERT INTO users", "INSERT INTO totp_secrets",
		"INSERT INTO backup_codes", "INSERT INTO challenges", "INSERT INTO sessions",
		"INSERT INTO settings", "INSERT INTO audit_log", "INSERT INTO trusted_devices",
		"INSERT INTO webauthn_credentials", "INSERT INTO schema_migrations",
	} {
		if !strings.Contains(s1, frag) {
			t.Errorf("в дампе нет %q", frag)
		}
	}

	// ---- вторая чистая БД того же контейнера ----
	if _, err := st.Pool().Exec(ctx, `CREATE DATABASE `+secondDBName); err != nil {
		t.Fatalf("создание второй БД: %v", err)
	}
	st2, err := store.Open(ctx, dsnWithDB(t, dsn, secondDBName))
	if err != nil {
		t.Fatalf("store.Open второй БД: %v", err)
	}
	defer st2.Close()
	if err := st2.Migrate(ctx); err != nil {
		t.Fatalf("миграции второй БД: %v", err)
	}
	// Весь файл одним Exec (простой протокол, несколько операторов) — как psql.
	if _, err := st2.Pool().Exec(ctx, s1); err != nil {
		t.Fatalf("применение дампа: %v", err)
	}
	// Повторное применение идемпотентно (DELETE + транзакция).
	if _, err := st2.Pool().Exec(ctx, s1); err != nil {
		t.Fatalf("повторное применение дампа: %v", err)
	}

	// ---- идентичность: дамп второй БД совпадает с первым (после BEGIN; —
	// в шапке таймстамп генерации).
	dump2, err := Dump(ctx, st2.Pool(), Options{IncludeAudit: true})
	if err != nil {
		t.Fatalf("Dump второй БД: %v", err)
	}
	body1 := s1[strings.Index(s1, "BEGIN;"):]
	body2 := string(dump2)
	body2 = body2[strings.Index(body2, "BEGIN;"):]
	if body1 != body2 {
		t.Fatalf("дампы различаются:\n--- первая БД (len %d)\n%s\n--- вторая БД (len %d)\n%s",
			len(body1), body1, len(body2), body2)
	}

	// ---- шифротекст TOTP переносим: расшифровка мастер-ключом первой БД ----
	enc2, digits, period, confirmed, _, err := st2.TOTPGet(ctx, u1.ID)
	if err != nil {
		t.Fatalf("TOTPGet из второй БД: %v", err)
	}
	if digits != 8 || period != 60 || !confirmed {
		t.Fatalf("totp_secrets восстановлена неверно: digits=%d period=%d confirmed=%v", digits, period, confirmed)
	}
	got, err := box.DecryptAAD(auth.AADTOTP(u1.Username), enc2)
	if err != nil {
		t.Fatalf("расшифровка TOTP после восстановления (требуется тот же master_key): %v", err)
	}
	if string(got) != string(totpSecret) {
		t.Fatalf("расшифрованный секрет = %q, want %q", got, totpSecret)
	}

	// ---- точечные проверки данных (кириллица, байты, jsonb) ----
	ru, err := st2.UserByUsername(ctx, "иван.петров")
	if err != nil {
		t.Fatalf("UserByUsername из второй БД: %v", err)
	}
	if ru.DisplayName != u1.DisplayName || ru.Email != u1.Email {
		t.Fatalf("кириллица не перенеслась: %+v", ru)
	}
	if string(ru.WebAuthnID) != string(u1.WebAuthnID) {
		t.Fatalf("webauthn_id: %x, want %x", ru.WebAuthnID, u1.WebAuthnID)
	}
	if ru.RadiusReply["Mikrotik-Group"] != "vpn-админы" {
		t.Fatalf("radius_reply: %+v", ru.RadiusReply)
	}
	if _, err := st2.UserByUsername(ctx, "maria"); err != nil {
		t.Fatalf("второй пользователь не восстановлен: %v", err)
	}

	// ---- последовательности BIGSERIAL живы (setval) ----
	if err := st2.Audit(ctx, "post-restore", "probe", nil, "", "ok"); err != nil {
		t.Fatalf("вставка в audit_log после восстановления (setval?): %v", err)
	}

	// ---- дамп без аудита ----
	noAudit, err := Dump(ctx, st.Pool(), Options{IncludeAudit: false})
	if err != nil {
		t.Fatalf("Dump без аудита: %v", err)
	}
	if strings.Contains(string(noAudit), "INSERT INTO audit_log") {
		t.Fatal("IncludeAudit=false не исключил audit_log")
	}
	if strings.Contains(string(noAudit), "DELETE FROM audit_log;") {
		t.Fatal("IncludeAudit=false не должен трогать audit_log вовсе")
	}
}
