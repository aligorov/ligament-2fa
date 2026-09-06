//go:build integration

// Интеграционные тесты webauthn-сервиса (testcontainers, postgres:16-alpine):
// полное Begin* с реальным хранилищем, негативные ветки Finish* (полные
// церемонии с настоящим аутентификатором — E2E в T15).
// Запуск: go test -tags integration ./internal/webauthn/
package webauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// testRPID — RP для интеграционных тестов.
const testRPID = "2fa.example.com"

var (
	sharedOnce sync.Once
	sharedPG   *tcpostgres.PostgresContainer
	sharedSt   *store.Store
	sharedErr  error
)

// sharedStore возвращает хранилище с применённой схемой; пропускает тест,
// если Docker недоступен (паттерн internal/store/repo_test.go).
func sharedStore(t *testing.T) *store.Store {
	t.Helper()
	if !dockerAvailable() {
		t.Skip("docker недоступен (docker info завершается с ошибкой) — интеграционный тест пропущен")
	}
	sharedOnce.Do(startSharedStore)
	if sharedErr != nil {
		t.Fatalf("подготовка общей тестовой БД: %v", sharedErr)
	}
	return sharedSt
}

func startSharedStore() {
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
		sharedErr = err
		return
	}
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		sharedErr = err
		return
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		sharedErr = err
		return
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		sharedErr = err
		return
	}
	sharedPG, sharedSt = pg, st
}

func dockerAvailable() bool {
	return exec.Command("docker", "info").Run() == nil
}

// TestMain закрывает пул и останавливает контейнер после всех тестов пакета.
func TestMain(m *testing.M) {
	code := m.Run()
	if sharedSt != nil {
		sharedSt.Close()
	}
	if sharedPG != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := sharedPG.Terminate(stopCtx); err != nil {
			os.Stderr.WriteString("остановка тестового контейнера: " + err.Error() + "\n")
		}
		cancel()
	}
	os.Exit(code)
}

// newWAUser создаёт пользователя с уникальным username.
func newWAUser(t *testing.T, st *store.Store) *store.User {
	t.Helper()
	u := &store.User{
		Username:     "wa-" + uuid.NewString()[:12],
		PasswordHash: "$argon2id$test",
		Role:         "user",
		Enabled:      true,
	}
	if err := st.UserCreate(t.Context(), u); err != nil {
		t.Fatalf("создание тестового пользователя: %v", err)
	}
	return u
}

// newWASvc поднимает менеджер настроек, задаёт rp_id и строит сервис.
func newWASvc(t *testing.T, st *store.Store) (*Svc, *settings.M) {
	t.Helper()
	ctx := t.Context()
	m, err := settings.NewManager(ctx, st)
	if err != nil {
		t.Fatalf("settings.NewManager: %v", err)
	}
	if err := m.Put(ctx, "webauthn",
		json.RawMessage(`{"rp_id":"`+testRPID+`","rp_name":"twofa"}`)); err != nil {
		t.Fatalf("запись webauthn.rp_id: %v", err)
	}
	svc, err := New(st, m)
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	return svc, m
}

// creationOpts — разобранные PublicKeyCredentialCreationOptions. Сервис
// отдаёт options верхнего уровня (спека и webauthn.js ждут challenge
// наверху), БЕЗ обёртки protocol.CredentialCreation {"publicKey":…}.
type creationOpts struct {
	RP struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	Challenge              string `json:"challenge"`
	AuthenticatorSelection struct {
		ResidentKey      string `json:"residentKey"`
		UserVerification string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	ExcludeCredentials []struct {
		ID string `json:"id"`
	} `json:"excludeCredentials"`
}

// TestNewEmptyRPIDIntegration: дефолтные настройки (rp_id пуст) → ошибка.
// Независим от порядка тестов: ключ webauthn сбрасывается перед Load,
// Load записывает дефолт {"rp_id":""} заново.
func TestNewEmptyRPIDIntegration(t *testing.T) {
	st := sharedStore(t)
	ctx := t.Context()
	if _, err := st.Pool().Exec(ctx, `DELETE FROM settings WHERE key = 'webauthn'`); err != nil {
		t.Fatalf("сброс ключа webauthn: %v", err)
	}
	m, err := settings.NewManager(ctx, st)
	if err != nil {
		t.Fatalf("settings.NewManager: %v", err)
	}
	if m.Get().WebAuthn.RPID != "" {
		t.Fatalf("дефолтный rp_id = %q, want пусто", m.Get().WebAuthn.RPID)
	}
	if _, err := New(st, m); err == nil {
		t.Fatal("New с пустым webauthn.rp_id: ожидалась ошибка, получен nil")
	}
}

// TestBeginRegisterIntegration: полный Begin — challenge-строка в БД,
// корректные options, ленивая генерация+сохранение webauthn_id.
func TestBeginRegisterIntegration(t *testing.T) {
	st := sharedStore(t)
	ctx := t.Context()
	svc, _ := newWASvc(t, st)
	u := newWAUser(t, st)

	optsJSON, handle, err := svc.BeginRegister(ctx, u)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}
	if handle == "" {
		t.Fatal("handle пуст")
	}

	// users.webauthn_id сгенерирован и сохранён.
	fresh, err := st.UserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if len(fresh.WebAuthnID) != userHandleLen {
		t.Fatalf("webauthn_id: %d байт, want %d", len(fresh.WebAuthnID), userHandleLen)
	}

	// Options верхнего уровня: rp.id, residentKey/UV required, user handle.
	// Обёртки {"publicKey":…} быть не должно (регрессия формы ответа).
	var opts creationOpts
	if err := json.Unmarshal(optsJSON, &opts); err != nil {
		t.Fatalf("opts не JSON: %v\n%s", err, optsJSON)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(optsJSON, &raw); err != nil {
		t.Fatalf("opts не JSON-объект: %v", err)
	}
	if _, wrapped := raw["publicKey"]; wrapped {
		t.Error("options завёрнуты в publicKey — клиент ждёт поля наверху")
	}
	if opts.RP.ID != testRPID || opts.RP.Name != "twofa" {
		t.Errorf("rp = %+v", opts.RP)
	}
	if opts.AuthenticatorSelection.ResidentKey != "required" ||
		opts.AuthenticatorSelection.UserVerification != "required" {
		t.Errorf("authenticatorSelection = %+v", opts.AuthenticatorSelection)
	}
	if opts.User.Name != u.Username || opts.User.DisplayName != u.Username {
		t.Errorf("user = %+v", opts.User)
	}
	userID, err := base64.RawURLEncoding.DecodeString(opts.User.ID)
	if err != nil || !bytes.Equal(userID, fresh.WebAuthnID) {
		t.Errorf("user.id = %q (%v), want webauthn_id", opts.User.ID, err)
	}
	if opts.Challenge == "" {
		t.Error("challenge пуст")
	}

	// Challenge-строка: ChallengeGet по SHA256(handle).
	ch, err := st.ChallengeGet(ctx, sessionChallengeID(handle))
	if err != nil {
		t.Fatalf("ChallengeGet(handle): %v", err)
	}
	if ch.Purpose != purposeWASession || ch.Channel != channel.WebAuthn {
		t.Errorf("purpose/channel = %s/%s", ch.Purpose, ch.Channel)
	}
	if ch.UserID != u.ID {
		t.Errorf("user_id = %s, want %s", ch.UserID, u.ID)
	}
	if !bytes.Equal(ch.CodeHash, secrets.SHA256(handle)) {
		t.Errorf("code_hash != SHA256(handle)")
	}
	if ch.UsedAt != nil {
		t.Error("свежая сессия уже помечена использованной")
	}
	if d := time.Until(ch.ExpiresAt); d < 4*time.Minute || d > sessionTTL+30*time.Second {
		t.Errorf("expires через %s, want ~%s", d, sessionTTL)
	}

	// push_state содержит SessionData, идентичную challenge из options.
	if ch.PushState == nil {
		t.Fatal("push_state (JSON сессии) пуст")
	}
	var session gowebauthn.SessionData
	if err := json.Unmarshal([]byte(*ch.PushState), &session); err != nil {
		t.Fatalf("разбор SessionData: %v", err)
	}
	if session.Challenge != opts.Challenge {
		t.Errorf("session.Challenge = %s, want %s", session.Challenge, opts.Challenge)
	}
	if !bytes.Equal(session.UserID, fresh.WebAuthnID) {
		t.Error("session.UserID != webauthn_id")
	}

	// Повторный Begin даёт новый handle; старая сессия не тронута.
	_, handle2, err := svc.BeginRegister(ctx, u)
	if err != nil {
		t.Fatalf("второй BeginRegister: %v", err)
	}
	if handle2 == handle {
		t.Fatal("два BeginRegister выдали одинаковый handle")
	}

	// Уже зарегистрированный ключ попадает в excludeCredentials.
	wc := &store.WACred{
		CredentialID: []byte("cred-" + uuid.NewString()[:12]),
		RPID:         testRPID,
		PublicKey:    []byte{0x04, 0x01},
	}
	if err := st.WACredUpsert(ctx, u.ID, wc); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}
	optsJSON3, _, err := svc.BeginRegister(ctx, u)
	if err != nil {
		t.Fatalf("BeginRegister с ключом: %v", err)
	}
	var opts3 creationOpts
	if err := json.Unmarshal(optsJSON3, &opts3); err != nil {
		t.Fatalf("opts3: %v", err)
	}
	if len(opts3.ExcludeCredentials) != 1 ||
		opts3.ExcludeCredentials[0].ID != base64.RawURLEncoding.EncodeToString(wc.CredentialID) {
		t.Errorf("excludeCredentials = %+v", opts3.ExcludeCredentials)
	}
}

// TestUserHandleAdoptPersistedIntegration — «двойной клик»: пользователь с
// nil WebAuthnID; первый резолв генерирует и сохраняет handle; у «второй
// вкладки» объект загружен до записи первой — handle в памяти всё ещё nil.
// Второй резолв обязан принять СОХРАНЁННОЕ значение из БД, а не генерировать
// новое: обе церемонии сходятся на одном user handle, значение в БД стабильно.
func TestUserHandleAdoptPersistedIntegration(t *testing.T) {
	st := sharedStore(t)
	ctx := t.Context()
	svc, _ := newWASvc(t, st)
	u := newWAUser(t, st)

	// Первая церемония: генерация + сохранение.
	if _, _, err := svc.BeginRegister(ctx, u); err != nil {
		t.Fatalf("BeginRegister #1: %v", err)
	}
	persisted1, err := st.UserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if len(persisted1.WebAuthnID) != userHandleLen {
		t.Fatalf("webauthn_id: %d байт, want %d", len(persisted1.WebAuthnID), userHandleLen)
	}

	// «Вторая вкладка»: копия пользователя с nil handle в памяти.
	second := *u
	second.WebAuthnID = nil
	optsJSON, _, err := svc.BeginRegister(ctx, &second)
	if err != nil {
		t.Fatalf("BeginRegister #2: %v", err)
	}

	// Вторая церемония приняла сохранённый handle (options + объект).
	var opts creationOpts
	if err := json.Unmarshal(optsJSON, &opts); err != nil {
		t.Fatalf("opts не JSON: %v\n%s", err, optsJSON)
	}
	userID, err := base64.RawURLEncoding.DecodeString(opts.User.ID)
	if err != nil || !bytes.Equal(userID, persisted1.WebAuthnID) {
		t.Fatalf("user.id = %q (%v), want сохранённый webauthn_id", opts.User.ID, err)
	}
	if !bytes.Equal(second.WebAuthnID, persisted1.WebAuthnID) {
		t.Fatal("вторая церемония не приняла сохранённый webauthn_id")
	}

	// Второй вызов ничего не генерировал: значение в БД не изменилось.
	persisted2, err := st.UserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserByID после второго резолва: %v", err)
	}
	if !bytes.Equal(persisted2.WebAuthnID, persisted1.WebAuthnID) {
		t.Fatal("webauthn_id в БД изменился после второго резолва — сгенерирован новый handle")
	}
}

// installWAIDRedirectTrigger детерминированно эмулирует гонку двух первых
// BeginRegister: BEFORE UPDATE триггер подменяет ПЕРВУЮ запись webauthn_id
// пользователя на handle «победителя» — в точности эффект «наша запись
// перезаписана параллельной церемонией сразу после UPDATE» (UserUpdate —
// последний-записавший-побеждает, без WHERE webauthn_id IS NULL). Триггер
// выстреливает только для userID и только при NULL→NOT NULL переходе.
func installWAIDRedirectTrigger(t *testing.T, st *store.Store, userID uuid.UUID, winner []byte) {
	t.Helper()
	const fn = "twofa_test_wa_race_redirect"
	if _, err := st.Pool().Exec(t.Context(), fmt.Sprintf(
		`CREATE OR REPLACE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $fn$
		 BEGIN
		   NEW.webauthn_id := decode('%s', 'hex');
		   RETURN NEW;
		 END $fn$`, fn, hex.EncodeToString(winner))); err != nil {
		t.Fatalf("CREATE FUNCTION перенаправителя webauthn_id: %v", err)
	}
	if _, err := st.Pool().Exec(t.Context(), fmt.Sprintf(
		`CREATE TRIGGER twofa_test_wa_race BEFORE UPDATE ON users
		 FOR EACH ROW
		 WHEN (OLD.webauthn_id IS NULL AND NEW.webauthn_id IS NOT NULL AND OLD.id = '%s')
		 EXECUTE FUNCTION %s()`, userID, fn)); err != nil {
		t.Fatalf("CREATE TRIGGER перенаправителя webauthn_id: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = st.Pool().Exec(cleanupCtx, `DROP TRIGGER IF EXISTS twofa_test_wa_race ON users`)
		_, _ = st.Pool().Exec(cleanupCtx, `DROP FUNCTION IF EXISTS `+fn+`()`)
	})
}

// TestUserHandleRaceAdoptsDBValueIntegration — ядро фикса: при гонке первой
// генерации обе церемонии прочитали пустой webauthn_id и сгенерировали свои
// handle; побеждает последняя запись. Резолв обязан вернуть авторитетный
// handle ИЗ БД (перечитать после UPDATE), а не локально сгенерированный:
// иначе сессия проигравшего embed'ит устаревший handle, его FinishRegister
// навсегда падает на bytes.Equal(user.WebAuthnID(), session.UserID), хотя
// аутентификатор уже создал discoverable credential на устаревшем handle.
func TestUserHandleRaceAdoptsDBValueIntegration(t *testing.T) {
	st := sharedStore(t)
	ctx := t.Context()
	svc, _ := newWASvc(t, st)
	u := newWAUser(t, st)

	// Handle «победителя гонки»: случайные 32 байта (колонка UNIQUE — значение
	// должно быть уникально и между прогонами теста).
	winner := make([]byte, userHandleLen)
	if _, err := rand.Read(winner); err != nil {
		t.Fatalf("генерация handle победителя: %v", err)
	}
	installWAIDRedirectTrigger(t, st, u.ID, winner)

	// «Проигравшая» церемония: генерирует свой handle, но её UPDATE
	// перезаписывается handle победителя.
	optsJSON, handle, err := svc.BeginRegister(ctx, u)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}

	// Авторитет — БД: после записи хранится handle победителя.
	dbu, err := st.UserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if !bytes.Equal(dbu.WebAuthnID, winner) {
		t.Fatalf("webauthn_id в БД = %x, want winner %x", dbu.WebAuthnID, winner)
	}

	// Церемония обязана использовать БД-handle, а не свой локальный:
	// options и объект пользователя несут авторитетное значение.
	var opts creationOpts
	if err := json.Unmarshal(optsJSON, &opts); err != nil {
		t.Fatalf("opts не JSON: %v\n%s", err, optsJSON)
	}
	userID, err := base64.RawURLEncoding.DecodeString(opts.User.ID)
	if err != nil || !bytes.Equal(userID, dbu.WebAuthnID) {
		t.Fatalf("user.id = %q (%v), want БД webauthn_id %x (handle победителя)", opts.User.ID, err, dbu.WebAuthnID)
	}
	if !bytes.Equal(u.WebAuthnID, dbu.WebAuthnID) {
		t.Fatal("резолв не принял БД webauthn_id в объект пользователя")
	}

	// Сессия церемонии embed'ит тот же авторитетный handle — иначе
	// FinishRegister упадёт на сверке session.UserID.
	ch, err := st.ChallengeGet(ctx, sessionChallengeID(handle))
	if err != nil {
		t.Fatalf("ChallengeGet(handle): %v", err)
	}
	if ch.PushState == nil {
		t.Fatal("push_state (JSON сессии) пуст")
	}
	var session gowebauthn.SessionData
	if err := json.Unmarshal([]byte(*ch.PushState), &session); err != nil {
		t.Fatalf("разбор SessionData: %v", err)
	}
	if !bytes.Equal(session.UserID, dbu.WebAuthnID) {
		t.Fatal("session.UserID != БД webauthn_id — сессия embed'ит устаревший handle")
	}
}

// badBodyRequest — POST с мусорным телом: путь разбора ответа в Finish*.
func badBodyRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "https://"+testRPID+"/webauthn/finish", strings.NewReader("not-json"))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	return r
}

// TestFinishRegisterNegativesIntegration: неизвестный/пустой/чужой/
// истёкший/использованный handle и мусорное тело — ошибки без паники.
func TestFinishRegisterNegativesIntegration(t *testing.T) {
	st := sharedStore(t)
	ctx := t.Context()
	svc, _ := newWASvc(t, st)
	u := newWAUser(t, st)

	// Неизвестный handle.
	err := svc.FinishRegister(ctx, u, "no-such-handle", "key", badBodyRequest(t))
	if err == nil || !errors.Is(err, store.ErrNotFound) {
		t.Errorf("неизвестный handle: err=%v, want обёрнутый ErrNotFound", err)
	}
	// Пустой handle.
	if err := svc.FinishRegister(ctx, u, "", "key", badBodyRequest(t)); err == nil {
		t.Error("пустой handle: ожидалась ошибка")
	}
	// Чужой пользователь.
	_, handle, err := svc.BeginRegister(ctx, u)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}
	other := newWAUser(t, st)
	if err := svc.FinishRegister(ctx, other, handle, "key", badBodyRequest(t)); err == nil ||
		!strings.Contains(err.Error(), "другому пользователю") {
		t.Errorf("чужой пользователь: err=%v", err)
	}
	// Истёкшая сессия.
	_, handle, err = svc.BeginRegister(ctx, u)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}
	if _, err := st.Pool().Exec(ctx,
		`UPDATE challenges SET expires_at = now() - interval '1 second' WHERE id = $1`,
		sessionChallengeID(handle)); err != nil {
		t.Fatalf("истечение сессии: %v", err)
	}
	if err := svc.FinishRegister(ctx, u, handle, "key", badBodyRequest(t)); err == nil ||
		!strings.Contains(err.Error(), "истекла") {
		t.Errorf("истёкшая сессия: err=%v", err)
	}
	// Уже использованная сессия.
	_, handle, err = svc.BeginRegister(ctx, u)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}
	if err := st.ChallengeMarkUsed(ctx, sessionChallengeID(handle)); err != nil {
		t.Fatalf("ChallengeMarkUsed: %v", err)
	}
	if err := svc.FinishRegister(ctx, u, handle, "key", badBodyRequest(t)); err == nil ||
		!strings.Contains(err.Error(), "использована") {
		t.Errorf("использованная сессия: err=%v", err)
	}
	// Валидная сессия, мусорное тело ответа: FinishRegistration отклоняет,
	// сессия погашена (повтор с тем же handle невозможен).
	_, handle, err = svc.BeginRegister(ctx, u)
	if err != nil {
		t.Fatalf("BeginRegister: %v", err)
	}
	if err := svc.FinishRegister(ctx, u, handle, "key", badBodyRequest(t)); err == nil {
		t.Error("мусорное тело: ожидалась ошибка FinishRegistration")
	}
	if err := svc.FinishRegister(ctx, u, handle, "key", badBodyRequest(t)); err == nil ||
		!strings.Contains(err.Error(), "использована") {
		t.Errorf("повторное использование погашенной сессии: err=%v", err)
	}
}

// TestLoginIntegration: BeginLogin без ключей и с ключом, негативные
// ветки FinishLogin.
func TestLoginIntegration(t *testing.T) {
	st := sharedStore(t)
	ctx := t.Context()
	svc, _ := newWASvc(t, st)
	u := newWAUser(t, st)

	// Без ключей вход невозможен.
	if _, _, err := svc.BeginLogin(ctx, u); err == nil ||
		!strings.Contains(err.Error(), "нет зарегистрированных ключей") {
		t.Errorf("BeginLogin без ключей: err=%v", err)
	}
	// Неизвестный handle в FinishLogin.
	if err := svc.FinishLogin(ctx, u, "no-such-handle", badBodyRequest(t)); err == nil ||
		!errors.Is(err, store.ErrNotFound) {
		t.Errorf("FinishLogin неизвестный handle: err=%v", err)
	}

	// С ключом: options корректны, мусорное тело отклоняется.
	wc := &store.WACred{
		CredentialID: []byte("cred-" + uuid.NewString()[:12]),
		RPID:         testRPID,
		PublicKey:    []byte{0x04, 0x02},
		SignCount:    3,
	}
	if err := st.WACredUpsert(ctx, u.ID, wc); err != nil {
		t.Fatalf("WACredUpsert: %v", err)
	}
	optsJSON, handle, err := svc.BeginLogin(ctx, u)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	// PublicKeyCredentialRequestOptions верхнего уровня, без обёртки.
	var assertion struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	}
	if err := json.Unmarshal(optsJSON, &assertion); err != nil {
		t.Fatalf("assertion opts: %v", err)
	}
	if assertion.RPID != testRPID || assertion.UserVerification != "required" || assertion.Challenge == "" {
		t.Errorf("assertion options = %+v", assertion)
	}
	if len(assertion.AllowCredentials) != 1 ||
		assertion.AllowCredentials[0].ID != base64.RawURLEncoding.EncodeToString(wc.CredentialID) {
		t.Errorf("allowCredentials = %+v", assertion.AllowCredentials)
	}
	// Сессия входа хранится как webauthn_session.
	if _, err := st.ChallengeGet(ctx, sessionChallengeID(handle)); err != nil {
		t.Errorf("ChallengeGet(handle): %v", err)
	}
	// Мусорное тело: ошибка, сессия погашена.
	if err := svc.FinishLogin(ctx, u, handle, badBodyRequest(t)); err == nil {
		t.Error("FinishLogin с мусорным телом: ожидалась ошибка")
	}
	if err := svc.FinishLogin(ctx, u, handle, badBodyRequest(t)); err == nil ||
		!strings.Contains(err.Error(), "использована") {
		t.Errorf("повтор FinishLogin: err=%v", err)
	}
}
