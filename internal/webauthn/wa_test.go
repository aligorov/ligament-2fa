// Юнит-тесты webauthn-сервиса без БД: конфигурация RP, мапперы учётных
// данных, адаптер пользователя. Пути с хранилищем — wa_integration_test.go
// (тег integration), полные церемонии — E2E в T15.
package webauthn

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

// TestNewWebAuthnEmptyRPID: пустой RPID отклоняется самим сервисом
// (go-webauthn.New его не требует, но церемонии без домена невозможны).
func TestNewWebAuthnEmptyRPID(t *testing.T) {
	if _, err := newWebAuthn("twofa", "", nil); err == nil {
		t.Fatal("пустой RPID: ожидалась ошибка, получен nil")
	}
}

// TestNewWebAuthnOrigins: displayName по умолчанию и оба варианта origin.
func TestNewWebAuthnOrigins(t *testing.T) {
	w, err := newWebAuthn("", "2fa.example.com", nil)
	if err != nil {
		t.Fatalf("newWebAuthn: %v", err)
	}
	if w.Config.RPDisplayName != defaultRPName {
		t.Errorf("RPDisplayName = %q, want дефолт %q", w.Config.RPDisplayName, defaultRPName)
	}
	if w.Config.RPID != "2fa.example.com" {
		t.Errorf("RPID = %q, want 2fa.example.com", w.Config.RPID)
	}
	want := []string{"https://2fa.example.com", "http://2fa.example.com"}
	if !reflect.DeepEqual(w.Config.RPOrigins, want) {
		t.Errorf("RPOrigins = %v, want %v", w.Config.RPOrigins, want)
	}
}

// TestNewWebAuthnBadRPID: недоменное RPID отклоняет protocol.ValidateRPID.
func TestNewWebAuthnBadRPID(t *testing.T) {
	if _, err := newWebAuthn("twofa", "not a domain", nil); err == nil {
		t.Fatal("битый RPID: ожидалась ошибка, получен nil")
	}
}

// TestResolveOrigins: явный webauthn.origins заменяет выведенные из RPID
// (нестандартный порт localhost:8080), нормализует хвостовой слэш и
// отклоняет не-origin значения (нет схемы/хоста, есть путь).
func TestResolveOrigins(t *testing.T) {
	// Пусто — вывод обоих схем из RPID (поведение по умолчанию).
	got, err := resolveOrigins("2fa.example.com", nil)
	if err != nil {
		t.Fatalf("resolveOrigins(nil): %v", err)
	}
	if want := []string{"https://2fa.example.com", "http://2fa.example.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("derived = %v, want %v", got, want)
	}

	// Явный список с портом — используется как есть.
	got, err = resolveOrigins("localhost", []string{"http://localhost:8080"})
	if err != nil {
		t.Fatalf("resolveOrigins(explicit): %v", err)
	}
	if want := []string{"http://localhost:8080"}; !reflect.DeepEqual(got, want) {
		t.Errorf("explicit = %v, want %v", got, want)
	}

	// Хвостовой слэш срезается, пробелы вокруг — тоже.
	got, err = resolveOrigins("localhost", []string{" https://localhost:8443/ "})
	if err != nil {
		t.Fatalf("resolveOrigins(normalize): %v", err)
	}
	if want := []string{"https://localhost:8443"}; !reflect.DeepEqual(got, want) {
		t.Errorf("normalized = %v, want %v", got, want)
	}

	// Некорректные: без схемы, без хоста, с путём.
	for _, bad := range []string{"localhost:8080", "https://", "ftp://x", "https://x/login", ""} {
		if _, err := resolveOrigins("localhost", []string{bad}); err == nil {
			t.Errorf("origin %q: ожидалась ошибка, получен nil", bad)
		}
	}
}

// TestNewNoSnapshot: New с менеджером без загруженного снимка даёт ошибку,
// не паникует.
func TestNewNoSnapshot(t *testing.T) {
	if _, err := New(&store.Store{}, &settings.M{}); err == nil {
		t.Fatal("New без снимка настроек: ожидалась ошибка, получен nil")
	}
	if _, err := New(&store.Store{}, nil); err == nil {
		t.Fatal("New с nil-менеджером: ожидалась ошибка, получен nil")
	}
}

// TestSessionChallengeID: ID детерминирован по handle и различается для
// разных handle.
func TestSessionChallengeID(t *testing.T) {
	a := sessionChallengeID("handle-a")
	if a != sessionChallengeID("handle-a") {
		t.Error("ID не детерминирован для одного handle")
	}
	if a == sessionChallengeID("handle-b") {
		t.Error("разные handle дают одинаковый ID")
	}
}

// newTestSvc — сервис с валидным RP без хранилища (для мапперов).
func newTestSvc(t *testing.T) *Svc {
	t.Helper()
	w, err := newWebAuthn("twofa", "2fa.example.com", nil)
	if err != nil {
		t.Fatalf("newWebAuthn: %v", err)
	}
	return &Svc{w: w}
}

// TestCredRoundtrip: toStoreCred → fromStoreCred восстанавливает все поля
// Credential без потерь.
func TestCredRoundtrip(t *testing.T) {
	s := newTestSvc(t)
	aaguid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	orig := gowebauthn.Credential{
		ID:                []byte("credential-id-123"),
		PublicKey:         []byte{0xa5, 0x01, 0x02, 0x03},
		AttestationType:   "none",
		AttestationFormat: "packed",
		Transport:         []protocol.AuthenticatorTransport{"usb", "nfc", "hybrid"},
		Flags: gowebauthn.CredentialFlags{
			UserPresent: true, UserVerified: true,
			BackupEligible: true, BackupState: false,
		},
		Authenticator: gowebauthn.Authenticator{
			AAGUID:       aaguid,
			SignCount:    4711,
			CloneWarning: false,
			Attachment:   protocol.CrossPlatform,
		},
	}

	wc := s.toStoreCred(uuid.MustParse("11111111-2222-4333-8444-555555555555"), &orig, "YubiKey 5")
	if wc.RPID != "2fa.example.com" {
		t.Errorf("RPID = %q, want 2fa.example.com", wc.RPID)
	}
	if wc.Name != "YubiKey 5" {
		t.Errorf("Name = %q, want YubiKey 5", wc.Name)
	}
	if wc.AAGUID != "01020304-0506-0708-090a-0b0c0d0e0f10" {
		t.Errorf("AAGUID = %q, want каноничный UUID", wc.AAGUID)
	}
	if wc.Transports != "usb,nfc,hybrid" {
		t.Errorf("Transports = %q, want usb,nfc,hybrid", wc.Transports)
	}
	if wc.Attachment != "cross-platform" || wc.AttestationType != "none" || wc.AttestationFormat != "packed" {
		t.Errorf("строковые поля: %+v", wc)
	}
	if !wc.Present || !wc.Verified || !wc.BackupEligible || wc.BackupState {
		t.Errorf("флаги: %+v", wc)
	}

	got := fromStoreCred(*wc)
	if !bytes.Equal(got.ID, orig.ID) || !bytes.Equal(got.PublicKey, orig.PublicKey) {
		t.Errorf("ID/PublicKey не восстановлены: %+v", got)
	}
	if !bytes.Equal(got.Authenticator.AAGUID, aaguid) {
		t.Errorf("AAGUID = %x, want %x", got.Authenticator.AAGUID, aaguid)
	}
	if got.AttestationType != orig.AttestationType || got.AttestationFormat != orig.AttestationFormat {
		t.Errorf("attestation: %+v", got)
	}
	if !reflect.DeepEqual(got.Transport, orig.Transport) {
		t.Errorf("Transport = %v, want %v", got.Transport, orig.Transport)
	}
	if got.Flags != orig.Flags {
		t.Errorf("Flags = %+v, want %+v", got.Flags, orig.Flags)
	}
	if got.Authenticator.SignCount != orig.Authenticator.SignCount ||
		got.Authenticator.CloneWarning != orig.Authenticator.CloneWarning ||
		got.Authenticator.Attachment != orig.Authenticator.Attachment {
		t.Errorf("Authenticator = %+v, want %+v", got.Authenticator, orig.Authenticator)
	}
}

// TestCredRoundtripEmpty: пустые transports/AAGUID/attachment переживают
// круг без паники и лишних элементов.
func TestCredRoundtripEmpty(t *testing.T) {
	s := newTestSvc(t)
	orig := gowebauthn.Credential{ID: []byte("x"), PublicKey: []byte("pk")}
	wc := s.toStoreCred(uuid.Nil, &orig, "")
	got := fromStoreCred(*wc)
	if len(got.Transport) != 0 {
		t.Errorf("Transport = %v, want пусто", got.Transport)
	}
	if got.Authenticator.AAGUID != nil {
		t.Errorf("AAGUID = %x, want nil", got.Authenticator.AAGUID)
	}
	if wc.AAGUID != "" || wc.Transports != "" || wc.Attachment != "" {
		t.Errorf("плоские поля не пусты: %+v", wc)
	}
}

// TestAAGUIDHelpers: нулевой AAGUID → каноничная строка nil-UUID и обратно.
func TestAAGUIDHelpers(t *testing.T) {
	if got := aaguidToString(make([]byte, 16)); got != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("нулевой AAGUID = %q", got)
	}
	if got := aaguidToString([]byte{1, 2, 3}); got != "" {
		t.Errorf("короткий AAGUID = %q, want пусто", got)
	}
	if got := aaguidBytes("not-a-uuid"); got != nil {
		t.Errorf("битый AAGUID = %x, want nil", got)
	}
}

// TestWaUserAdapter: адаптер отдаёт username и user handle, credentials —
// копией.
func TestWaUserAdapter(t *testing.T) {
	u := &store.User{
		ID:         uuid.MustParse("11111111-2222-4333-8444-555555555555"),
		Username:   "alice",
		WebAuthnID: []byte("handle-32-bytes-random-xxxxxxxx"),
	}
	creds := []gowebauthn.Credential{{ID: []byte("c1")}, {ID: []byte("c2")}}
	a := &waUser{u: u, creds: creds}

	if string(a.WebAuthnID()) != string(u.WebAuthnID) {
		t.Errorf("WebAuthnID = %x", a.WebAuthnID())
	}
	if a.WebAuthnName() != "alice" || a.WebAuthnDisplayName() != "alice" {
		t.Errorf("имена = %q/%q", a.WebAuthnName(), a.WebAuthnDisplayName())
	}
	got := a.WebAuthnCredentials()
	if len(got) != 2 {
		t.Fatalf("credentials: %d, want 2", len(got))
	}
	// Возвращённый срез — копия: мутация не видна адаптеру.
	got[0].ID = []byte("mutated")
	if string(a.creds[0].ID) != "c1" {
		t.Error("WebAuthnCredentials вернула не копию")
	}
}
