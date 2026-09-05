// Package webauthn — церемонии регистрации и входа WebAuthn/passkey поверх
// go-webauthn. Учётные данные хранятся плоскими колонками
// (webauthn_credentials, паттерн Authelia), сессии церемоний — в таблице
// challenges (purpose=webauthn_session): клиент получает случайный handle,
// по коду SHA256(handle) и детерминированному UUID челленджа сессия
// находится и погашается одноразово.
package webauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/channel"
	"github.com/aligorov/twofa/internal/secrets"
	"github.com/aligorov/twofa/internal/settings"
	"github.com/aligorov/twofa/internal/store"
)

const (
	// defaultRPName — отображаемое имя RP, если настройка webauthn.rp_name пуста.
	defaultRPName = "twofa"
	// purposeWASession — purpose challenges-строки с сессией церемонии.
	purposeWASession = "webauthn_session"
	// sessionTTL — срок жизни сессии церемонии (challenge и client-side таймаут).
	sessionTTL = 5 * time.Minute
	// handleEntropy — случайная энтропия handle церемонии (128 бит, base64url).
	handleEntropy = 16
	// userHandleLen — случайный users.webauthn_id (лимит спеки — 64 байта).
	userHandleLen = 32
)

// waSessionNS — фиксированный namespace: ID challenges-строки выводится из
// handle как uuid v5 поверх SHA-256, поэтому сессия находится штатным
// ChallengeGet без отдельного индекса по code_hash.
var waSessionNS = uuid.MustParse("7f3b9c2e-5a41-4c8f-9b2d-1e6a8d4f0c31")

// Svc — сервис WebAuthn-церемоний. RPID/origins фиксируются при создании:
// их смена требует рестарта процесса (как и listen.*).
type Svc struct {
	w  *gowebauthn.WebAuthn
	st *store.Store
	m  *settings.M
}

// New строит сервис из настроек webauthn.rp_id / webauthn.rp_name.
// RPID обязателен (голый домен RP); origins выводятся в обоих вариантах
// схемы — https для продакшена и http для локальной разработки.
func New(st *store.Store, m *settings.M) (*Svc, error) {
	if m == nil {
		return nil, errors.New("webauthn: менеджер настроек не задан")
	}
	snap := m.Get()
	if snap == nil {
		return nil, errors.New("webauthn: снимок настроек ещё не загружен")
	}
	if snap.WebAuthn.RPID == "" {
		return nil, errors.New("webauthn: настройка webauthn.rp_id обязательна (домен RP, например 2fa.example.com)")
	}
	if st == nil {
		return nil, errors.New("webauthn: хранилище не задано")
	}
	w, err := newWebAuthn(snap.WebAuthn.RPName, snap.WebAuthn.RPID)
	if err != nil {
		return nil, err
	}
	return &Svc{w: w, st: st, m: m}, nil
}

// newWebAuthn валидирует параметры RP и создаёт экземпляр go-webauthn.
func newWebAuthn(displayName, rpid string) (*gowebauthn.WebAuthn, error) {
	if rpid == "" {
		return nil, errors.New("webauthn: RPID не задан")
	}
	if displayName == "" {
		displayName = defaultRPName
	}
	return gowebauthn.New(&gowebauthn.Config{
		RPDisplayName: displayName,
		RPID:          rpid,
		RPOrigins:     rpOrigins(rpid),
	})
}

// rpOrigins — https- и http-варианты origin (scheme+host, без пути и слэша).
func rpOrigins(rpid string) []string {
	return []string{"https://" + rpid, "http://" + rpid}
}

// ---- церемония регистрации ----

// BeginRegister запускает регистрацию нового ключа: требует resident key
// (passkey), user verification и исключает уже зарегистрированные ключи
// пользователя. Возвращает JSON PublicKeyCredentialCreationOptions и handle
// сессии церемонии (одноразовый, живёт sessionTTL).
func (s *Svc) BeginRegister(ctx context.Context, user *store.User) (opts json.RawMessage, handle string, err error) {
	au, err := s.ceremonyUser(ctx, user)
	if err != nil {
		return nil, "", err
	}
	creation, session, err := s.w.BeginRegistration(au,
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		gowebauthn.WithExclusions(
			gowebauthn.Credentials(au.creds).CredentialDescriptors()),
	)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: BeginRegistration(%s): %w", au.WebAuthnName(), err)
	}
	handle, err = s.saveSession(ctx, user.ID, session)
	if err != nil {
		return nil, "", err
	}
	opts, err = json.Marshal(creation)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: кодирование creation options: %w", err)
	}
	return opts, handle, nil
}

// FinishRegister завершает регистрацию: погашает сессию церемонии,
// проверяет ответ аутентификатора и сохраняет учётные данные плоскими
// колонками. name — пользовательская метка ключа ("YubiKey 5").
func (s *Svc) FinishRegister(ctx context.Context, user *store.User, handle, name string, r *http.Request) error {
	session, err := s.claimSession(ctx, user.ID, handle)
	if err != nil {
		return err
	}
	au, err := s.ceremonyUser(ctx, user)
	if err != nil {
		return err
	}
	cred, err := s.w.FinishRegistration(au, *session, r)
	if err != nil {
		return fmt.Errorf("webauthn: FinishRegistration(%s): %w", au.WebAuthnName(), err)
	}
	if err := s.st.WACredUpsert(ctx, user.ID, s.toStoreCred(user.ID, cred, name)); err != nil {
		return err
	}
	detail := map[string]any{"name": name}
	if cred.Authenticator.CloneWarning {
		detail["clone_warning"] = true
	}
	if err := s.st.Audit(ctx, user.Username, "webauthn_enroll", detail, r.RemoteAddr, "ok"); err != nil {
		return err
	}
	if cred.Authenticator.CloneWarning {
		if err := s.st.Audit(ctx, user.Username, "webauthn_clone_warning",
			map[string]any{"credential_id": base64.RawURLEncoding.EncodeToString(cred.ID)},
			r.RemoteAddr, "ok"); err != nil {
			return err
		}
	}
	return nil
}

// ---- церемония входа ----

// BeginLogin запускает вход: только для пользователей с ключами, user
// verification required (вход как второй фактор подтверждает владельца).
func (s *Svc) BeginLogin(ctx context.Context, user *store.User) (opts json.RawMessage, handle string, err error) {
	au, err := s.ceremonyUser(ctx, user)
	if err != nil {
		return nil, "", err
	}
	if len(au.creds) == 0 {
		return nil, "", fmt.Errorf("webauthn: у пользователя %s нет зарегистрированных ключей", au.WebAuthnName())
	}
	assertion, session, err := s.w.BeginLogin(au,
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: BeginLogin(%s): %w", au.WebAuthnName(), err)
	}
	handle, err = s.saveSession(ctx, user.ID, session)
	if err != nil {
		return nil, "", err
	}
	opts, err = json.Marshal(assertion)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: кодирование assertion options: %w", err)
	}
	return opts, handle, nil
}

// FinishLogin завершает вход и ОБЯЗАТЕЛЬНО сохраняет обновлённый счётчик
// подписей — иначе клон-детектор и следующий вход сломаются. Признак
// возможного клона не отклоняет вход, но попадает в аудит отдельным событием.
func (s *Svc) FinishLogin(ctx context.Context, user *store.User, handle string, r *http.Request) error {
	session, err := s.claimSession(ctx, user.ID, handle)
	if err != nil {
		return err
	}
	au, err := s.ceremonyUser(ctx, user)
	if err != nil {
		return err
	}
	cred, err := s.w.FinishLogin(au, *session, r)
	if err != nil {
		return fmt.Errorf("webauthn: FinishLogin(%s): %w", au.WebAuthnName(), err)
	}
	if err := s.st.WACredUpdateSignIn(ctx, cred.ID,
		cred.Authenticator.SignCount, cred.Authenticator.CloneWarning); err != nil {
		return err
	}
	detail := map[string]any{"credential_id": base64.RawURLEncoding.EncodeToString(cred.ID)}
	if cred.Authenticator.CloneWarning {
		detail["clone_warning"] = true
	}
	if err := s.st.Audit(ctx, user.Username, "webauthn_login", detail, r.RemoteAddr, "ok"); err != nil {
		return err
	}
	if cred.Authenticator.CloneWarning {
		if err := s.st.Audit(ctx, user.Username, "webauthn_clone_warning", detail, r.RemoteAddr, "ok"); err != nil {
			return err
		}
	}
	return nil
}

// ---- сессии церемоний в challenges ----

// sessionChallengeID выводит ID challenges-строки из handle: uuid v5
// (SHA-256(namespace || handle), усечён до 128 бит). Handle — 128-битная
// случайность, поэтому ID невозможно перебрать извне.
func sessionChallengeID(handle string) uuid.UUID {
	return uuid.NewHash(sha256.New(), waSessionNS, []byte(handle), 5)
}

// saveSession сериализует SessionData и сохраняет челлендж
// purpose=webauthn_session; JSON сессии занимает единственную свободную
// TEXT-колонку push_state (для telegram_push-строк она хранит состояние
// пуша; строки webauthn_session различаются по purpose и никогда не
// пересекаются с ними — схема заморожена миграцией 0001). Возвращает handle.
func (s *Svc) saveSession(ctx context.Context, userID uuid.UUID, session *gowebauthn.SessionData) (string, error) {
	if session == nil {
		return "", errors.New("webauthn: сессия церемонии пуста")
	}
	raw, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("webauthn: кодирование сессии церемонии: %w", err)
	}
	handle := secrets.RandomToken(handleEntropy)
	payload := string(raw)
	ch := &store.Challenge{
		ID:        sessionChallengeID(handle),
		UserID:    userID,
		Channel:   channel.WebAuthn,
		CodeHash:  secrets.SHA256(handle),
		PushState: &payload,
		ExpiresAt: time.Now().Add(sessionTTL),
		// Одна попытка: сессия гасится даже при неудачном ответе, брутфорс
		// assertion против той же сессии невозможен.
		AttemptsLeft: 1,
		Purpose:      purposeWASession,
	}
	if err := s.st.ChallengeCreate(ctx, ch); err != nil {
		return "", err
	}
	return handle, nil
}

// claimSession находит сессию по handle, проверяет принадлежность
// пользователю, срок и одноразовость, помечает использованной (закрывает
// гонку двойного использования) и декодирует SessionData.
func (s *Svc) claimSession(ctx context.Context, userID uuid.UUID, handle string) (*gowebauthn.SessionData, error) {
	if handle == "" {
		return nil, errors.New("webauthn: handle сессии церемонии пуст")
	}
	ch, err := s.st.ChallengeGet(ctx, sessionChallengeID(handle))
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("webauthn: сессия церемонии неизвестна: %w", err)
	}
	if err != nil {
		return nil, err
	}
	if ch.Purpose != purposeWASession || ch.Channel != channel.WebAuthn {
		return nil, fmt.Errorf("webauthn: challenges-строка %s не является сессией церемонии", ch.ID)
	}
	if ch.UserID != userID {
		return nil, fmt.Errorf("webauthn: сессия церемонии %s принадлежит другому пользователю", ch.ID)
	}
	// handle и хеш сверяются явно: ID детерминирован, но защита от
	// подмены/коллизий — только по code_hash.
	if len(ch.CodeHash) == 0 || !bytes.Equal(ch.CodeHash, secrets.SHA256(handle)) {
		return nil, fmt.Errorf("webauthn: handle не совпадает с сессией церемонии %s", ch.ID)
	}
	if ch.UsedAt != nil {
		return nil, fmt.Errorf("webauthn: сессия церемонии %s уже использована", ch.ID)
	}
	if !time.Now().Before(ch.ExpiresAt) {
		return nil, fmt.Errorf("webauthn: сессия церемонии %s истекла", ch.ID)
	}
	if err := s.st.ChallengeMarkUsed(ctx, ch.ID); err != nil {
		return nil, fmt.Errorf("webauthn: погасить сессию церемонии %s: %w", ch.ID, err)
	}
	payload := ""
	if ch.PushState != nil {
		payload = *ch.PushState
	}
	var session gowebauthn.SessionData
	if err := json.Unmarshal([]byte(payload), &session); err != nil {
		return nil, fmt.Errorf("webauthn: разбор сессии церемонии %s: %w", ch.ID, err)
	}
	return &session, nil
}

// ---- адаптер пользователя и мапперы учётных данных ----

// ceremonyUser готовит адаптер: гарантирует наличие users.webauthn_id
// (ленивая генерация с сохранением) и загружает ключи пользователя из БД.
func (s *Svc) ceremonyUser(ctx context.Context, user *store.User) (*waUser, error) {
	if user == nil || user.ID == uuid.Nil {
		return nil, errors.New("webauthn: пользователь не задан")
	}
	if len(user.WebAuthnID) == 0 {
		if err := s.genUserHandle(ctx, user); err != nil {
			return nil, err
		}
	}
	wacreds, err := s.st.WACredListForUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	creds := make([]gowebauthn.Credential, len(wacreds))
	for i, wc := range wacreds {
		creds[i] = fromStoreCred(wc)
	}
	return &waUser{u: user, creds: creds}, nil
}

// genUserHandle генерирует и сохраняет users.webauthn_id. Пишется ровно это
// поле: из БД берётся свежая копия пользователя, чтобы не затереть
// параллельные изменения остальных колонок.
func (s *Svc) genUserHandle(ctx context.Context, user *store.User) error {
	fresh, err := s.st.UserByID(ctx, user.ID)
	if err != nil {
		return err
	}
	if len(fresh.WebAuthnID) > 0 {
		user.WebAuthnID = fresh.WebAuthnID
		return nil
	}
	id := make([]byte, userHandleLen)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("webauthn: генерация webauthn_id: %w", err)
	}
	fresh.WebAuthnID = id
	if err := s.st.UserUpdate(ctx, fresh); err != nil {
		return err
	}
	user.WebAuthnID = id
	return nil
}

// toStoreCred переводит свежий Credential в плоскую строку
// webauthn_credentials; transports склеиваются через запятую.
func (s *Svc) toStoreCred(userID uuid.UUID, c *gowebauthn.Credential, name string) *store.WACred {
	transports := make([]string, len(c.Transport))
	for i, t := range c.Transport {
		transports[i] = string(t)
	}
	return &store.WACred{
		CredentialID:      c.ID,
		RPID:              s.w.Config.RPID,
		PublicKey:         c.PublicKey,
		SignCount:         c.Authenticator.SignCount,
		CloneWarning:      c.Authenticator.CloneWarning,
		AAGUID:            aaguidToString(c.Authenticator.AAGUID),
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFormat,
		Attachment:        string(c.Authenticator.Attachment),
		Transports:        strings.Join(transports, ","),
		Name:              name,
		Present:           c.Flags.UserPresent,
		Verified:          c.Flags.UserVerified,
		BackupEligible:    c.Flags.BackupEligible,
		BackupState:       c.Flags.BackupState,
	}
}

// fromStoreCred восстанавливает Credential из плоской строки (transport —
// список через запятую).
func fromStoreCred(wc store.WACred) gowebauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	if wc.Transports != "" {
		parts := strings.Split(wc.Transports, ",")
		transports = make([]protocol.AuthenticatorTransport, 0, len(parts))
		for _, t := range parts {
			if t != "" {
				transports = append(transports, protocol.AuthenticatorTransport(t))
			}
		}
	}
	return gowebauthn.Credential{
		ID:                wc.CredentialID,
		PublicKey:         wc.PublicKey,
		AttestationType:   wc.AttestationType,
		AttestationFormat: wc.AttestationFormat,
		Transport:         transports,
		Flags: gowebauthn.CredentialFlags{
			UserPresent:    wc.Present,
			UserVerified:   wc.Verified,
			BackupEligible: wc.BackupEligible,
			BackupState:    wc.BackupState,
		},
		Authenticator: gowebauthn.Authenticator{
			AAGUID:       aaguidBytes(wc.AAGUID),
			SignCount:    wc.SignCount,
			CloneWarning: wc.CloneWarning,
			Attachment:   protocol.AuthenticatorAttachment(wc.Attachment),
		},
	}
}

// aaguidToString кодирует 16 байт AAGUID в каноничную строку UUID
// (16 нулевых байт — «нулевой» AAGUID анонимных аутентификаторов).
func aaguidToString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	var u uuid.UUID
	copy(u[:], b)
	return u.String()
}

// aaguidBytes — обратное преобразование; пустая/битая строка даёт nil.
func aaguidBytes(s string) []byte {
	if s == "" {
		return nil
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return u[:]
}
