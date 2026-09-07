// Package acme предоставляет встроенный клиент для автоматического получения
// и обновления SSL/TLS-сертификатов Let's Encrypt (RFC 8555) по методу HTTP-01.
package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	// Directory URL Let's Encrypt
	LetsEncryptProdURL    = acme.LetsEncryptURL
	LetsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// RenewalThreshold: сертификат обновляется, если до окончания срока осталось менее 30 дней.
	RenewalThreshold = 30 * 24 * time.Hour

	// CheckInterval: периодичность фоновой проверки сертификата.
	CheckInterval = 12 * time.Hour
)

// CertInfo содержит распарсенные метаданные активного сертификата.
type CertInfo struct {
	SubjectCN    string    `json:"subject_cn"`
	IssuerOrg    string    `json:"issuer_org"`
	IssuerCN     string    `json:"issuer_cn"`
	DNSNames     []string  `json:"dns_names"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	DaysLeft     int       `json:"days_left"`
	IsExpired    bool      `json:"is_expired"`
	IsSelfSigned bool      `json:"is_self_signed"`
	IsACME       bool      `json:"is_acme"`
}

// Config содержит зависимости и колбэки для работы Manager.
type Config struct {
	// GetSettings возвращает актуальные настройки ACME:
	// enabled, domain, email, staging.
	GetSettings func() (enabled bool, domain string, email string, staging bool)

	// CurrentCertPEM возвращает текущий сертификат в PEM-формате.
	CurrentCertPEM func() []byte

	// OnCertRenewed вызывается при успешном выпуске/обновлении нового сертификата.
	// Колбэк должен сохранить cert_pem и key_pem и обновить активный сертификат сервера.
	OnCertRenewed func(ctx context.Context, certPEM, keyPEM []byte) error
}

// Manager управляет ACME-челленджами, выпуском и фоновым обновлением сертификатов.
type Manager struct {
	cfg Config

	mu         sync.RWMutex
	challenges map[string]string // token -> keyAuthorization

	accountKeyMu sync.Mutex
	accountKey   crypto.Signer
}

// NewManager создаёт новый ACME Manager.
func NewManager(cfg Config) *Manager {
	return &Manager{
		cfg:        cfg,
		challenges: make(map[string]string),
	}
}

// SetChallenge регистрирует ожидаемый токен и ответ для HTTP-01 проверки.
func (m *Manager) SetChallenge(token, keyAuth string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.challenges[token] = keyAuth
}

// DeleteChallenge удаляет токен после проверки.
func (m *Manager) DeleteChallenge(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.challenges, token)
}

// GetChallenge возвращает keyAuthorization для токена челленджа, если он активен.
func (m *Manager) GetChallenge(token string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.challenges[token]
	return v, ok
}

// HTTPHandler возвращает http.Handler для маршрута /.well-known/acme-challenge/{token}.
// Если запрос не относится к ACME-челленджу или токен не найден, вызывается fallback (или 404).
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			if fallback != nil {
				fallback.ServeHTTP(w, r)
			} else {
				http.NotFound(w, r)
			}
			return
		}

		token := strings.TrimPrefix(r.URL.Path, prefix)
		// Отрезаем возможные параметры или слэши
		if idx := strings.IndexByte(token, '/'); idx != -1 {
			token = token[:idx]
		}

		keyAuth, ok := m.GetChallenge(token)
		if !ok {
			slog.Warn("acme: получен запрос на неизвестный токен челленджа", "token", token, "remote", r.RemoteAddr)
			if fallback != nil {
				fallback.ServeHTTP(w, r)
			} else {
				http.NotFound(w, r)
			}
			return
		}

		slog.Info("acme: успешно отдан HTTP-01 челлендж", "token", token, "remote", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(keyAuth))
	})
}

// getAccountKey возвращает или генерирует приватный ключ аккаунта ACME.
func (m *Manager) getAccountKey() (crypto.Signer, error) {
	m.accountKeyMu.Lock()
	defer m.accountKeyMu.Unlock()
	if m.accountKey != nil {
		return m.accountKey, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("генерация ключа аккаунта ACME: %w", err)
	}
	m.accountKey = key
	return key, nil
}

// ObtainCertificate выполняет полный протокол ACME (RFC 8555) через HTTP-01
// и возвращает новую пару certPEM (fullchain) и keyPEM (RSA-2048).
func (m *Manager) ObtainCertificate(ctx context.Context, domain, email string, staging bool) ([]byte, []byte, error) {
	domain = strings.TrimSpace(domain)
	email = strings.TrimSpace(email)
	if domain == "" {
		return nil, nil, errors.New("acme: доменное имя не указано")
	}

	accountKey, err := m.getAccountKey()
	if err != nil {
		return nil, nil, err
	}

	dirURL := LetsEncryptProdURL
	if staging {
		dirURL = LetsEncryptStagingURL
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: dirURL,
		UserAgent:    "Ligament-2FA/0.4 (ACME)",
	}

	slog.Info("acme: инициализация регистрации в центре сертификации", "directory", dirURL, "domain", domain)

	// 1. Регистрация аккаунта с согласием с условиями (TOS)
	var contact []string
	if email != "" {
		contact = []string{"mailto:" + email}
	}
	acct := &acme.Account{Contact: contact}
	_, regErr := client.Register(ctx, acct, acme.AcceptTOS)
	if regErr != nil && !errors.Is(regErr, acme.ErrAccountAlreadyExists) {
		return nil, nil, fmt.Errorf("acme: регистрация аккаунта в %s: %w", dirURL, regErr)
	}

	// 2. Создание заказа (AuthorizeOrder)
	slog.Info("acme: создание заказа на сертификат", "domain", domain)
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: domain}})
	if err != nil {
		return nil, nil, fmt.Errorf("acme: ошибка создания заказа: %w", err)
	}

	// 3. Авторизация каждого домена через HTTP-01
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, nil, fmt.Errorf("acme: ошибка получения авторизации %s: %w", authzURL, err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, nil, fmt.Errorf("acme: центр сертификации не вернул челлендж http-01 для %s", domain)
		}

		keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, nil, fmt.Errorf("acme: генерация ответа на челлендж: %w", err)
		}

		m.SetChallenge(chal.Token, keyAuth)

		slog.Info("acme: уведомление центра сертификации о готовности челленджа", "token", chal.Token, "uri", chal.URI)
		if _, err := client.Accept(ctx, chal); err != nil {
			m.DeleteChallenge(chal.Token)
			return nil, nil, fmt.Errorf("acme: ошибка отправки Accept на челлендж: %w", err)
		}

		// Ожидание завершения проверки центром сертификации
		waitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		authzRes, err := client.WaitAuthorization(waitCtx, chal.URI)
		cancel()
		m.DeleteChallenge(chal.Token)

		if err != nil {
			return nil, nil, fmt.Errorf("acme: проверка владения доменом %s не удалась: %w", domain, err)
		}
		if authzRes.Status != acme.StatusValid {
			return nil, nil, fmt.Errorf("acme: статус авторизации %s: %s", domain, authzRes.Status)
		}
		slog.Info("acme: владение доменом успешно подтверждено", "domain", domain)
	}

	// 4. Ожидание готовности заказа
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: ожидание финализации заказа: %w", err)
	}

	// 5. Генерация RSA-2048 ключа сертификата (наивысшая совместимость с Wi-Fi клиентами)
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: генерация RSA-ключа: %w", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain, Organization: []string{"Ligament"}},
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: формирование CSR: %w", err)
	}

	// 6. Получение подписанного сертификата и цепочки доверия
	slog.Info("acme: финализация заказа и скачивание сертификата", "finalize_url", order.FinalizeURL)
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: CreateOrderCert: %w", err)
	}

	// 7. Сборка PEM
	var certBuf bytes.Buffer
	for _, b := range der {
		if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
			return nil, nil, fmt.Errorf("acme: PEM кодирование: %w", err)
		}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})

	slog.Info("acme: сертификат Let's Encrypt успешно получен", "domain", domain, "cert_len", certBuf.Len())
	return certBuf.Bytes(), keyPEM, nil
}

// Renew запускает выпуск или обновление сертификата по текущим настройкам.
func (m *Manager) Renew(ctx context.Context) error {
	if m.cfg.GetSettings == nil {
		return errors.New("acme: GetSettings не настроен")
	}
	enabled, domain, email, staging := m.cfg.GetSettings()
	if !enabled || strings.TrimSpace(domain) == "" {
		return errors.New("acme: автообновление выключено или домен не указан")
	}

	certPEM, keyPEM, err := m.ObtainCertificate(ctx, domain, email, staging)
	if err != nil {
		return err
	}

	if m.cfg.OnCertRenewed != nil {
		if err := m.cfg.OnCertRenewed(ctx, certPEM, keyPEM); err != nil {
			return fmt.Errorf("acme: применение нового сертификата: %w", err)
		}
	}
	return nil
}

// ShouldRenew проверяет, нужно ли обновлять текущий сертификат.
// Возвращает true, если сертификат отсутствует, просрочен,
// его срок действия заканчивается менее чем через 30 дней,
// или он самоподписанный / выпущен на другой домен.
func ShouldRenew(curPEM []byte, targetDomain string) (bool, string) {
	if len(curPEM) == 0 {
		return true, "сертификат отсутствует"
	}
	cert, info, err := ParseCertPEM(curPEM)
	if err != nil {
		return true, "ошибка разбора текущего сертификата: " + err.Error()
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		return true, "сертификат просрочен (" + cert.NotAfter.Format("2006-01-02") + ")"
	}

	if targetDomain != "" {
		targetDomain = strings.ToLower(strings.TrimSpace(targetDomain))
		hasDomain := strings.EqualFold(cert.Subject.CommonName, targetDomain)
		if !hasDomain {
			for _, san := range cert.DNSNames {
				if strings.EqualFold(san, targetDomain) {
					hasDomain = true
					break
				}
			}
		}
		if !hasDomain {
			return true, fmt.Sprintf("домен сертификата (%s) не совпадает с целевым (%s)", cert.Subject.CommonName, targetDomain)
		}
	}

	if info.IsSelfSigned {
		return true, "текущий сертификат является самоподписанным"
	}

	remaining := cert.NotAfter.Sub(now)
	if remaining < RenewalThreshold {
		days := int(remaining.Hours() / 24)
		return true, fmt.Sprintf("до окончания срока осталось %d дн. (< 30)", days)
	}

	return false, ""
}

// CheckAndRenew выполняет проверку срока действия и при необходимости обновляет сертификат.
func (m *Manager) CheckAndRenew(ctx context.Context) error {
	if m.cfg.GetSettings == nil {
		return nil
	}
	enabled, domain, _, _ := m.cfg.GetSettings()
	if !enabled || strings.TrimSpace(domain) == "" {
		return nil
	}

	var curPEM []byte
	if m.cfg.CurrentCertPEM != nil {
		curPEM = m.cfg.CurrentCertPEM()
	}

	need, reason := ShouldRenew(curPEM, domain)
	if !need {
		slog.Debug("acme: сертификат актуален, обновление не требуется", "domain", domain)
		return nil
	}

	slog.Info("acme: запуск автоматического обновления сертификата", "domain", domain, "reason", reason)
	return m.Renew(ctx)
}

// Run запускает фоновый процесс автообновления.
// Первая проверка выполняется через 15 секунд после старта, затем каждые CheckInterval (12 часов).
func (m *Manager) Run(ctx context.Context) {
	slog.Info("acme: запущен фоновый воркер автообновления сертификатов")

	// Первая проверка с небольшой задержкой после старта
	select {
	case <-ctx.Done():
		return
	case <-time.After(15 * time.Second):
		checkCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		if err := m.CheckAndRenew(checkCtx); err != nil {
			slog.Error("acme: ошибка при первоначальной проверке/обновлении сертификата", "error", err)
		}
		cancel()
	}

	ticker := time.NewTicker(CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("acme: фоновый воркер автообновления остановлен")
			return
		case <-ticker.C:
			checkCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			if err := m.CheckAndRenew(checkCtx); err != nil {
				slog.Error("acme: ошибка автоматического продления сертификата", "error", err)
			}
			cancel()
		}
	}
}

// ParseCertPEM разбирает первый сертификат из PEM-данных и формирует структуру CertInfo.
func ParseCertPEM(pemBytes []byte) (*x509.Certificate, *CertInfo, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil, errors.New("не удалось декодировать PEM-блок сертификата")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("разбор сертификата x509: %w", err)
	}

	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	isExpired := now.After(cert.NotAfter)

	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	}

	isSelfSigned := bytes.Equal(cert.RawIssuer, cert.RawSubject)
	isACME := strings.Contains(strings.ToLower(issuerOrg), "let's encrypt") ||
		strings.Contains(strings.ToLower(cert.Issuer.CommonName), "r3") ||
		strings.Contains(strings.ToLower(cert.Issuer.CommonName), "e1") ||
		strings.Contains(strings.ToLower(cert.Issuer.CommonName), "let's encrypt")

	info := &CertInfo{
		SubjectCN:    cert.Subject.CommonName,
		IssuerOrg:    issuerOrg,
		IssuerCN:     cert.Issuer.CommonName,
		DNSNames:     cert.DNSNames,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DaysLeft:     daysLeft,
		IsExpired:    isExpired,
		IsSelfSigned: isSelfSigned,
		IsACME:       isACME,
	}

	return cert, info, nil
}
