// Серверный сертификат EAP-TTLS: self-signed RSA-2048 (CN=ligament,
// SAN=ligament, срок 10 лет). Создаётся при первом старте (EnsureEAPCert,
// вызывается из main; при недоступной БД — повторная ленивая попытка при
// первом EAP-запросе) и хранится в настройках ключом radius.eap_cert
// (JSON {"cert_pem","key_pem"}) — по образцу oidc.keys (internal/oidc).
// Секрет: settings не экспортирует/не импортирует ключ и маскирует его.
package radiusserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"
)

// Параметры self-signed сертификата EAP-TTLS / PEAP.
// Срок действия ограничен 730 днями (2 года): Apple (iOS 13+) блокирует
// TLS-сертификаты с валидностью > 825 дней.
const (
	eapCertKeyBits   = 2048
	eapCertCN        = "ligament"
	eapCertValidity  = 730 * 24 * time.Hour
	maxAppleCertDays = 825
)

// eapCertPair — значение настройки radius.eap_cert: сертификат и приватный
// ключ в PEM. Приватный ключ — секрет.
type eapCertPair struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// EnsureEAPCert гарантирует загруженный TLS-сертификат для TTLS/PEAP: читает
// radius.eap_cert из текущего снимка настроек, при отсутствии/битом
// значении или превышении лимита 825 дней генерирует новую пару и
// сохраняет через settings.Put.
// Идемпотентен и потокобезопасен; ошибка не катастрофа — PAP-RADIUS
// продолжает работать, EAP-запросы получают Reject.
func (s *Server) EnsureEAPCert(ctx context.Context) error {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if s.eapTLSCert != nil {
		return nil
	}

	// 1. Проверяем, заданы ли файлы сертификата (EAP_CERT_FILE / radius.cert_file)
	cf := s.m.Get().Radius.CertFile
	kf := s.m.Get().Radius.KeyFile
	if cf != "" && kf != "" {
		certData, err := os.ReadFile(cf)
		if err != nil {
			return fmt.Errorf("radius: чтение cert_file %s: %w", cf, err)
		}
		keyData, err := os.ReadFile(kf)
		if err != nil {
			return fmt.Errorf("radius: чтение key_file %s: %w", kf, err)
		}
		pair := &eapCertPair{CertPEM: string(certData), KeyPEM: string(keyData)}
		if err := loadEAPCert(s, pair); err != nil {
			return err
		}
		slog.Info("radius: загружен EAP-сертификат из файлов", "cert_file", cf)
		return nil
	}

	var pair *eapCertPair
	if raw := s.m.Get().Radius.EAPCert; len(raw) > 0 {
		p, err := parseEAPCertPair(raw)
		if err != nil {
			slog.Error("radius: значение radius.eap_cert не разбирается — генерирую новый сертификат", "error", err)
		} else {
			// Проверка на соответствие лимитам Apple (<= 825 дней)
			if block, _ := pem.Decode([]byte(p.CertPEM)); block != nil {
				if parsed, perr := x509.ParseCertificate(block.Bytes); perr == nil {
					if parsed.NotAfter.Sub(parsed.NotBefore) > maxAppleCertDays*24*time.Hour || time.Now().After(parsed.NotAfter) {
						slog.Warn("radius: существующий сертификат radius.eap_cert устарел или превышает 825 дней — перевыпуск")
					} else {
						pair = p
					}
				}
			}
		}
	}
	if pair == nil {
		var err error
		pair, err = generateEAPCertPair()
		if err != nil {
			return err
		}
		raw, merr := json.Marshal(pair)
		if merr != nil {
			return fmt.Errorf("radius: маршал radius.eap_cert: %w", merr)
		}
		// Сертификат грузим в память ДО записи: даже если БД недоступна,
		// EAP работает до рестарта (Put вернёт ошибку наружу для лога).
		if perr := s.m.Put(ctx, "radius.eap_cert", raw); perr != nil {
			if cerr := loadEAPCert(s, pair); cerr == nil {
				return fmt.Errorf("radius: radius.eap_cert не сохранён в настройках: %w", perr)
			}
			return perr
		}
		slog.Info("radius: сгенерирован self-signed сертификат EAP-TTLS (CN=ligament)")
	}
	return loadEAPCert(s, pair)
}

// SetEAPCertificate устанавливает активный сертификат в рантайме (например, после ACME-обновления).
func (s *Server) SetEAPCertificate(cert *tls.Certificate, rawPEM []byte) {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	s.eapTLSCert = cert
	s.eapCertPEM = rawPEM
}

// CurrentEAPCertPEM возвращает сырой PEM активного сертификата.
func (s *Server) CurrentEAPCertPEM() []byte {
	s.certMu.RLock()
	defer s.certMu.RUnlock()
	if len(s.eapCertPEM) > 0 {
		return s.eapCertPEM
	}
	if raw := s.m.Get().Radius.EAPCert; len(raw) > 0 {
		if pair, err := parseEAPCertPair(raw); err == nil && pair != nil {
			return []byte(pair.CertPEM)
		}
	}
	return nil
}

// CurrentEAPCertificate возвращает текущий *tls.Certificate и распарсенный leaf *x509.Certificate.
func (s *Server) CurrentEAPCertificate() (*tls.Certificate, *x509.Certificate, error) {
	s.certMu.RLock()
	defer s.certMu.RUnlock()
	if s.eapTLSCert == nil {
		return nil, nil, errors.New("сертификат EAP не загружен")
	}
	if len(s.eapTLSCert.Certificate) == 0 {
		return s.eapTLSCert, nil, errors.New("в tls.Certificate нет DER-блоков")
	}
	leaf, err := x509.ParseCertificate(s.eapTLSCert.Certificate[0])
	if err != nil {
		return s.eapTLSCert, nil, fmt.Errorf("разбор x509: %w", err)
	}
	return s.eapTLSCert, leaf, nil
}

// eapCertificate возвращает загруженный сертификат (nil — ещё нет).
func (s *Server) eapCertificate() *tls.Certificate {
	s.certMu.RLock()
	defer s.certMu.RUnlock()
	return s.eapTLSCert
}

// loadEAPCert разбирает PEM-пару и запоминает её в сервере.
func loadEAPCert(s *Server, pair *eapCertPair) error {
	cert, err := tls.X509KeyPair([]byte(pair.CertPEM), []byte(pair.KeyPEM))
	if err != nil {
		return fmt.Errorf("radius: разбор сертификата radius.eap_cert: %w", err)
	}
	s.eapTLSCert = &cert
	s.eapCertPEM = []byte(pair.CertPEM)
	return nil
}

// parseEAPCertPair разбирает сырой JSON radius.eap_cert; null/пустое
// значение — сертификат ещё не создан (nil, nil).
func parseEAPCertPair(raw json.RawMessage) (*eapCertPair, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var pair eapCertPair
	if err := json.Unmarshal(raw, &pair); err != nil {
		return nil, fmt.Errorf("разбор radius.eap_cert: %w", err)
	}
	if pair.CertPEM == "" || pair.KeyPEM == "" {
		return nil, errors.New("radius.eap_cert без cert_pem/key_pem")
	}
	return &pair, nil
}

// generateEAPCertPair создаёт self-signed пару RSA-2048: CN/SAN=ligament,
// 10 лет, EKU serverAuth; IsCA+CertSign — чтобы клиент мог доверять
// сертификату как CA в настройках 802.1X (одна и та же пара — и лист, и
// якорь доверия; ручная замена через БД settings остаётся возможной).
func generateEAPCertPair() (*eapCertPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, eapCertKeyBits)
	if err != nil {
		return nil, fmt.Errorf("radius: генерация RSA-%d: %w", eapCertKeyBits, err)
	}
	serial := make([]byte, 16)
	if _, err := rand.Read(serial); err != nil {
		return nil, fmt.Errorf("radius: серийный номер сертификата: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serial),
		Subject:               pkix.Name{CommonName: eapCertCN, Organization: []string{"Ligament"}},
		DNSNames:              []string{eapCertCN},
		NotBefore:             now.Add(-time.Hour), // запас на рассинхрон часов
		NotAfter:              now.Add(eapCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("radius: выпуск сертификата EAP-TTLS: %w", err)
	}
	return &eapCertPair{
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM: string(pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
		})),
	}, nil
}
