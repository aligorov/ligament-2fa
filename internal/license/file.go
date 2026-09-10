// Формат license-файла (report §3.1): PEM-подобная обёртка, внутри одна
// строка base64(payload) + "." + base64(sig). Подпись — Ed25519 (алгоритм
// жёстко зафиксирован в коде, без JWT-зависимостей и alg-confusion) по
// каноническим байtam payload. Публичные ключи вендора зашиты в бинарник
// (ротация по kid), приватные — только в офлайн-хранилище вендора.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Обёртки license-файла и CRL.
const (
	LicenseHeader    = "-----BEGIN LIGAMENT LICENSE-----"
	LicenseFooter    = "-----END LIGAMENT LICENSE-----"
	RevocationHeader = "-----BEGIN LIGAMENT REVOCATION-----"
	RevocationFooter = "-----END LIGAMENT REVOCATION-----"
)

// Ошибки разбора/проверки (машинные — API отдаёт клиенту коды).
var (
	ErrMalformed    = errors.New("license: некорректный формат блоба")
	ErrBadSignature = errors.New("license: неверная подпись")
	ErrUnknownKid   = errors.New("license: неизвестный ключ подписи (kid)")
)

// footerLine — перевод строки перед закрывающей обёрткой (для тестов,
// срезающих подпись).
const footerLine = "\n" + LicenseFooter

// mustPubKey декодирует hex-публик (зашивка ключей — ошибка компиляции
// времени разработки, паника допустима только на старте).
func mustPubKey(hexKey string) ed25519.PublicKey {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		panic("license: битый hex доверенного ключа: " + err.Error())
	}
	if len(b) != ed25519.PublicKeySize {
		panic("license: неверная длина доверенного ключа")
	}
	return ed25519.PublicKey(b)
}

// trustedKeys — публичные ключи вендора, зашитые в бинарник (ротация по
// kid). Собираются из двух частей: боевой набор prodTrustedKeys (все
// сборки) + devTrustedKeys (НЕПУСТ только в -tags dev — make build-dev;
// в продовые бинарники dev-ключи физически не попадают, см.
// devkeys_dev.go / devkeys_prod.go). Вендор перед релизом обязан
// сгенерировать свою пару (cmd/licgen -genkey), вшить hex публичного ключа
// в prodTrustedKeys и хранить приватный офлайн (см. README
// «Лицензирование» → «Ключи выпуска»). Подмена в рантайме — только через
// SetTrustedKeys (тесты).
var trustedKeys = func() map[string]ed25519.PublicKey {
	keys := make(map[string]ed25519.PublicKey, len(prodTrustedKeys)+len(devTrustedKeys))
	for kid, k := range prodTrustedKeys {
		keys[kid] = k
	}
	for kid, k := range devTrustedKeys {
		keys[kid] = k
	}
	return keys
}()

// prodTrustedKeys — боевые ключи вендора: присутствуют в каждой сборке.
var prodTrustedKeys = map[string]ed25519.PublicKey{
	"aligorov-2026-09": mustPubKey("5b3832181a5881426544a4e7eca6a75cdc8f59ecfb143d063b40b7671cdbcb10"),
}

// SetTrustedKeys подменяет набор доверенных ключей и возвращает функцию
// восстановления прежнего набора (интеграционные тесты генерируют свою
// пару: restore := SetTrustedKeys(...); t.Cleanup(restore)).
func SetTrustedKeys(keys map[string]ed25519.PublicKey) func() {
	prev := trustedKeys
	trustedKeys = keys
	return func() { trustedKeys = prev }
}

// Sign подписывает payload приватным ключом вендора и собирает blob.
func Sign(priv ed25519.PrivateKey, p Payload) (string, error) {
	canonical, err := p.Canonical()
	if err != nil {
		return "", err
	}
	return encodeBlob(LicenseHeader, LicenseFooter, canonical, ed25519.Sign(priv, canonical)), nil
}

// SignRevocation подписывает CRL-отзыв и собирает blob.
func SignRevocation(priv ed25519.PrivateKey, r Revocation) (string, error) {
	canonical, err := r.Canonical()
	if err != nil {
		return "", err
	}
	return encodeBlob(RevocationHeader, RevocationFooter, canonical, ed25519.Sign(priv, canonical)), nil
}

// encodeBlob собирает PEM-подобный blob: обёртка + base64(payload)+"."+
// base64(sig).
func encodeBlob(header, footer string, payload, sig []byte) string {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(base64.StdEncoding.EncodeToString(payload))
	b.WriteString(".")
	b.WriteString(base64.StdEncoding.EncodeToString(sig))
	b.WriteString("\n")
	b.WriteString(footer)
	b.WriteString("\n")
	return b.String()
}

// ParseLicense разбирает и проверяет license-blob: формат → payload →
// известный kid → подпись Ed25519 по каноническим байtam.
func ParseLicense(blob string) (Payload, error) {
	payload, sig, err := decodeBlob(blob, LicenseHeader, LicenseFooter)
	if err != nil {
		return Payload{}, err
	}
	var p Payload
	if err := strictUnmarshal(payload, &p); err != nil {
		return Payload{}, ErrMalformed
	}
	if p.LicID == "" || p.Kid == "" ||
		(p.Plan != PlanSubscription && p.Plan != PlanPerpetual && p.Plan != PlanDemo) {
		return Payload{}, ErrMalformed
	}
	if p.Plan == PlanPerpetual && p.ExpiresAt != nil {
		return Payload{}, ErrMalformed // perpetual — бессрочная по определению
	}
	if p.Plan == PlanSubscription && p.ExpiresAt == nil {
		return Payload{}, ErrMalformed // подписка обязана иметь expires_at
	}
	if p.Plan == PlanDemo {
		if p.ExpiresAt == nil {
			return Payload{}, ErrMalformed // демо обязана иметь срок
		}
		if p.ExpiresAt.Sub(p.IssuedAt) > 31*24*time.Hour {
			return Payload{}, ErrMalformed // демо — не дольше 30 дней (+сутки запаса)
		}
	}
	canonical, err := p.Canonical()
	if err != nil {
		return Payload{}, err
	}
	if err := verifySigned(p.Kid, canonical, sig); err != nil {
		return Payload{}, err
	}
	return p, nil
}

// ParseRevocation разбирает и проверяет CRL-blob.
func ParseRevocation(blob string) (Revocation, error) {
	payload, sig, err := decodeBlob(blob, RevocationHeader, RevocationFooter)
	if err != nil {
		return Revocation{}, err
	}
	var r Revocation
	if err := strictUnmarshal(payload, &r); err != nil {
		return Revocation{}, ErrMalformed
	}
	if r.LicID == "" || r.Kid == "" || r.RevokedAt.IsZero() {
		return Revocation{}, ErrMalformed
	}
	canonical, err := r.Canonical()
	if err != nil {
		return Revocation{}, err
	}
	if err := verifySigned(r.Kid, canonical, sig); err != nil {
		return Revocation{}, err
	}
	return r, nil
}

// decodeBlob срезает обёртку и разбирает строку base64(payload)+"."+
// base64(sig); ошибки формата схлопываются в ErrMalformed.
func decodeBlob(blob, header, footer string) ([]byte, []byte, error) {
	s := strings.TrimSpace(strings.ReplaceAll(blob, "\r\n", "\n"))
	if !strings.HasPrefix(s, header+"\n") || !strings.HasSuffix(s, footer) {
		return nil, nil, ErrMalformed
	}
	inner := strings.TrimSpace(s[len(header) : len(s)-len(footer)])
	dot := strings.IndexByte(inner, '.')
	if dot < 0 {
		return nil, nil, ErrMalformed
	}
	payload, err := base64.StdEncoding.DecodeString(inner[:dot])
	if err != nil {
		return nil, nil, ErrMalformed
	}
	sig, err := base64.StdEncoding.DecodeString(inner[dot+1:])
	if err != nil {
		return nil, nil, ErrMalformed
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, nil, ErrMalformed
	}
	return payload, sig, nil
}

// strictUnmarshal запрещает неизвестные поля: payload лицензии фиксирован,
// опечатки вендора не должны молча теряться.
func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// verifySigned сверяет подпись Ed25519 с каноническими байтами РАЗОБРАННОГО
// значения: подпись валидна только для строго канонической формы payload
// (roundtrip parse→canonical стабилен — см. TestCanonicalRoundtrip).
func verifySigned(kid string, canonical, sig []byte) error {
	pub, ok := trustedKeys[kid]
	if !ok {
		return ErrUnknownKid
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return ErrBadSignature
	}
	return nil
}
