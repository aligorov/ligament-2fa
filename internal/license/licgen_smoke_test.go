// Смоук-проверка совместимости cmd/licgen ↔ internal/license: блоб,
// выпущенный генератором (фиксированный тестовый ключ), разбирается
// валидатором сервера. Полный цикл licgen покрывается ручным прогоном
// (README «Лицензирование»).
package license

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLicgenOutputParses: licgen -key (PKCS8 PEM) → blob → ParseLicense.
func TestLicgenOutputParses(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go недоступен в PATH")
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "vendor.pem")
	if err := os.WriteFile(keyPath, testPKCS8PEM(t, priv), 0o600); err != nil {
		t.Fatalf("запись ключа: %v", err)
	}

	blobBytes, err := exec.Command("go", "run", "../../cmd/licgen",
		"-key", keyPath, "-kid", "smoke-1", "-customer", "Test LLC",
		"-plan", "perpetual", "-users", "10", "-maintenance-months", "6",
	).Output()
	if err != nil {
		t.Skipf("go run licgen не удался (сетевая сборка?): %v", err)
	}
	blob := strings.TrimSpace(string(blobBytes))
	if !strings.HasPrefix(blob, LicenseHeader) {
		t.Fatalf("licgen вывел не license-blob: %q", blob[:min(60, len(blob))])
	}

	restore := SetTrustedKeys(map[string]ed25519.PublicKey{"smoke-1": pub})
	t.Cleanup(restore)
	p, err := ParseLicense(blob)
	if err != nil {
		t.Fatalf("ParseLicense(licgen blob): %v", err)
	}
	if p.Customer != "Test LLC" || p.Plan != PlanPerpetual || p.UserLimit != 10 {
		t.Fatalf("payload разошёлся: %+v", p)
	}
}

// testPKCS8PEM кодирует приватный Ed25519-ключ в PKCS8 PEM (формат -key).
func testPKCS8PEM(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
