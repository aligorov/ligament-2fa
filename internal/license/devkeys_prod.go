//go:build !dev

// Продакшен-сборка (дефолт: go build / make build / docker): набор
// dev-ключей ПУСТ — kid=dev-1 не признаётся, старые демо-лицензии не
// проходят проверку (ожидаемо: перевыпустить командой licgen боевым
// ключом, см. README «Ключи выпуска»). Симметричен devkeys_dev.go.
package license

import "crypto/ed25519"

// devKeysEnabled — индикатор -tags dev для тестов (в дефолтной сборке
// trustedKeys обязан быть без dev-1).
const devKeysEnabled = false

// devTrustedKeys — дополнительный набор, доступный только в -tags dev.
var devTrustedKeys = map[string]ed25519.PublicKey{}
