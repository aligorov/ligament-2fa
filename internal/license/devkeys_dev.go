//go:build dev

// ДЕВ-сборка (go build -tags dev / make build-dev): добавляет ключ dev-1
// в trustedKeys — лицензии старых локальных демо продолжают читаться.
// ТОЛЬКО для локальных демонстраций: бинарник с этим ключом признаёт
// лицензии, подписанные dev-приватником, и НЕ должен поставляться
// клиентам, собираться CI или публиковаться (audit P1: держатель
// dev-приватника выпускает валидные лицензии любого плана).
package license

import "crypto/ed25519"

// devKeysEnabled — индикатор -tags dev для тестов (в дефолтной сборке
// trustedKeys обязан быть без dev-1).
const devKeysEnabled = true

// devTrustedKeys — дополнительный набор, доступный только в -tags dev.
var devTrustedKeys = map[string]ed25519.PublicKey{
	"dev-1": mustPubKey("335571483eb7a56d0ea0eb4afab5b74b7df3d9239d8862cc1066a987d63919ca"),
}
