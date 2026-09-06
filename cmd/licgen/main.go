// licgen — вендорский генератор лицензий Ligament. Публичный репозиторий
// безопасен: без приватного Ed25519-ключа вендора (хранимого офлайн)
// сгенерированные блобы бесполезны — сервер проверяет подпись ключами,
// зашитыми в бинарник (ротация по kid).
//
// Режимы:
//
//	licgen -genkey
//	        сгенерировать пару ключей: приватный/публичный PEM (PKCS8/PKIX)
//	        и hex публичного ключа для вшивания в internal/license/file.go.
//	licgen -key private.pem -kid 2026-09 -customer "ООО Ромашка" \
//	        -plan subscription -users 50 -months 12 [-features a,b] \
//	        -plan demo -days 30 (демо-файл: включает 30 дней полного функционала) \
//	        [-notes "..."] [-out license.pem]
//	        выпустить лицензию (subscription: expires_at через -months,
//	        максимум 13; perpetual: -maintenance-months, expires_at нет).
//	licgen -key private.pem -kid 2026-09 -crl -revoke <lic_id> [-out crl.pem]
//	        выпустить CRL-отзыв лицензии.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/license"
)

func main() {
	var (
		genKey   = flag.Bool("genkey", false, "сгенерировать пару ключей и выйти")
		keyPath  = flag.String("key", "", "путь к приватному ключу (Ed25519, PKCS8 PEM)")
		kid      = flag.String("kid", "", "ID ключа подписи (ротация; зашит в бинарнике)")
		out      = flag.String("out", "", "записать blob в файл (по умолчанию — stdout)")
		customer = flag.String("customer", "", "имя клиента (для UI)")
		plan     = flag.String("plan", license.PlanSubscription,
			"тариф: subscription | perpetual")
		users       = flag.Int("users", 0, "лимит активных пользователей (0 — не ограничено)")
		months      = flag.Int("months", 12, "subscription: месяцев подписки (≤ 13)")
		demoDays    = flag.Int("days", 30, "demo: дней демо-лицензии (1..30)")
		maintMonths = flag.Int("maintenance-months", 12, "perpetual: месяцев окна обновлений")
		features    = flag.String("features", "", "edition-флаги через запятую")
		notes       = flag.String("notes", "", "заметка (не влияет на проверку)")
		crl         = flag.Bool("crl", false, "режим выпуска CRL-отзыва (-revoke lic_id)")
		revoke      = flag.String("revoke", "", "lic_id отзываемой лицензии (с -crl)")
	)
	flag.Parse()

	if *genKey {
		genAndPrintKey()
		return
	}
	if *keyPath == "" || *kid == "" {
		fmt.Fprintln(os.Stderr, "нужны -key и -kid (или -genkey); -h для справки")
		os.Exit(2)
	}
	priv := loadPrivate(*keyPath)

	var blob string
	switch {
	case *crl:
		if *revoke == "" {
			fmt.Fprintln(os.Stderr, "режим -crl требует -revoke <lic_id>")
			os.Exit(2)
		}
		rev, err := license.SignRevocation(priv, license.Revocation{
			LicID: *revoke, RevokedAt: time.Now().UTC(), Kid: *kid,
		})
		fatal(err)
		blob = rev
	default:
		if *customer == "" {
			fmt.Fprintln(os.Stderr, "нужно -customer (или -crl для отзыва)")
			os.Exit(2)
		}
		blob = issue(priv, *kid, *customer, *plan, *users, *months, *maintMonths, *demoDays, *features, *notes)
	}

	if *out != "" {
		fatal(os.WriteFile(*out, []byte(blob), 0o600))
		fmt.Fprintf(os.Stderr, "записано: %s\n", *out)
	} else {
		fmt.Print(blob)
	}
}

// issue собирает payload лицензии и подписывает его.
func issue(priv ed25519.PrivateKey, kid, customer, plan string, users, months, maintMonths, days int, features, notes string) string {
	now := time.Now().UTC()
	p := license.Payload{
		LicID:     uuid.NewString(),
		Customer:  customer,
		Plan:      plan,
		UserLimit: users,
		IssuedAt:  now,
		Kid:       kid,
	}
	if strings.TrimSpace(features) != "" {
		for _, f := range strings.Split(features, ",") {
			if f = strings.TrimSpace(f); f != "" {
				p.Features = append(p.Features, f)
			}
		}
	}
	if notes != "" {
		p.Notes = notes
	}
	switch plan {
	case license.PlanPerpetual:
		p.MaintenanceExpires = now.AddDate(0, maintMonths, 0)
	case license.PlanSubscription:
		if months < 1 || months > 13 {
			fmt.Fprintf(os.Stderr, "-months: подписка выпускается на 1..13 мес (получено %d)\n", months)
			os.Exit(2)
		}
		exp := now.AddDate(0, months, 0)
		p.ExpiresAt = &exp
		p.MaintenanceExpires = exp
	case license.PlanDemo:
		if days < 1 || days > 30 {
			fmt.Fprintf(os.Stderr, "-days: демо выпускается на 1..30 дней (получено %d)\n", days)
			os.Exit(2)
		}
		exp := now.AddDate(0, 0, days)
		p.ExpiresAt = &exp
	default:
		fmt.Fprintf(os.Stderr, "-plan: только subscription|perpetual|demo (получено %q)\n", plan)
		os.Exit(2)
	}
	blob, err := license.Sign(priv, p)
	fatal(err)
	fmt.Fprintf(os.Stderr, "lic_id: %s\nplan: %s\nissued_at: %s\nmaintenance_expires: %s\n",
		p.LicID, p.Plan, p.IssuedAt.Format(time.RFC3339), p.MaintenanceExpires.Format(time.RFC3339))
	return blob
}

// genAndPrintKey генерирует пару и печатает PEM-ключи + hex публичного.
func genAndPrintKey() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	fatal(err)

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatal(err)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	fatal(err)

	fmt.Fprintln(os.Stderr, "== приватный ключ (хранить офлайн, НЕ коммитить) ==")
	fmt.Print(string(pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privDER})))
	fmt.Fprintln(os.Stderr, "== публичный ключ (для реестра) ==")
	fmt.Print(string(pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: pubDER})))
	fmt.Fprintln(os.Stderr, "== hex публичного ключа — вшить в internal/license/file.go (trustedKeys) ==")
	fmt.Fprintln(os.Stderr, hex.EncodeToString(pub))
}

// loadPrivate читает приватный Ed25519-ключ из PKCS8 PEM.
func loadPrivate(path string) ed25519.PrivateKey {
	b, err := os.ReadFile(path)
	fatal(err)
	block, _ := pem.Decode(b)
	if block == nil {
		fmt.Fprintf(os.Stderr, "%s: не PEM", path)
		os.Exit(2)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	fatal(err)
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "%s: не Ed25519-ключ", path)
		os.Exit(2)
	}
	return priv
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "licgen:", err)
		os.Exit(1)
	}
}
