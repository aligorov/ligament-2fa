package auth

import (
	"strings"
	"sync"
	"testing"

	"github.com/aligorov/twofa/internal/secrets"
)

// TestDummyArgon2Hash: хеш-приманка для ветки «пользователь не найден»
// валиден, детерминирован (один argon2-хеш на процесс) и не принимает ни
// одного пароля — обе ветки LocalVerifier.Verify стоят одинакового argon2,
// время ответа не раскрывает существование учётной записи.
func TestDummyArgon2Hash(t *testing.T) {
	h1, h2 := dummyArgon2Hash(), dummyArgon2Hash()
	if h1 == "" || h1 != h2 {
		t.Fatalf("dummy-хеш не детерминирован: %q vs %q", h1, h2)
	}
	if !strings.HasPrefix(h1, "$argon2id$v=19$m=65536,t=1,p=4$") {
		t.Fatalf("dummy-хех не в формате HashPassword: %q", h1)
	}
	// Любой «настоящий» пароль отвергается. Сам источник хеша
	// ("twofa-dummy-password") совпадает по построению — это безопасно:
	// результат burnDummyVerify отбрасывается и ответ одинаков (401).
	for _, pw := range []string{"dummy", "", "hunter2pass", "wrong-password"} {
		if secrets.VerifyPassword(h1, pw) {
			t.Fatalf("dummy-хеш принял пароль %q", pw)
		}
	}
}

// TestDummyArgon2HashConcurrent: генерация под гонкой тоже даёт один хеш
// (sync.Once) — параллельные запросы к отсутствующим пользователям не
// пересоздают argon2-хеш.
func TestDummyArgon2HashConcurrent(t *testing.T) {
	const n = 16
	var wg sync.WaitGroup
	hashes := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hashes[i] = dummyArgon2Hash()
		}(i)
	}
	wg.Wait()
	for i, h := range hashes {
		if h != hashes[0] {
			t.Fatalf("hash[%d] = %q, want %q", i, h, hashes[0])
		}
	}
}
