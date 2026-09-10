// Юнит-тест eviction-политики EAP-сессий (без БД и сети): при переполнении
// капы выметаются ТОЛЬКО простаивающие >30с сессии; если таких нет — новая
// отклоняется (churn-DoS не рвёт активные handshake-ы).
package radiusserver

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestEAPSessionStoreEvictIdleOnly(t *testing.T) {
	st := newEAPSessionStore()
	// Пустой сертификат достаточен: TLS-воркеры стартуют и блокируются на
	// чтении моста — тест проверяет только политику карты сессий.
	cert := &tls.Certificate{}

	// Заполняем капу «активными» сессиями (lastUsed = сейчас).
	for len(st.sessions) < eapSessionCap {
		if s := st.create(cert, eapProtoPEAP); s == nil {
			t.Fatalf("create #%d вернул nil до достижения капы", len(st.sessions))
		}
	}

	// Все активны — новая сессия отклоняется, карта не тронута.
	before := len(st.sessions)
	if s := st.create(cert, eapProtoTTLS); s != nil {
		st.delete(s)
		t.Fatal("при капе без простаивающих новая сессия должна отклоняться")
	}
	if len(st.sessions) != before {
		t.Fatalf("карка изменилась при отклонении: %d → %d", before, len(st.sessions))
	}

	// Одна сессия простаивает дольше eapEvictIdle — выметается именно она,
	// новая создаётся.
	var idleKey string
	st.mu.Lock()
	for k, v := range st.sessions {
		v.lastUsed = time.Now().Add(-eapEvictIdle - time.Second)
		idleKey = k
		break
	}
	st.mu.Unlock()
	fresh := st.create(cert, eapProtoTTLS)
	if fresh == nil {
		t.Fatal("создание при живой простаивающей сессии отклонено — должна вымететься")
	}
	st.mu.Lock()
	_, stillThere := st.sessions[idleKey]
	n := len(st.sessions)
	st.mu.Unlock()
	if stillThere {
		t.Fatal("простаивающая сессия не выметена")
	}
	if n != eapSessionCap {
		t.Fatalf("размер карты после выметания = %d, хочу %d", n, eapSessionCap)
	}
	fresh.conn.Close()
}
