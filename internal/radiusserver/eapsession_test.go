// Юнит-тест eviction-политики EAP-сессий (без БД и сети): при переполнении
// капы выметаются ТОЛЬКО простаивающие >30с сессии; если таких нет — новая
// отклоняется (churn-DoS не рвёт активные handshake-ы).
package radiusserver

import (
	"bytes"
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

// TestStashPendingInnerCap — анти-DoS кап накопителя phase-2: буфер больше
// maxPendingInner (64 KiB) не запоминается (вызывающий завершит обмен
// failEAP), допустимый размер кладётся как есть; повторный stash заменяет
// предыдущий (append частичного блока делается до stash).
func TestStashPendingInnerCap(t *testing.T) {
	sess := &eapSession{}

	if !sess.stashPendingInner(make([]byte, maxPendingInner)) {
		t.Fatal("буфер ровно maxPendingInner должен приниматься (<= кап)")
	}
	if len(sess.pendingInner) != maxPendingInner {
		t.Fatalf("pendingInner = %d, хочу %d", len(sess.pendingInner), maxPendingInner)
	}

	if sess.stashPendingInner(make([]byte, maxPendingInner+1)) {
		t.Fatal("буфер больше капа должен отвергаться (failEAP у вызывающего)")
	}

	// Отвергнутый stash не портит предыдущее состояние.
	if len(sess.pendingInner) != maxPendingInner {
		t.Fatalf("после отказа pendingInner = %d, хочу прежние %d",
			len(sess.pendingInner), maxPendingInner)
	}

	small := []byte{1, 2, 3}
	if !sess.stashPendingInner(small) {
		t.Fatal("маленький буфер должен приниматься")
	}
	if !bytes.Equal(sess.pendingInner, small) {
		t.Fatalf("pendingInner после замены = %v, хочу %v", sess.pendingInner, small)
	}
}
