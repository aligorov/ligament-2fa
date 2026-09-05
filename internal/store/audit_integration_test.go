//go:build integration

// Интеграционные тесты аудита: запись событий и фильтры AuditList.
package store

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuditAndListIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()
	name := "audit-" + uuid.NewString()[:10]

	events := []string{"login_ok", "login_fail", "login_ok"}
	for i, ev := range events {
		if err := st.Audit(ctx, name, ev, map[string]any{"attempt": i}, "192.0.2.1", "ok"); err != nil {
			t.Fatalf("Audit #%d: %v", i, err)
		}
	}

	// Разносим ts созданных строк: 2 часа назад / 1 час назад / сейчас.
	var ids []int64
	rows, err := st.Pool().Query(ctx,
		`SELECT id FROM audit_log WHERE username = $1 ORDER BY id`, name)
	if err != nil {
		t.Fatalf("select ids: %v", err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan id: %v", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) != 3 {
		t.Fatalf("создано %d записей аудита, want 3", len(ids))
	}
	backdate := func(id int64, age time.Duration) {
		t.Helper()
		if _, err := st.Pool().Exec(ctx,
			`UPDATE audit_log SET ts = now() - make_interval(secs => $1) WHERE id = $2`,
			age.Seconds(), id); err != nil {
			t.Fatalf("backdate: %v", err)
		}
	}
	backdate(ids[0], 2*time.Hour)
	backdate(ids[1], 1*time.Hour)

	// Без фильтров (только по username, чтобы изолировать от других тестов):
	// все три, новые сверху.
	list, err := st.AuditList(ctx, AuditFilter{Username: name})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("AuditList: %d записей, want 3", len(list))
	}
	if list[0].Ts.Before(list[1].Ts) || list[1].Ts.Before(list[2].Ts) {
		t.Fatalf("AuditList не отсортирован по ts DESC: %v %v %v", list[0].Ts, list[1].Ts, list[2].Ts)
	}
	if list[0].Event != "login_ok" || list[0].Username != name ||
		list[0].SrcIP != "192.0.2.1" || list[0].Result != "ok" {
		t.Fatalf("верхняя запись: %+v", list[0])
	}
	if list[0].Detail == nil || list[0].Detail["attempt"] != float64(2) {
		t.Fatalf("detail верхней записи: %v (последняя — attempt 2)", list[0].Detail)
	}

	// Фильтр по событию.
	list, err = st.AuditList(ctx, AuditFilter{Username: name, Event: "login_ok"})
	if err != nil {
		t.Fatalf("AuditList(event): %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("AuditList(event=login_ok): %d записей, want 2", len(list))
	}

	// Since/Until (включительно) по отдельности и вместе.
	list, err = st.AuditList(ctx, AuditFilter{Username: name, Since: time.Now().Add(-90 * time.Minute)})
	if err != nil || len(list) != 2 {
		t.Fatalf("AuditList(since=-90m): %d записей (%v), want 2", len(list), err)
	}
	list, err = st.AuditList(ctx, AuditFilter{Username: name, Until: time.Now().Add(-30 * time.Minute)})
	if err != nil || len(list) != 2 {
		t.Fatalf("AuditList(until=-30m): %d записей (%v), want 2", len(list), err)
	}
	list, err = st.AuditList(ctx, AuditFilter{
		Username: name,
		Since:    time.Now().Add(-90 * time.Minute),
		Until:    time.Now().Add(-30 * time.Minute),
	})
	if err != nil || len(list) != 1 {
		t.Fatalf("AuditList(since+until): %d записей (%v), want 1", len(list), err)
	}

	// Limit.
	list, err = st.AuditList(ctx, AuditFilter{Username: name, Limit: 2})
	if err != nil || len(list) != 2 {
		t.Fatalf("AuditList(limit=2): %d записей (%v), want 2", len(list), err)
	}

	// detail=nil → NULL → nil-словарь; пустой username → NULL.
	if err := st.Audit(ctx, name, "code_sent", nil, "", "ok"); err != nil {
		t.Fatalf("Audit без detail: %v", err)
	}
	if err := st.Audit(ctx, "", "system_boot", nil, "", "ok"); err != nil {
		t.Fatalf("Audit без username: %v", err)
	}
	list, err = st.AuditList(ctx, AuditFilter{Username: name, Event: "code_sent"})
	if err != nil || len(list) != 1 {
		t.Fatalf("AuditList(code_sent): %d (%v), want 1", len(list), err)
	}
	if list[0].Detail != nil {
		t.Fatalf("detail = %v, want nil", list[0].Detail)
	}
	if list[0].SrcIP != "" {
		t.Fatalf("src_ip = %q, want \"\"", list[0].SrcIP)
	}

	// Ничего не найдено — пустой список без ошибки.
	list, err = st.AuditList(ctx, AuditFilter{Username: "no-such-user"})
	if err != nil || len(list) != 0 {
		t.Fatalf("AuditList(пусто): %d записей (%v), want 0", len(list), err)
	}
}
