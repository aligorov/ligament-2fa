//go:build integration

// Интеграционные тесты машины состояний обращений (support_sessions) на
// уровне HTTP API: строгая последовательность действий — доступ оператора
// к рабочему столу возможен только после approve пользователя с верным
// number-match; повторное подключение/переадресация завершённых сессий —
// 409; дедупликация обращений; смена access_mode после approve невозможна.
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/store"
)

// supportFlow — окружение одного сценария: пользователь, два инженера
// поддержки (it) и «чужой» инженер 1С, авторизованные app-токенами.
type supportFlow struct {
	t         *testing.T
	h         http.Handler
	adminTok  string
	userTok   string
	userDevID string
	user      *store.User
	it1Tok    string
	it2Tok    string
	c1cTok    string
}

func newSupportFlow(t *testing.T, name string) *supportFlow {
	t.Helper()
	st, set, box := setup(t)
	rt := newPagesRouter(t, st, set, box)
	t.Cleanup(rt.Stop)

	user := mkUser(t, t.Context(), st, name, nil)
	it1 := mkUser(t, t.Context(), st, name+"it1", func(u *store.User) { u.SupportRoles = []string{"it"} })
	it2 := mkUser(t, t.Context(), st, name+"it2", func(u *store.User) { u.SupportRoles = []string{"it"} })
	c1c := mkUser(t, t.Context(), st, name+"c1c", func(u *store.User) { u.SupportRoles = []string{"1c"} })

	login := func(u *store.User) (string, string) {
		rec := appLogin(t, rt.Handler, u.Username, testPassword)
		wantStatus(t, rec, http.StatusOK)
		b := jsonBody(t, rec)
		tok, _ := b["token"].(string)
		devID, _ := b["device_id"].(string)
		return tok, devID
	}
	userTok, userDevID := login(user)
	it1Tok, _ := login(it1)
	it2Tok, _ := login(it2)
	c1cTok, _ := login(c1c)

	return &supportFlow{
		t: t, h: rt.Handler, adminTok: set.Get().AdminToken,
		userTok: userTok, userDevID: userDevID, user: user,
		it1Tok: it1Tok, it2Tok: it2Tok, c1cTok: c1cTok,
	}
}

// req — JSON-запрос с опциональным Bearer-токеном.
func (f *supportFlow) req(method, path, token string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// request — новое обращение от пользователя; возвращает ID сессии.
func (f *supportFlow) request(accessMode string) uuid.UUID {
	f.t.Helper()
	rec := f.req(http.MethodPost, "/api/v1/app/support/request", f.userTok, map[string]string{
		"category":        "it",
		"problem_summary": "не запускается 1С",
		"access_mode":     accessMode,
	})
	wantStatus(f.t, rec, http.StatusOK)
	id, _ := jsonBody(f.t, rec)["id"].(string)
	return uuidMustParse(f.t, id)
}

// connect — подключение инженера; возвращает сгенерированный код.
func (f *supportFlow) connect(id uuid.UUID, tok string) string {
	f.t.Helper()
	rec := f.req(http.MethodPost, "/api/v1/app/support/"+id.String()+"/connect", tok, map[string]string{})
	wantStatus(f.t, rec, http.StatusOK)
	nm, _ := jsonBody(f.t, rec)["number_match"].(string)
	if nm == "" {
		f.t.Fatalf("connect без number_match: %s", rec.Body.String())
	}
	return nm
}

// adminGet — чтение сессии глобальным admin-токеном.
func (f *supportFlow) adminGet(id uuid.UUID) *store.SupportSession {
	f.t.Helper()
	rec := f.req(http.MethodGet, "/api/v1/admin/support/sessions/"+id.String(), f.adminTok, nil)
	wantStatus(f.t, rec, http.StatusOK)
	var ss store.SupportSession
	if err := json.Unmarshal(rec.Body.Bytes(), &ss); err != nil {
		f.t.Fatalf("adminGet unmarshal: %v (%s)", err, rec.Body.String())
	}
	return &ss
}

// decision — approve/deny пользователя.
func (f *supportFlow) decision(id uuid.UUID, decision, nm string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.req(http.MethodPost, "/api/v1/app/support/"+id.String()+"/decision", f.userTok,
		map[string]string{"decision": decision, "number_match": nm})
}

// TestSupportFSMNoActiveWithoutUserDecision — инвариант: active достижим
// только решением владельца с верным кодом. Все обходные пути закрыты.
func TestSupportFSMNoActiveWithoutUserDecision(t *testing.T) {
	f := newSupportFlow(t, "fsm1")

	// 1. Подтверждение до подключения оператора невозможно.
	id := f.request("view_only")
	rec := f.decision(id, "approve", "")
	wantStatus(t, rec, http.StatusConflict) // no_operator_connected

	// 2. Код обязателен: approve с неверным кодом не проходит.
	f.connect(id, f.it1Tok)
	rec = f.decision(id, "approve", "00")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("approve с неверным кодом: %d (%s), want 400", rec.Code, rec.Body.String())
	}
	// 3. Подобрать код нельзя: после 3 несовпадений сессия гасится.
	f.decision(id, "approve", "01")
	rec = f.decision(id, "approve", "02")
	wantStatus(t, rec, http.StatusConflict)
	if ss := f.adminGet(id); ss.Status != "rejected" {
		t.Fatalf("после 3 несовпадений: status=%s, want rejected", ss.Status)
	}

	// 4. Полный штатный цикл: connect → approve с верным кодом → active.
	id2 := f.request("view_only")
	nm2 := f.connect(id2, f.it1Tok)
	rec = f.decision(id2, "approve", nm2)
	wantStatus(t, rec, http.StatusOK)
	ss := f.adminGet(id2)
	if ss.Status != "active" || ss.StartedAt == nil || ss.NumberMatch != "" {
		t.Fatalf("после approve: status=%s started=%v nm=%q, want active/started/погашен", ss.Status, ss.StartedAt, ss.NumberMatch)
	}
	// access_mode неизменяем после approve (никакой путь его не меняет).
	if ss.AccessMode != "view_only" {
		t.Fatalf("access_mode после approve: %s, want view_only", ss.AccessMode)
	}
	if ss.AssignedAdminID == nil {
		t.Fatal("active без назначенного оператора (assigned_admin_id nil)")
	}
}

// TestSupportFSMInvalidTransitions — каждый нештатный переход → 409.
func TestSupportFSMInvalidTransions(t *testing.T) {
	f := newSupportFlow(t, "fsm2")

	// Полный цикл до завершения.
	id := f.request("full_control")
	nm := f.connect(id, f.it1Tok)
	wantStatus(t, f.decision(id, "approve", nm), http.StatusOK)
	// Повторный approve уже активной сессии.
	wantStatus(t, f.decision(id, "approve", nm), http.StatusConflict)
	// Второй оператор не может «переподключиться» к активной сессии.
	rec := f.req(http.MethodPost, "/api/v1/app/support/"+id.String()+"/connect", f.it2Tok, map[string]string{})
	wantStatus(t, rec, http.StatusConflict)

	// Завершение пользователем.
	rec = f.req(http.MethodPost, "/api/v1/app/support/"+id.String()+"/end", f.userTok, nil)
	wantStatus(t, rec, http.StatusOK)
	if ss := f.adminGet(id); ss.Status != "completed" {
		t.Fatalf("end: status=%s, want completed", ss.Status)
	}

	// ВСЁ к завершённой сессии — 409: повторный connect, decision,
	// end, transfer, admin end, admin connect.
	admin := func(method, path string, body any) *httptest.ResponseRecorder {
		return f.req(method, path, f.adminTok, body)
	}
	base := "/api/v1/admin/support/sessions/" + id.String()
	wantStatus(t, f.req(http.MethodPost, "/api/v1/app/support/"+id.String()+"/connect", f.it1Tok, nil), http.StatusConflict)
	wantStatus(t, f.decision(id, "approve", nm), http.StatusConflict)
	wantStatus(t, f.decision(id, "deny", ""), http.StatusConflict)
	wantStatus(t, f.req(http.MethodPost, "/api/v1/app/support/"+id.String()+"/end", f.userTok, nil), http.StatusConflict)
	wantStatus(t, admin(http.MethodPost, base+"/connect", nil), http.StatusConflict)
	wantStatus(t, admin(http.MethodPost, base+"/end", nil), http.StatusConflict)
	wantStatus(t, admin(http.MethodPost, base+"/transfer", map[string]string{}), http.StatusConflict)
}

// TestSupportFSMTransferRequiresApprovedSession — переадресация только из
// active/transferred: transfer неподтверждённой сессии (обход approve по
// transfer-токену) и завершённой — 409.
func TestSupportFSMTransferRequiresApprovedSession(t *testing.T) {
	f := newSupportFlow(t, "fsm3")

	// Неподтверждённая сессия: transfer запрещён.
	id := f.request("full_control")
	f.connect(id, f.it1Tok)
	rec := f.req(http.MethodPost, "/api/v1/admin/support/sessions/"+id.String()+"/transfer", f.adminTok,
		map[string]string{"to_user_id": ""})
	wantStatus(t, rec, http.StatusConflict)

	// Подтверждённая — можно.
	nm := f.connect(id, f.it1Tok)
	wantStatus(t, f.decision(id, "approve", nm), http.StatusOK)
	rec = f.req(http.MethodPost, "/api/v1/admin/support/sessions/"+id.String()+"/transfer", f.adminTok,
		map[string]string{"to_user_id": ""})
	wantStatus(t, rec, http.StatusOK)
	if ss := f.adminGet(id); ss.Status != "transferred" {
		t.Fatalf("transfer: status=%s, want transferred", ss.Status)
	}
}

// TestSupportFSMDuplicateRequests — одна живая сессия на пользователя:
// повторное обращение в pending заменяет старое, при активной сессии — 409.
func TestSupportFSMDuplicateRequests(t *testing.T) {
	f := newSupportFlow(t, "fsm4")

	// Pending-обращение заменяется новым.
	id1 := f.request("full_control")
	id2 := f.request("full_control")
	if ss := f.adminGet(id1); ss.Status != "cancelled" {
		t.Fatalf("старое обращение: status=%s, want cancelled", ss.Status)
	}
	if ss := f.adminGet(id2); ss.Status != "requested" {
		t.Fatalf("новое обращение: status=%s, want requested", ss.Status)
	}

	// Активная сессия — новое обращение отклоняется.
	nm := f.connect(id2, f.it1Tok)
	wantStatus(t, f.decision(id2, "approve", nm), http.StatusOK)
	rec := f.req(http.MethodPost, "/api/v1/app/support/request", f.userTok, map[string]string{
		"category": "it", "problem_summary": "ещё одна проблема",
	})
	wantStatus(t, rec, http.StatusConflict)
}

// TestSupportFSMOperatorSeesOnlyOwnCategories — инженер 1С не видит и не
// подключает IT-обращения; queue фильтруется по ролям.
func TestSupportFSMOperatorSeesOnlyOwnCategories(t *testing.T) {
	f := newSupportFlow(t, "fsm5")

	id := f.request("full_control")

	// Очередь инженера 1С не содержит IT-обращение.
	rec := f.req(http.MethodGet, "/api/v1/app/support/queue", f.c1cTok, nil)
	wantStatus(t, rec, http.StatusOK)
	if bytes.Contains(rec.Body.Bytes(), []byte(id.String())) {
		t.Fatalf("IT-сессия видна инженеру 1С в очереди: %s", rec.Body.String())
	}

	// Connect чужой категории — 403.
	rec = f.req(http.MethodPost, "/api/v1/app/support/"+id.String()+"/connect", f.c1cTok, map[string]string{})
	wantStatus(t, rec, http.StatusForbidden)

	// Админ-список для инженера 1С тоже отфильтрован.
	rec = f.req(http.MethodGet, "/api/v1/admin/support/sessions", f.c1cTok, nil)
	wantStatus(t, rec, http.StatusOK)
	if bytes.Contains(rec.Body.Bytes(), []byte(id.String())) {
		t.Fatalf("IT-сессия видна инженеру 1С в admin-списке: %s", rec.Body.String())
	}

	// Прямой GET деталей сессии и чата чужой категории — 403.
	wantStatus(t, f.req(http.MethodGet, "/api/v1/admin/support/sessions/"+id.String(), f.c1cTok, nil), http.StatusForbidden)
	wantStatus(t, f.req(http.MethodGet, "/api/v1/admin/support/sessions/"+id.String()+"/messages", f.c1cTok, nil), http.StatusForbidden)
	// Инженер своей категории детали видит, админ — тоже.
	wantStatus(t, f.req(http.MethodGet, "/api/v1/admin/support/sessions/"+id.String(), f.it1Tok, nil), http.StatusOK)
	wantStatus(t, f.req(http.MethodGet, "/api/v1/admin/support/sessions/"+id.String(), f.adminTok, nil), http.StatusOK)
}

// TestSupportFSMSignalOnlyAssigned — сигналинг активной сессии доступен
// назначенному оператору и админу; посторонний инженер отсечён.
func TestSupportFSMSignalOnlyAssigned(t *testing.T) {
	f := newSupportFlow(t, "fsm6")

	id := f.request("full_control")
	nm := f.connect(id, f.it1Tok) // it1 — назначенный оператор
	wantStatus(t, f.decision(id, "approve", nm), http.StatusOK)

	sig := map[string]any{"candidate": map[string]any{"candidate": "candidate:1"}}
	// Назначенный — может.
	wantStatus(t, f.req(http.MethodPost, "/api/v1/app/support/"+id.String()+"/signal", f.userTok, sig), http.StatusOK)

	// Посторонний инженер (it2, не назначен) — нет: через admin-ручку
	// signal закрыт (403), а app-рука signal принадлежит пользователю.
	rec := f.req(http.MethodPost, "/api/v1/admin/support/sessions/"+id.String()+"/signal", f.it2Tok, sig)
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
		t.Fatalf("signal постороннего инженера: %d (%s), want 401/403", rec.Code, rec.Body.String())
	}
	// Назначенный оператор через admin-ручку — может (app-токен it1).
	wantStatus(t, f.req(http.MethodPost, "/api/v1/admin/support/sessions/"+id.String()+"/signal", f.it1Tok, sig), http.StatusOK)

	// Завершённой сессии сигнал недоступен никому.
	rec = f.req(http.MethodPost, "/api/v1/app/support/"+id.String()+"/end", f.userTok, nil)
	wantStatus(t, rec, http.StatusOK)
	wantStatus(t, f.req(http.MethodPost, "/api/v1/admin/support/sessions/"+id.String()+"/signal", f.adminTok, sig), http.StatusConflict)
}
