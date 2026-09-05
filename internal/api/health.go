// Health-эндпоинт /healthz: живость процесса и доступность PostgreSQL.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/aligorov/twofa/internal/store"
)

// healthzHandler возвращает обработчик /healthz. st == nil (минимальный
// роутер smoke-тестов NewRouter) — проверяется только сам процесс; иначе —
// SELECT 1 через пул: БД недоступна → 503 {"status":"db_error"} (балансировщик
// снимает экземпляр с ротации, не дождавшись TCP/5xx таймаутов на запросах).
func healthzHandler(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st != nil {
			var one int
			if err := st.Pool().QueryRow(r.Context(), `SELECT 1`).Scan(&one); err != nil || one != 1 {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db_error"})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}
