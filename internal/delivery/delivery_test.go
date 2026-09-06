package delivery

import "testing"

// TestRenderTemplate: переменные подставляются до кода (код не может
// подменить {ttl}/{domain}), пустой шаблон = BodyTemplate, неизвестные
// плейсхолдеры остаются как есть.
func TestRenderTemplate(t *testing.T) {
	vars := map[string]string{"ttl": "5 мин", "domain": "https://2fa.example.com"}
	if got := RenderTemplate("Код {code} на {domain}, действует {ttl}", "123456", vars); got != "Код 123456 на https://2fa.example.com, действует 5 мин" {
		t.Errorf("RenderTemplate = %q", got)
	}
	// Код подставляется последним: значение переменной вида {code} не
	// исполняется.
	if got := RenderTemplate("{code}", "{ttl}", nil); got != "{ttl}" {
		t.Errorf("код раньше переменных: %q", got)
	}
	if got := RenderTemplate("", "42", nil); got != "Ваш код подтверждения: 42" {
		t.Errorf("пустой шаблон = %q, want BodyTemplate", got)
	}
	if got := RenderTemplate("{unknown}", "1", vars); got != "{unknown}" {
		t.Errorf("неизвестный плейсхолдер = %q, want как есть", got)
	}
}
