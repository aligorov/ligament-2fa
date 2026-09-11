// Юнит-тесты серверной таблицы переходов support_sessions: единый
// валидатор SupportTransitionAllowed (машина состояний обращений
// удалённой помощи). Интеграционные сценарии — в
// support_transition_integration_test.go.
package store

import (
	"errors"
	"testing"
)

// TestSupportTransitionTableValid — все переходы, разрешённые таблицей.
func TestSupportTransitionTableValid(t *testing.T) {
	valid := []struct {
		from, to string
		actor    SupportActor
	}{
		// Подключение оператора — только к неразыгранной заявке.
		{"requested", "connecting", SupportActorOperator},
		{"requested", "connecting", SupportActorAdmin},
		{"connecting", "connecting", SupportActorOperator}, // повторный запрос кода
		{"connecting", "connecting", SupportActorAdmin},
		// ГЛАВНЫЙ ИНВАРИАНТ: в active — только решение владельца.
		{"requested", "active", SupportActorUser},
		{"connecting", "active", SupportActorUser},
		// Переадресация — только подтверждённой сессии.
		{"active", "transferred", SupportActorAssigned},
		{"active", "transferred", SupportActorAdmin},
		{"transferred", "transferred", SupportActorAssigned},
		{"transferred", "active", SupportActorAssigned}, // accept transfer
		{"transferred", "active", SupportActorAdmin},
		// Отклонение/прерывание владельцем и автоматикой.
		{"requested", "rejected", SupportActorUser},
		{"connecting", "rejected", SupportActorUser},
		{"active", "rejected", SupportActorUser},
		{"transferred", "rejected", SupportActorUser},
		{"connecting", "rejected", SupportActorSystem}, // лимит попыток number-match
		// Отмена до подключения.
		{"requested", "cancelled", SupportActorUser},
		{"connecting", "cancelled", SupportActorAdmin},
		{"requested", "cancelled", SupportActorSystem},
		// Завершение.
		{"requested", "completed", SupportActorUser},
		{"connecting", "completed", SupportActorUser},
		{"active", "completed", SupportActorUser},
		{"active", "completed", SupportActorAssigned},
		{"active", "completed", SupportActorAdmin},
		{"active", "completed", SupportActorSystem}, // TTL 4 часа
		{"transferred", "completed", SupportActorAssigned},
		{"active", "ended_by_admin", SupportActorAdmin},
		{"active", "ended_by_admin", SupportActorAssigned},
		{"connecting", "ended_by_user", SupportActorUser},
		// Истечение — только автоматикой.
		{"requested", "expired", SupportActorSystem},
		{"connecting", "expired", SupportActorSystem},
	}
	for _, c := range valid {
		if err := SupportTransitionAllowed(c.from, c.to, c.actor); err != nil {
			t.Errorf("TransitionAllowed(%s→%s, %s) = %v, want nil", c.from, c.to, c.actor, err)
		}
	}
}

// TestSupportTransitionTableInvalid — запрещённые переходы: эскалации прав,
// обход approve, воскрешение терминальных статусов, чужие роли.
func TestSupportTransitionTableInvalid(t *testing.T) {
	invalid := []struct {
		from, to string
		actor    SupportActor
	}{
		// Оператор/админ/автоматика НЕ могут активировать доступ без
		// подтверждения пользователя — главный инвариант.
		{"requested", "active", SupportActorOperator},
		{"connecting", "active", SupportActorOperator},
		{"requested", "active", SupportActorAssigned},
		{"connecting", "active", SupportActorAdmin},
		{"requested", "active", SupportActorAdmin},
		{"active", "active", SupportActorAdmin}, // повторный «active» — тоже запрещён
		{"transferred", "active", SupportActorOperator},
		// Доступ к экрану до approve: transfer неподтверждённой сессии.
		{"requested", "transferred", SupportActorAdmin},
		{"connecting", "transferred", SupportActorAdmin},
		{"connecting", "transferred", SupportActorAssigned},
		// Воскрешение завершённых сессий запрещено полностью.
		{"completed", "connecting", SupportActorAdmin},
		{"completed", "active", SupportActorUser},
		{"completed", "transferred", SupportActorAdmin},
		{"rejected", "connecting", SupportActorOperator},
		{"cancelled", "connecting", SupportActorOperator},
		{"expired", "active", SupportActorUser},
		{"ended_by_admin", "transferred", SupportActorAdmin},
		{"completed", "completed", SupportActorUser},
		{"completed", "rejected", SupportActorUser},
		{"completed", "ended_by_admin", SupportActorAdmin},
		{"rejected", "rejected", SupportActorUser},
		// Завершение живой сессии посторонним (не назначенным) оператором.
		{"active", "completed", SupportActorOperator},
		{"active", "ended_by_admin", SupportActorOperator},
		{"active", "ended_by_user", SupportActorAdmin},
		{"transferred", "transferred", SupportActorOperator},
		{"active", "transferred", SupportActorOperator},
		// Истечение/отмена — не пользовательскими и не операторскими руками.
		{"requested", "expired", SupportActorAdmin},
		{"requested", "expired", SupportActorUser},
		{"active", "expired", SupportActorSystem}, // active завершается, но не «истекает»
		{"active", "cancelled", SupportActorUser},
		{"transferred", "cancelled", SupportActorAdmin},
		// Пользователь не подключается и не переадресует сам себя.
		{"requested", "connecting", SupportActorUser},
		{"active", "transferred", SupportActorUser},
		{"connecting", "connecting", SupportActorUser},
		// Неизвестные цели.
		{"requested", "hacked", SupportActorAdmin},
	}
	for _, c := range invalid {
		err := SupportTransitionAllowed(c.from, c.to, c.actor)
		if err == nil {
			t.Errorf("TransitionAllowed(%s→%s, %s) = nil, want ErrInvalidTransition", c.from, c.to, c.actor)
			continue
		}
		if !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("TransitionAllowed(%s→%s, %s) = %v, want ErrInvalidTransition", c.from, c.to, c.actor, err)
		}
	}
}

// TestSupportTerminalStatuses — перечень терминальных статусов.
func TestSupportTerminalStatuses(t *testing.T) {
	for _, s := range []string{"rejected", "completed", "cancelled", "expired", "ended_by_admin", "ended_by_user"} {
		if !SupportIsTerminal(s) {
			t.Errorf("SupportIsTerminal(%q) = false, want true", s)
		}
	}
	for _, s := range SupportLiveStatuses() {
		if SupportIsTerminal(s) {
			t.Errorf("SupportIsTerminal(%q) = true, want false (живой статус)", s)
		}
	}
}
