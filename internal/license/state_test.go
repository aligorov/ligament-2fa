// Юнит-тесты машины состояний (чистая логика без БД): free/trial/licensed,
// истечение подписки с grace-окном, отзыв CRL, perpetual, гейт build-date.
package license

import (
	"errors"
	"testing"
	"time"
)

// fakeNow — фиксированное «сейчас» для детерминизма.
var fakeNow = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

// mkLicense — подписанный blob с доверенным ключом kid.
func mkLicense(t *testing.T, kid string, mutate func(*Payload)) string {
	t.Helper()
	_, priv := withTestKeys(t, kid)
	p := testPayload()
	p.Kid = kid
	if mutate != nil {
		mutate(&p)
	}
	blob, err := Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return blob
}

func days(n int) time.Time { return fakeNow.Add(time.Duration(n) * 24 * time.Hour) }

// TestStateFree: без лицензии и без trial — лимит FreeUserLimit.
func TestStateFree(t *testing.T) {
	st := computeStatus(fakeNow, "", "", nil, false)
	if st.Mode != ModeFree {
		t.Fatalf("режим = %s, хочу free", st.Mode)
	}
	if st.UserLimit != FreeUserLimit {
		t.Fatalf("лимит free = %d, хочу %d", st.UserLimit, FreeUserLimit)
	}
}

// TestStateTrial: 30 дней full-featured от первого старта, лимит не
// ограничен; за 10 дней до конца — TrialDaysLeft=10.
func TestStateTrial(t *testing.T) {
	start := days(-20)
	st := computeStatus(fakeNow, "", "", &start, false)
	if st.Mode != ModeTrial {
		t.Fatalf("режим = %s, хочу trial", st.Mode)
	}
	if st.UserLimit > 0 {
		t.Fatalf("trial: лимит должен быть не ограничен, есть %d", st.UserLimit)
	}
	if st.TrialDaysLeft != 10 {
		t.Fatalf("осталось демо = %d, хочу 10", st.TrialDaysLeft)
	}
}

// TestStateTrialExpired: демо истекло → Free(5), НЕ хард-блок (report §3.1).
func TestStateTrialExpired(t *testing.T) {
	start := days(-31)
	st := computeStatus(fakeNow, "", "", &start, false)
	if st.Mode != ModeFree || st.UserLimit != FreeUserLimit {
		t.Fatalf("после демо: %+v, хочу free/%d", st, FreeUserLimit)
	}
}

// TestStateLicensed: валидная подписка — лимит из payload, UpdatesUntil.
func TestStateLicensed(t *testing.T) {
	blob := mkLicense(t, "k-lic", nil)
	st := computeStatus(fakeNow, blob, "", nil, false)
	if st.Mode != ModeLicensed {
		t.Fatalf("режим = %s, хочу licensed", st.Mode)
	}
	if st.UserLimit != 25 {
		t.Fatalf("лимит = %d, хочу 25", st.UserLimit)
	}
	if st.DaysLeft != 360 { // 2026-09-06T12:00 → 2027-09-01T00:00, округление вверх
		t.Fatalf("дней подписки = %d, хочу 360", st.DaysLeft)
	}
	if !st.UpdatesUntil.Equal(time.Date(2027, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("updates_until = %v", st.UpdatesUntil)
	}
	if st.Customer != "ООО Ромашка" || st.LicID == "" {
		t.Fatalf("метаданные потерялись: %+v", st)
	}
}

// TestStateSubscriptionGrace: истекла, но в пределах grace (5 дней) —
// licensed, Grace=true; после grace → Free(5), Expired=true.
func TestStateSubscriptionGrace(t *testing.T) {
	// Истекла 3 дня назад — grace действует.
	blob := mkLicense(t, "k-grace", func(p *Payload) {
		exp := days(-3)
		p.ExpiresAt = &exp
		p.MaintenanceExpires = exp
	})
	st := computeStatus(fakeNow, blob, "", nil, false)
	if st.Mode != ModeLicensed || !st.Grace {
		t.Fatalf("grace: %+v, хочу licensed+grace", st)
	}

	// Истекла 6 дней назад — лицензия погасла.
	blob = mkLicense(t, "k-grace", func(p *Payload) {
		exp := days(-6)
		p.ExpiresAt = &exp
		p.MaintenanceExpires = exp
	})
	st = computeStatus(fakeNow, blob, "", nil, false)
	if st.Mode != ModeFree || st.UserLimit != FreeUserLimit || !st.Expired {
		t.Fatalf("после grace: %+v, хочу free/5/expired", st)
	}
}

// TestStatePerpetual: бессрочная — licensed всегда, updates до maintenance.
func TestStatePerpetual(t *testing.T) {
	blob := mkLicense(t, "k-perp", func(p *Payload) {
		p.Plan = PlanPerpetual
		p.ExpiresAt = nil
		p.MaintenanceExpires = days(400)
	})
	st := computeStatus(fakeNow, blob, "", nil, false)
	if st.Mode != ModeLicensed || st.UserLimit != 25 {
		t.Fatalf("perpetual: %+v", st)
	}
	if !st.UpdatesUntil.Equal(days(400)) {
		t.Fatalf("maintenance = %v", st.UpdatesUntil)
	}

	// Даже очень старая perpetual — работает (право на купленные версии).
	old := mkLicense(t, "k-perp", func(p *Payload) {
		p.Plan = PlanPerpetual
		p.ExpiresAt = nil
		p.MaintenanceExpires = days(-3650)
	})
	if st := computeStatus(fakeNow, old, "", nil, false); st.Mode != ModeLicensed {
		t.Fatalf("старая perpetual: %+v", st)
	}
}

// TestStateCRLSkipsPerpetual: CRL отзывает ТОЛЬКО подписки (report §3.5,
// README «Perpetual технически не отзывается») — perpetual с совпадающим
// lic_id остаётся licensed, подписка с тем же lic_id гаснет в free+revoked.
func TestStateCRLSkipsPerpetual(t *testing.T) {
	// Одна пара ключей на лицензии и CRL (mkLicense перевыпускает ключи).
	_, priv := withTestKeys(t, "k-perp-rev")
	perpPayload := testPayload()
	perpPayload.Kid = "k-perp-rev"
	perpPayload.Plan = PlanPerpetual
	perpPayload.ExpiresAt = nil
	perpPayload.MaintenanceExpires = days(400)
	perp, err := Sign(priv, perpPayload)
	if err != nil {
		t.Fatalf("Sign perpetual: %v", err)
	}
	subPayload := testPayload() // тот же lic_id, но подписка
	subPayload.Kid = "k-perp-rev"
	sub, err := Sign(priv, subPayload)
	if err != nil {
		t.Fatalf("Sign subscription: %v", err)
	}
	rev, err := SignRevocation(priv, Revocation{
		LicID: "11111111-2222-3333-4444-555555555555", RevokedAt: fakeNow, Kid: "k-perp-rev",
	})
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}

	if st := computeStatus(fakeNow, perp, rev, nil, false); st.Mode != ModeLicensed || st.Revoked {
		t.Fatalf("perpetual+CRL: %+v, хочу licensed без отзыва", st)
	}
	if st := computeStatus(fakeNow, sub, rev, nil, false); st.Mode != ModeFree || !st.Revoked {
		t.Fatalf("subscription+CRL: %+v, хочу free+revoked", st)
	}
}

// TestStateTrialUsedBlocksResurrection: маркер license.trial_used (его
// ставит Upload лицензии и никто не удаляет) гасит демо навсегда —
// удаление лицензии не воскрешает оставшиеся дни триала.
func TestStateTrialUsedBlocksResurrection(t *testing.T) {
	start := days(-3) // демо активно ещё 27 дней
	st := computeStatus(fakeNow, "", "", &start, true)
	if st.Mode != ModeFree || st.UserLimit != FreeUserLimit {
		t.Fatalf("trial_used: %+v, хочу free/%d", st, FreeUserLimit)
	}
}

// TestStateRevoked: CRL на lic_id лицензии → Free(5) + Revoked.
func TestStateRevoked(t *testing.T) {
	_, priv := withTestKeys(t, "k-rev")
	p := testPayload()
	p.Kid = "k-rev"
	blob, err := Sign(priv, p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	rev, err := SignRevocation(priv, Revocation{
		LicID: "11111111-2222-3333-4444-555555555555", RevokedAt: fakeNow, Kid: "k-rev",
	})
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}
	st := computeStatus(fakeNow, blob, rev, nil, false)
	if st.Mode != ModeFree || st.UserLimit != FreeUserLimit || !st.Revoked {
		t.Fatalf("revoked: %+v, хочу free/5/revoked", st)
	}
	if st.LicID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("lic_id отзыва потерян: %+v", st)
	}

	// CRL на ДРУГУЮ лицензию не действует.
	other, err := SignRevocation(priv, Revocation{
		LicID: "99999999-9999-9999-9999-999999999999", RevokedAt: fakeNow, Kid: "k-rev",
	})
	if err != nil {
		t.Fatalf("SignRevocation other: %v", err)
	}
	if st := computeStatus(fakeNow, blob, other, nil, false); st.Mode != ModeLicensed {
		t.Fatalf("чужой CRL погасил лицензию: %+v", st)
	}
}

// TestStateBrokenBlob: битый/непроверяемый blob → деградация в free (не
// авария сервера).
func TestStateBrokenBlob(t *testing.T) {
	st := computeStatus(fakeNow, "мусор", "", nil, false)
	if st.Mode != ModeFree || st.UserLimit != FreeUserLimit {
		t.Fatalf("битый blob: %+v, хочу free/5", st)
	}
}

// TestCheckBuildAllowed: матрица гейта обновлений (report §3.4).
func TestCheckBuildAllowed(t *testing.T) {
	licensed := Status{Mode: ModeLicensed, UpdatesUntil: time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)}
	free := Status{Mode: ModeFree, UserLimit: FreeUserLimit}
	trial := Status{Mode: ModeTrial}

	cases := []struct {
		name      string
		buildDate string
		st        Status
		wantErr   bool
	}{
		{"free всегда можно", "2030-01-01", free, false},
		{"trial всегда можно", "2030-01-01", trial, false},
		{"licensed без buildDate", "", licensed, false},
		{"сборка до окна", "2026-08-31", licensed, false},
		{"сборка в день окна", "2026-09-01", licensed, false},
		{"сборка после окна", "2026-09-02", licensed, true},
		{"сборка много позже", "2027-01-01", licensed, true},
		{"битая дата — fail open", "not-a-date", licensed, false},
	}
	for _, c := range cases {
		err := CheckBuildAllowed(c.buildDate, c.st)
		if c.wantErr && err == nil {
			t.Errorf("%s: ожидалась ошибка гейта", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: неожиданная ошибка: %v", c.name, err)
		}
		if c.wantErr && err != nil && !errors.Is(err, ErrBuildTooNew) {
			t.Errorf("%s: ошибка = %v, хочу ErrBuildTooNew", c.name, err)
		}
	}
}
