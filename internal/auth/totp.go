package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"

	"github.com/aligorov/twofa/internal/store"
)

// verifyTOTP проверяет TOTP-код пользователя с replay-защитой:
//
//  1. секрет читается из БД и расшифровывается с AAD по username
//     (AADTOTP) — секрет, скопированный в другую учётную запись, не
//     расшифруется;
//  2. код проверяется totp.ValidateCustom (SHA-1, период/digits из строки
//     totp_secrets, skew из настроек);
//  3. среди счётчиков окна (C-skew .. C+skew, где C = unix/period) ищется
//     НАИВЫСШИЙ счётчик, порождающий этот код; он обязан быть строго больше
//     last_timestep — уже потраченного счётчика, иначе код считается
//     переиспользованным (одно окно — одна попытка);
//  4. успех поднимает last_timestep (TOTPSetTimestep, CAS «строго больше» —
//     без отката и без двойной траты одного окна двумя конкурентными
//     проверками).
//
// Ошибки: store.ErrNotFound — TOTP не настроен; ErrBadCode — неверный или
// переиспользованный код (включая неподтверждённый секрет).
func (c *Core) verifyTOTP(ctx context.Context, user *store.User, code string) error {
	secretEnc, digits, period, confirmed, lastTimestep, err := c.st.TOTPGet(ctx, user.ID)
	if err != nil {
		return err // store.ErrNotFound — TOTP не настроен
	}
	if !confirmed {
		return ErrBadCode
	}
	secret, err := c.box.DecryptAAD(AADTOTP(user.Username), secretEnc)
	if err != nil {
		return fmt.Errorf("auth: расшифровка TOTP-секрета %s: %w", user.Username, err)
	}

	now := time.Now().UTC()
	skew := c.set.Get().TOTP.Skew
	ok, err := totp.ValidateCustom(code, string(secret), now, totp.ValidateOpts{
		Period:    uint(period),
		Skew:      skew,
		Digits:    otp.Digits(digits),
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return fmt.Errorf("auth: TOTP-проверка %s: %w", user.Username, err)
	}
	if !ok {
		return ErrBadCode
	}

	// Replay-защита: тот же диапазон счётчиков, что проверяет
	// ValidateCustom; берём наивысший совпавший.
	cur := now.Unix() / int64(period)
	hotpOpts := hotp.ValidateOpts{Digits: otp.Digits(digits), Algorithm: otp.AlgorithmSHA1}
	var matched int64 = -1
	for cnt := cur - int64(skew); cnt <= cur+int64(skew); cnt++ {
		if cnt < 0 {
			continue
		}
		want, err := hotp.GenerateCodeCustom(string(secret), uint64(cnt), hotpOpts)
		if err != nil {
			continue
		}
		if want == code && cnt > matched {
			matched = cnt
		}
	}
	if matched < 0 || matched <= lastTimestep {
		return ErrBadCode
	}
	advanced, err := c.st.TOTPSetTimestep(ctx, user.ID, matched)
	if err != nil {
		return fmt.Errorf("auth: обновление last_timestep %s: %w", user.Username, err)
	}
	if !advanced {
		// CAS проигран: конкурентный запрос уже потратил это окно — тот же
		// код второй раз успехом не считается (replay).
		return ErrBadCode
	}
	return nil
}
