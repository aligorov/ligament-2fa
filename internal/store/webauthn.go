// Репозиторий WebAuthn-учётных данных: плоские колонки 1:1 с
// webauthn.Credential (паттерн Authelia), без JSON-блоба.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// WACred — строка таблицы webauthn_credentials (passkey/ключ).
type WACred struct {
	ID                int64
	CredentialID      []byte
	RPID              string
	PublicKey         []byte
	SignCount         uint32
	CloneWarning      bool
	AAGUID            string
	AttestationType   string
	AttestationFormat string
	Attachment        string
	Transports        string // через запятую: "usb,nfc"
	Name              string
	Present           bool
	Verified          bool
	BackupEligible    bool
	BackupState       bool
	LastUsedAt        *time.Time
}

// waCredCols — список колонок webauthn_credentials для SELECT/сканирования;
// nullable текстовые колонки читаются как пустые строки.
const waCredCols = `id, credential_id, rpid, public_key, sign_count, clone_warning,
	COALESCE(aaguid, ''), COALESCE(attestation_type, ''), COALESCE(attestation_format, ''),
	COALESCE(attachment, ''), transports, name, present, verified,
	backup_eligible, backup_state, last_used_at`

// scanWACred сканирует строку webauthn_credentials (колонки в порядке
// waCredCols); sign_count (BIGINT) читается через int64.
func scanWACred(row scanner) (WACred, error) {
	var (
		c         WACred
		signCount int64
	)
	if err := row.Scan(
		&c.ID, &c.CredentialID, &c.RPID, &c.PublicKey, &signCount,
		&c.CloneWarning, &c.AAGUID, &c.AttestationType, &c.AttestationFormat,
		&c.Attachment, &c.Transports, &c.Name, &c.Present, &c.Verified,
		&c.BackupEligible, &c.BackupState, &c.LastUsedAt,
	); err != nil {
		return WACred{}, err
	}
	c.SignCount = uint32(signCount)
	return c, nil
}

// WACredUpsert вставляет учётные данные или обновляет существующие по
// credential_id (public_key/sign_count/флаги и т.д.). user_id при конфликте
// не меняется: повторная регистрация чужого credential_id не переносит
// владение. ID заполняется из RETURNING.
func (s *Store) WACredUpsert(ctx context.Context, userID uuid.UUID, c *WACred) error {
	err := s.Pool().QueryRow(ctx, `INSERT INTO webauthn_credentials
		(user_id, credential_id, rpid, public_key, sign_count, clone_warning,
		 aaguid, attestation_type, attestation_format, attachment, transports,
		 present, verified, backup_eligible, backup_state, name, last_used_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (credential_id) DO UPDATE SET
			rpid = EXCLUDED.rpid,
			public_key = EXCLUDED.public_key,
			sign_count = EXCLUDED.sign_count,
			clone_warning = EXCLUDED.clone_warning,
			aaguid = EXCLUDED.aaguid,
			attestation_type = EXCLUDED.attestation_type,
			attestation_format = EXCLUDED.attestation_format,
			attachment = EXCLUDED.attachment,
			transports = EXCLUDED.transports,
			present = EXCLUDED.present,
			verified = EXCLUDED.verified,
			backup_eligible = EXCLUDED.backup_eligible,
			backup_state = EXCLUDED.backup_state,
			name = EXCLUDED.name,
			last_used_at = EXCLUDED.last_used_at
		RETURNING id`,
		userID, c.CredentialID, c.RPID, c.PublicKey, c.SignCount, c.CloneWarning,
		c.AAGUID, c.AttestationType, c.AttestationFormat, c.Attachment,
		c.Transports, c.Present, c.Verified, c.BackupEligible, c.BackupState,
		c.Name, c.LastUsedAt).Scan(&c.ID)
	if err != nil {
		return fmt.Errorf("store: upsert webauthn-credential: %w", err)
	}
	return nil
}

// WACredListForUser возвращает учётные данные пользователя, старые первыми.
func (s *Store) WACredListForUser(ctx context.Context, userID uuid.UUID) ([]WACred, error) {
	rows, err := s.Pool().Query(ctx, `SELECT `+waCredCols+` FROM webauthn_credentials
		WHERE user_id = $1
		ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: список webauthn-credentials %s: %w", userID, err)
	}
	defer rows.Close()
	var out []WACred
	for rows.Next() {
		c, err := scanWACred(rows)
		if err != nil {
			return nil, fmt.Errorf("store: список webauthn-credentials %s: %w", userID, err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: список webauthn-credentials %s: %w", userID, err)
	}
	return out, nil
}

// WACredUpdateSignIn обновляет метки входа по credential_id: sign_count,
// clone_warning и last_used_at; ErrNotFound, если записи нет.
func (s *Store) WACredUpdateSignIn(ctx context.Context, credID []byte, signCount uint32, cloneWarning bool) error {
	ct, err := s.Pool().Exec(ctx, `UPDATE webauthn_credentials
		SET sign_count = $2, clone_warning = $3, last_used_at = now()
		WHERE credential_id = $1`, credID, signCount, cloneWarning)
	if err != nil {
		return fmt.Errorf("store: обновление входа webauthn-credential: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// WACredDelete удаляет учётные данные; userID — проверка принадлежности;
// ErrNotFound, если записи нет.
func (s *Store) WACredDelete(ctx context.Context, id int64, userID uuid.UUID) error {
	ct, err := s.Pool().Exec(ctx,
		`DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return fmt.Errorf("store: удалить webauthn-credential %d: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// WACredsDeleteForUser удаляет все учётные данные пользователя
// (admin reset-webauthn); идемпотентно.
func (s *Store) WACredsDeleteForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := s.Pool().Exec(ctx,
		`DELETE FROM webauthn_credentials WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("store: удалить webauthn-credentials %s: %w", userID, err)
	}
	return nil
}
