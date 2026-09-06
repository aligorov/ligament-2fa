// OpenID Connect Provider: клиенты (relying party), authorization-коды и
// access-токены. Коды и токены хранятся только хешами SHA-256; код
// одноразовый — погашение атомарным UPDATE ... WHERE used_at IS NULL
// (0 строк = код истёк, погашен или неизвестен → replay невозможен).
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// OIDCClient — клиентское приложение (relying party) OIDC.
// ClientSecretHash — строка «salt$hash» (см. internal/oidc); у public-клиентов
// пуста: они аутентифицируются только PKCE, без секрета.
type OIDCClient struct {
	ID               uuid.UUID `json:"id"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash string    `json:"-"`
	Name             string    `json:"name"`
	RedirectURIs     []string  `json:"redirect_uris"`
	IsPublic         bool      `json:"is_public"`
	CreatedAt        time.Time `json:"created_at"`
}

// OIDCCode — authorization-код (запись oidc_codes без хеша).
type OIDCCode struct {
	ClientID            string
	UserID              uuid.UUID
	RedirectURI         string
	Scope               string
	Nonce               string
	AuthTime            time.Time
	AMR                 string
	CodeChallenge       string
	CodeChallengeMethod string
}

// OIDCToken — access-токен /userinfo (запись oidc_tokens без хеша).
type OIDCToken struct {
	UserID    uuid.UUID
	ClientID  string
	Scope     string
	AMR       string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// OIDCClientUpsert создаёт клиента или обновляет по client_id (name,
// redirect_uris, is_public, client_secret_hash). ID и created_at
// возвращаются из БД.
func (s *Store) OIDCClientUpsert(ctx context.Context, c *OIDCClient) error {
	err := s.Pool().QueryRow(ctx, `
		INSERT INTO oidc_clients (client_id, client_secret_hash, name, redirect_uris, is_public)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (client_id) DO UPDATE SET
		  client_secret_hash = EXCLUDED.client_secret_hash,
		  name = EXCLUDED.name,
		  redirect_uris = EXCLUDED.redirect_uris,
		  is_public = EXCLUDED.is_public
		RETURNING id, created_at`,
		c.ClientID, c.ClientSecretHash, c.Name, c.RedirectURIs, c.IsPublic).
		Scan(&c.ID, &c.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: oidc_clients upsert %s: %w", c.ClientID, err)
	}
	return nil
}

// OIDCClients возвращает всех клиентов по времени создания.
func (s *Store) OIDCClients(ctx context.Context) ([]OIDCClient, error) {
	rows, err := s.Pool().Query(ctx, `
		SELECT id, client_id, client_secret_hash, name, redirect_uris, is_public, created_at
		FROM oidc_clients ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: oidc_clients: %w", err)
	}
	defer rows.Close()
	var out []OIDCClient
	for rows.Next() {
		var c OIDCClient
		if err := rows.Scan(&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name,
			&c.RedirectURIs, &c.IsPublic, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: oidc_clients scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// OIDCClientByClientID возвращает клиента по client_id; ErrNotFound, если нет.
func (s *Store) OIDCClientByClientID(ctx context.Context, clientID string) (*OIDCClient, error) {
	c := &OIDCClient{}
	err := s.Pool().QueryRow(ctx, `
		SELECT id, client_id, client_secret_hash, name, redirect_uris, is_public, created_at
		FROM oidc_clients WHERE client_id = $1`, clientID).
		Scan(&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name,
			&c.RedirectURIs, &c.IsPublic, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: oidc_clients по client_id %s: %w", clientID, err)
	}
	return c, nil
}

// OIDCClientDelete удаляет клиента по id вместе с его кодами и токенами;
// ErrNotFound, если клиента не было.
func (s *Store) OIDCClientDelete(ctx context.Context, id uuid.UUID) error {
	// Каждое предложение — отдельный Exec: pgx в расширенном протоколе
	// (с аргументами) не выполняет несколько операторов одним вызовом.
	if _, err := s.Pool().Exec(ctx,
		`DELETE FROM oidc_codes WHERE client_id = (SELECT client_id FROM oidc_clients WHERE id = $1)`, id); err != nil {
		return fmt.Errorf("store: oidc_clients delete (коды): %w", err)
	}
	if _, err := s.Pool().Exec(ctx,
		`DELETE FROM oidc_tokens WHERE client_id = (SELECT client_id FROM oidc_clients WHERE id = $1)`, id); err != nil {
		return fmt.Errorf("store: oidc_clients delete (токены): %w", err)
	}
	ct, err := s.Pool().Exec(ctx, `DELETE FROM oidc_clients WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: oidc_clients delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// OIDCCodeSave записывает authorization-код (code_hash — SHA-256 кода) и
// попутно чистит просроченные коды (копеечная уборка на каждой записи —
// отдельный фоновый цикл не нужен).
func (s *Store) OIDCCodeSave(ctx context.Context, codeHash []byte, c *OIDCCode, ttl time.Duration) error {
	_, err := s.Pool().Exec(ctx, `
		WITH cleanup AS (DELETE FROM oidc_codes WHERE expires_at < now())
		INSERT INTO oidc_codes
		  (code_hash, client_id, user_id, redirect_uri, scope, nonce, auth_time, amr,
		   code_challenge, code_challenge_method, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now() + make_interval(secs => $11))`,
		codeHash, c.ClientID, c.UserID, c.RedirectURI, c.Scope, c.Nonce,
		c.AuthTime, c.AMR, c.CodeChallenge, c.CodeChallengeMethod, int(ttl.Seconds()))
	if err != nil {
		return fmt.Errorf("store: oidc_codes save: %w", err)
	}
	return nil
}

// OIDCCodeClaim атомарно погашает код и возвращает его данные:
// UPDATE ... WHERE used_at IS NULL AND expires_at > now() — ноль строк
// означает, что код неизвестен, истёк или уже использован (ErrNotFound,
// replay неотличим от опоздания). Одноразовость гарантирует БД даже при
// гонке двух параллельных запросов токена.
func (s *Store) OIDCCodeClaim(ctx context.Context, codeHash []byte) (*OIDCCode, error) {
	c := &OIDCCode{}
	err := s.Pool().QueryRow(ctx, `
		UPDATE oidc_codes SET used_at = now()
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING client_id, user_id, redirect_uri, scope, nonce, auth_time, amr,
		          code_challenge, code_challenge_method`,
		codeHash).
		Scan(&c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope, &c.Nonce,
			&c.AuthTime, &c.AMR, &c.CodeChallenge, &c.CodeChallengeMethod)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: oidc_codes claim: %w", err)
	}
	return c, nil
}

// OIDCTokenSave записывает access-токен (token_hash — SHA-256) с чисткой
// просроченных.
func (s *Store) OIDCTokenSave(ctx context.Context, tokenHash []byte, t *OIDCToken, ttl time.Duration) error {
	_, err := s.Pool().Exec(ctx, `
		WITH cleanup AS (DELETE FROM oidc_tokens WHERE expires_at < now())
		INSERT INTO oidc_tokens (token_hash, user_id, client_id, scope, amr, expires_at)
		VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))`,
		tokenHash, t.UserID, t.ClientID, t.Scope, t.AMR, int(ttl.Seconds()))
	if err != nil {
		return fmt.Errorf("store: oidc_tokens save: %w", err)
	}
	return nil
}

// OIDCTokenGet возвращает живой access-токен по хешу; ErrNotFound, если
// токен неизвестен или истёк.
func (s *Store) OIDCTokenGet(ctx context.Context, tokenHash []byte) (*OIDCToken, error) {
	t := &OIDCToken{}
	err := s.Pool().QueryRow(ctx, `
		SELECT user_id, client_id, scope, amr, expires_at, created_at
		FROM oidc_tokens WHERE token_hash = $1 AND expires_at > now()`,
		tokenHash).Scan(&t.UserID, &t.ClientID, &t.Scope, &t.AMR, &t.ExpiresAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: oidc_tokens get: %w", err)
	}
	return t, nil
}

// OIDCTokenDelete удаляет access-токен по хешу (ревокация); отсутствие
// токена — не ошибка.
func (s *Store) OIDCTokenDelete(ctx context.Context, tokenHash []byte) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM oidc_tokens WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return fmt.Errorf("store: oidc_tokens delete: %w", err)
	}
	return nil
}

// OIDCSessionInfo — данные web-сессии для authorize: пользователь, CSRF и
// момент входа (created_at сессии → клейм auth_time ID-токена). Семантика
// та же, что у SessionGet, плюс created_at; отдельный метод, чтобы не
// менять сигнатуру SessionGet.
func (s *Store) OIDCSessionInfo(ctx context.Context, tokenHash []byte) (userID uuid.UUID, csrf string, createdAt time.Time, err error) {
	err = s.Pool().QueryRow(ctx,
		`SELECT user_id, csrf, created_at FROM sessions WHERE token_hash = $1 AND expires_at > now()`,
		tokenHash).Scan(&userID, &csrf, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, "", time.Time{}, fmt.Errorf("store: чтение сессии (oidc): %w", err)
	}
	return userID, csrf, createdAt, nil
}
