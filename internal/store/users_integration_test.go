//go:build integration

// Интеграционные тесты репозитория users: CRUD, JSON-раундтрип
// prefer_channels/radius_reply, пути ErrNotFound.
package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/channel"
)

func TestUserCRUDIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	created := &User{
		Username:     "crud-" + uuid.NewString()[:8],
		PasswordHash: "$argon2id$test",
		Role:         "user",
		Enabled:      true,
		Email:        "crud@example.com",
		Phone:        "+70000000001",
	}
	if err := st.UserCreate(ctx, created); err != nil {
		t.Fatalf("UserCreate: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("UserCreate не проставил ID")
	}

	got, err := st.UserByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if got.Username != created.Username || got.PasswordHash != created.PasswordHash ||
		got.Role != "user" || !got.Enabled || got.Email != created.Email ||
		got.Phone != created.Phone || got.TelegramChatID != nil || got.RadiusPush ||
		got.RadiusReply != nil || got.WebAuthnID != nil {
		t.Fatalf("несовпадение после создания: %+v", got)
	}
	if want := []channel.Channel{channel.TOTP, channel.Email, channel.SMS}; !channelsEq(got.PreferChannels, want) {
		t.Fatalf("prefer_channels: got %v, want %v", got.PreferChannels, want)
	}

	byName, err := st.UserByUsername(ctx, created.Username)
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	if byName.ID != created.ID {
		t.Fatalf("UserByUsername: ID %s, want %s", byName.ID, created.ID)
	}

	// Update: меняются все мутируемые поля.
	tg := int64(100500)
	created.Role = "admin"
	created.Enabled = false
	created.Email = "new@example.com"
	created.Phone = "+70000000002"
	created.TelegramChatID = &tg
	created.PreferChannels = []channel.Channel{channel.TelegramPush, channel.Email}
	created.RadiusPush = true
	created.RadiusReply = map[string]string{"Filter-Id": "vpn", "Framed-IP": "10.0.0.1"}
	created.WebAuthnID = []byte("waid-" + uuid.NewString()[:8])
	created.PasswordHash = "$argon2id$rotated"
	if err := st.UserUpdate(ctx, created); err != nil {
		t.Fatalf("UserUpdate: %v", err)
	}
	updated, err := st.UserByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("UserByID после update: %v", err)
	}
	if updated.Role != "admin" || updated.Enabled {
		t.Fatalf("role/enabled не обновились: %+v", updated)
	}
	if updated.Email != "new@example.com" || updated.Phone != "+70000000002" {
		t.Fatalf("email/phone не обновились: %+v", updated)
	}
	if updated.TelegramChatID == nil || *updated.TelegramChatID != tg {
		t.Fatalf("telegram_chat_id не обновился: %v", updated.TelegramChatID)
	}
	if want := []channel.Channel{channel.TelegramPush, channel.Email}; !channelsEq(updated.PreferChannels, want) {
		t.Fatalf("prefer_channels после update: got %v, want %v", updated.PreferChannels, want)
	}
	if !updated.RadiusPush {
		t.Fatal("radius_push не обновился")
	}
	if updated.RadiusReply == nil || updated.RadiusReply["Filter-Id"] != "vpn" ||
		updated.RadiusReply["Framed-IP"] != "10.0.0.1" || len(updated.RadiusReply) != 2 {
		t.Fatalf("radius_reply не обновился: %v", updated.RadiusReply)
	}
	if string(updated.WebAuthnID) != string(created.WebAuthnID) {
		t.Fatalf("webauthn_id не обновился: %q", updated.WebAuthnID)
	}
	if updated.PasswordHash != "$argon2id$rotated" {
		t.Fatalf("password_hash не обновился: %q", updated.PasswordHash)
	}

	if err := st.UserDelete(ctx, created.ID); err != nil {
		t.Fatalf("UserDelete: %v", err)
	}
	if _, err := st.UserByID(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UserByID после delete: err=%v, want ErrNotFound", err)
	}
}

func TestUserNotFoundIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	if _, err := st.UserByUsername(ctx, "no-such-"+uuid.NewString()[:8]); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserByUsername(нет такого): err=%v, want ErrNotFound", err)
	}
	if _, err := st.UserByID(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserByID(случайный): err=%v, want ErrNotFound", err)
	}
	if err := st.UserUpdate(ctx, &User{ID: uuid.New(), Username: "ghost"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserUpdate(нет такого): err=%v, want ErrNotFound", err)
	}
	if err := st.UserDelete(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserDelete(нет такого): err=%v, want ErrNotFound", err)
	}
}

func TestUserListCountIntegration(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	before, err := st.UserCount(ctx)
	if err != nil {
		t.Fatalf("UserCount: %v", err)
	}
	var names []string
	for i := 0; i < 3; i++ {
		u := &User{
			Username:     "list-" + uuid.NewString()[:12],
			PasswordHash: "$argon2id$test",
		}
		if err := st.UserCreate(ctx, u); err != nil {
			t.Fatalf("UserCreate: %v", err)
		}
		names = append(names, u.Username)
	}
	after, err := st.UserCount(ctx)
	if err != nil {
		t.Fatalf("UserCount: %v", err)
	}
	if after != before+3 {
		t.Fatalf("UserCount: был %d, стал %d, ожидался +3", before, after)
	}

	list, err := st.UserList(ctx)
	if err != nil {
		t.Fatalf("UserList: %v", err)
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].Username > list[i].Username {
			t.Fatalf("UserList не отсортирован по username: %q > %q",
				list[i-1].Username, list[i].Username)
		}
	}
	found := 0
	for _, u := range list {
		for _, n := range names {
			if u.Username == n {
				found++
			}
		}
	}
	if found != 3 {
		t.Fatalf("в UserList найдено %d из 3 созданных", found)
	}
}
