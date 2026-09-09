//go:build integration

package store

import (
	"testing"

	"github.com/google/uuid"

	"github.com/aligorov/twofa/internal/channel"
)

func TestGroupPriorityAndSettingsResolution(t *testing.T) {
	st := sharedTestStore(t)
	ctx := t.Context()

	u := &User{
		Username:     "grp-test-" + uuid.NewString()[:8],
		PasswordHash: "$argon2id$test",
		Role:         "user",
		Enabled:      true,
	}
	if err := st.UserCreate(ctx, u); err != nil {
		t.Fatalf("UserCreate: %v", err)
	}

	gLow := &Group{
		Name:        "LowPrio-" + uuid.NewString()[:8],
		Priority:    30,
		PreferChannels: []channel.Channel{channel.SMS},
		RadiusPush:  false,
		RadiusReply: map[string]string{
			"Mikrotik-Group":          "users",
			"Tunnel-Private-Group-Id": "30",
		},
	}
	if err := st.GroupCreate(ctx, gLow); err != nil {
		t.Fatalf("GroupCreate gLow: %v", err)
	}

	gHigh := &Group{
		Name:        "HighPrio-" + uuid.NewString()[:8],
		Priority:    80,
		PreferChannels: []channel.Channel{channel.TOTP},
		RadiusPush:  true,
		RadiusReply: map[string]string{
			"Mikrotik-Group":          "admins",
			"Tunnel-Private-Group-Id": "80",
		},
	}
	if err := st.GroupCreate(ctx, gHigh); err != nil {
		t.Fatalf("GroupCreate gHigh: %v", err)
	}

	// Назначаем пользователя в обе группы
	if err := st.SetUserGroups(ctx, u.ID, []uuid.UUID{gLow.ID, gHigh.ID}); err != nil {
		t.Fatalf("SetUserGroups: %v", err)
	}

	// 1. Проверка унаследованного VLAN: должен победить gHigh (80 > 30)
	vlan, gname := st.UserInheritedVLANInfo(ctx, u)
	if vlan != "80" || gname != gHigh.Name {
		t.Fatalf("UserInheritedVLANInfo: got vlan=%q, group=%q; want 80, %q", vlan, gname, gHigh.Name)
	}

	// 2. Проверка RADIUS Push: включён в gHigh
	if !st.UserEffectiveRadiusPush(ctx, u) {
		t.Fatalf("UserEffectiveRadiusPush: expected true from gHigh")
	}

	// 3. Проверка каналов второго фактора: TOTP из gHigh
	chs, err := st.UserEffectivePreferChannels(ctx, u)
	if err != nil {
		t.Fatalf("UserEffectivePreferChannels: %v", err)
	}
	if len(chs) != 1 || chs[0] != channel.TOTP {
		t.Fatalf("UserEffectivePreferChannels: got %v, want [totp]", chs)
	}

	// 4. Проверка RADIUS Reply: Mikrotik-Group=admins, Tunnel-Private-Group-Id=80
	reply, err := st.UserEffectiveRadiusReply(ctx, u)
	if err != nil {
		t.Fatalf("UserEffectiveRadiusReply: %v", err)
	}
	if reply["Mikrotik-Group"] != "admins" || reply["Tunnel-Private-Group-Id"] != "80" {
		t.Fatalf("UserEffectiveRadiusReply: unexpected reply %v", reply)
	}

	// 5. Личные настройки пользователя перекрывают групповые
	u.RadiusReply = map[string]string{"Tunnel-Private-Group-Id": "999"}
	reply, err = st.UserEffectiveRadiusReply(ctx, u)
	if err != nil {
		t.Fatalf("UserEffectiveRadiusReply with user override: %v", err)
	}
	if reply["Tunnel-Private-Group-Id"] != "999" || reply["Mikrotik-Group"] != "admins" {
		t.Fatalf("User personal reply should override group VLAN: got %v", reply)
	}

	// 6. Проверка ApplyGroupSettingsToMembers
	if err := st.ApplyGroupSettingsToMembers(ctx, gLow.ID); err != nil {
		t.Fatalf("ApplyGroupSettingsToMembers: %v", err)
	}
	uUpdated, err := st.UserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserByID after apply: %v", err)
	}
	if uUpdated.RadiusReply["Tunnel-Private-Group-Id"] != "30" {
		t.Fatalf("ApplyGroupSettingsToMembers: expected vlan 30, got %v", uUpdated.RadiusReply)
	}
}
