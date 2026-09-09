package store

import (
	"testing"

	"github.com/google/uuid"
)

func TestGroupVLAN(t *testing.T) {
	var nilGroup *Group
	if got := nilGroup.VLAN(); got != "" {
		t.Fatalf("nilGroup.VLAN() = %q, want empty", got)
	}

	g := &Group{
		ID:   uuid.New(),
		Name: "Developers",
	}
	if got := g.VLAN(); got != "" {
		t.Fatalf("empty RadiusReply VLAN() = %q, want empty", got)
	}

	g.RadiusReply = map[string]string{"Tunnel-Private-Group-Id": "100"}
	if got := g.VLAN(); got != "100" {
		t.Fatalf("VLAN() = %q, want 100", got)
	}
}
