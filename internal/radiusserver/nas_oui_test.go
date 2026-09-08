package radiusserver

import (
	"testing"
)

func TestExtractVLAN(t *testing.T) {
	cases := []struct {
		attrs map[string]string
		want  string
	}{
		{nil, ""},
		{map[string]string{}, ""},
		{map[string]string{"Tunnel-Private-Group-Id": "100"}, "100"},
		{map[string]string{"Filter-Id": "test", "Tunnel-Private-Group-Id": "20"}, "20"},
	}
	for _, tc := range cases {
		got := ExtractVLAN(tc.attrs)
		if got != tc.want {
			t.Errorf("ExtractVLAN(%v) = %q, want %q", tc.attrs, got, tc.want)
		}
	}
}

func TestLookupDeviceVendor(t *testing.T) {
	cases := []struct {
		mac        string
		wantVendor string
		wantRandom bool
	}{
		{"f0:18:98:11:22:33", "Apple", false},
		{"F0-18-98-AA-BB-CC", "Apple", false},
		{"f01898112233", "Apple", false},
		{"00:00:0c:12:34:56", "Cisco", false},
		{"48:8f:5a:01:02:03", "Samsung", false},
		{"4c:5e:0c:01:02:03", "MikroTik", false},
		{"74:83:c2:44:55:66", "Ubiquiti", false},
		{"02:11:22:33:44:55", "Частный/случайный MAC", true},
		{"da:a1:19:67:89:ab", "Частный/случайный MAC", true},
		{"", "", false},
		{"invalid-mac", "", false},
	}
	for _, tc := range cases {
		gotVendor, gotRandom := LookupDeviceVendor(tc.mac)
		if gotVendor != tc.wantVendor || gotRandom != tc.wantRandom {
			t.Errorf("LookupDeviceVendor(%q) = (%q, %v), want (%q, %v)", tc.mac, gotVendor, gotRandom, tc.wantVendor, tc.wantRandom)
		}
	}
}

func TestFormatDeviceDescription(t *testing.T) {
	if got := FormatDeviceDescription(""); got != "" {
		t.Errorf("FormatDeviceDescription(\"\") = %q, want empty", got)
	}
	got := FormatDeviceDescription("f0:18:98:aa:bb:cc")
	want := "Apple (F0:18:98:AA:BB:CC)"
	if got != want {
		t.Errorf("FormatDeviceDescription = %q, want %q", got, want)
	}

	gotRandom := FormatDeviceDescription("02:11:22:33:44:55")
	wantRandom := "Частный адрес (02:11:22:33:44:55)"
	if gotRandom != wantRandom {
		t.Errorf("FormatDeviceDescription(random) = %q, want %q", gotRandom, wantRandom)
	}
}

func TestParseCalledStationID(t *testing.T) {
	bssid, ssid := ParseCalledStationID("00-11-22-33-44-55:Corp-WiFi")
	if bssid != "00:11:22:33:44:55" || ssid != "Corp-WiFi" {
		t.Errorf("ParseCalledStationID(\"00-11-22-33-44-55:Corp-WiFi\") = (%q, %q)", bssid, ssid)
	}

	bssid, ssid = ParseCalledStationID("Guest-Network")
	if bssid != "" || ssid != "Guest-Network" {
		t.Errorf("ParseCalledStationID(\"Guest-Network\") = (%q, %q)", bssid, ssid)
	}

	bssid, ssid = ParseCalledStationID("aa:bb:cc:dd:ee:ff")
	if bssid != "AA:BB:CC:DD:EE:FF" || ssid != "" {
		t.Errorf("ParseCalledStationID(\"aa:bb:cc:dd:ee:ff\") = (%q, %q)", bssid, ssid)
	}
}

func TestResolveNASDescription(t *testing.T) {
	inventory := map[string]string{
		"192.168.1.50": "UniFi AP-Pro Офис 2 этаж",
		"AP-LOBBY":     "Точка Доступа Холл",
	}

	// 1. По совпадению IP и наличию SSID
	got := ResolveNASDescription("192.168.1.50", "", "00-11-22-33-44-55:Corp-WiFi", inventory)
	want := "192.168.1.50 (UniFi AP-Pro Офис 2 этаж, SSID: Corp-WiFi)"
	if got != want {
		t.Errorf("ResolveNASDescription = %q, want %q", got, want)
	}

	// 2. По совпадению NAS Identifier
	got = ResolveNASDescription("10.0.0.1", "AP-LOBBY", "", inventory)
	want = "10.0.0.1 (Точка Доступа Холл)"
	if got != want {
		t.Errorf("ResolveNASDescription = %q, want %q", got, want)
	}

	// 3. Без инвентаря, но с SSID
	got = ResolveNASDescription("10.10.10.10", "AP-OTHER", "00-11-22-33-44-55:Staff-WiFi", inventory)
	want = "10.10.10.10 (AP-OTHER, SSID: Staff-WiFi)"
	if got != want {
		t.Errorf("ResolveNASDescription = %q, want %q", got, want)
	}
}
