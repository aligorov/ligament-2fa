package auth

import (
	"testing"
)

func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name        string
		ua          string
		wantDevice  string
		wantBrowser string
	}{
		{
			name:        "Mac Chrome",
			ua:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
			wantDevice:  "Apple Mac (macOS)",
			wantBrowser: "Google Chrome 128",
		},
		{
			name:        "iPhone Safari",
			ua:          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			wantDevice:  "Apple iPhone (iOS 17.5.1)",
			wantBrowser: "Safari 17.5",
		},
		{
			name:        "iPad Safari",
			ua:          "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
			wantDevice:  "Apple iPad (iPadOS 16.6)",
			wantBrowser: "Safari 16.6",
		},
		{
			name:        "Windows Edge",
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
			wantDevice:  "ПК (Windows 10/11)",
			wantBrowser: "Microsoft Edge 128",
		},
		{
			name:        "Windows Firefox",
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
			wantDevice:  "ПК (Windows 10/11)",
			wantBrowser: "Firefox 129",
		},
		{
			name:        "Android Samsung Chrome",
			ua:          "Mozilla/5.0 (Linux; Android 14; SM-S918B Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36",
			wantDevice:  "Samsung (SM-S918B) (Android 14)",
			wantBrowser: "Google Chrome 128",
		},
		{
			name:        "RADIUS MAC address passthrough",
			ua:          "Apple, Inc. (MAC: F4:E8:C7:4A:B9:82)",
			wantDevice:  "Apple, Inc. (MAC: F4:E8:C7:4A:B9:82)",
			wantBrowser: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDev, gotBrowser := FormatDeviceAndBrowser(tt.ua)
			if gotDev != tt.wantDevice {
				t.Errorf("FormatDeviceAndBrowser() gotDev = %q, want %q", gotDev, tt.wantDevice)
			}
			if gotBrowser != tt.wantBrowser {
				t.Errorf("FormatDeviceAndBrowser() gotBrowser = %q, want %q", gotBrowser, tt.wantBrowser)
			}
		})
	}
}

func TestFormatIPDescription(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.1.10", "192.168.1.10 (локальная сеть)"},
		{"10.0.0.1", "10.0.0.1 (локальная сеть)"},
		{"172.18.0.5", "172.18.0.5 (локальная сеть)"},
		{"127.0.0.1", "127.0.0.1 (локально)"},
		{"31.207.73.29", "31.207.73.29"},
		{"", ""},
	}

	for _, tt := range tests {
		got := FormatIPDescription(tt.ip)
		if got != tt.want {
			t.Errorf("FormatIPDescription(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}
