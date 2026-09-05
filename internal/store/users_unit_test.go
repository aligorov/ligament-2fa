// Unit-тесты чистых helpers JSON-преобразований (без БД): fallback-дефолт
// prefer_channels и раундтрип radius_reply.
package store

import (
	"encoding/json"
	"testing"

	"github.com/aligorov/twofa/internal/channel"
)

// channelsEq сравнивает списки каналов поэлементно.
func channelsEq(a, b []channel.Channel) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestScanPreferChannelsFallbackDefault(t *testing.T) {
	want := []channel.Channel{channel.TOTP, channel.Email, channel.SMS}
	cases := map[string][]byte{
		"NULL":          nil,
		"пустой массив": []byte(`[]`),
		"json null":     []byte(`null`),
	}
	for name, raw := range cases {
		got, err := scanPreferChannels(raw)
		if err != nil {
			t.Fatalf("%s: scanPreferChannels: %v", name, err)
		}
		if !channelsEq(got, want) {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
	}
}

func TestScanPreferChannelsValues(t *testing.T) {
	got, err := scanPreferChannels([]byte(`["telegram_push","email"]`))
	if err != nil {
		t.Fatalf("scanPreferChannels: %v", err)
	}
	want := []channel.Channel{channel.TelegramPush, channel.Email}
	if !channelsEq(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestScanPreferChannelsInvalid(t *testing.T) {
	if _, err := scanPreferChannels([]byte(`{"totp"`)); err == nil {
		t.Fatal("ожидалась ошибка разбора")
	}
}

func TestPreferChannelsJSONRoundTrip(t *testing.T) {
	in := []channel.Channel{channel.Telegram, channel.SMS}
	raw, err := preferChannelsJSON(in)
	if err != nil {
		t.Fatalf("preferChannelsJSON: %v", err)
	}
	got, err := scanPreferChannels(raw)
	if err != nil {
		t.Fatalf("scanPreferChannels: %v", err)
	}
	if !channelsEq(got, in) {
		t.Fatalf("раундтрип: got %v, want %v", got, in)
	}

	// nil → дефолт ["totp","email","sms"].
	rawNil, err := preferChannelsJSON(nil)
	if err != nil {
		t.Fatalf("preferChannelsJSON(nil): %v", err)
	}
	var arr []string
	if err := json.Unmarshal(rawNil, &arr); err != nil {
		t.Fatalf("разбор %s: %v", rawNil, err)
	}
	if len(arr) != 3 || arr[0] != "totp" || arr[1] != "email" || arr[2] != "sms" {
		t.Fatalf("preferChannelsJSON(nil) = %s, want дефолт", rawNil)
	}
}

func TestRadiusReplyJSONRoundTrip(t *testing.T) {
	rawNil, err := radiusReplyJSON(nil)
	if err != nil {
		t.Fatalf("radiusReplyJSON(nil): %v", err)
	}
	if rawNil != nil {
		t.Fatalf("radiusReplyJSON(nil) = %s, want nil", rawNil)
	}

	in := map[string]string{"Filter-Id": "vpn"}
	raw, err := radiusReplyJSON(in)
	if err != nil {
		t.Fatalf("radiusReplyJSON: %v", err)
	}
	got, err := scanRadiusReply(raw)
	if err != nil {
		t.Fatalf("scanRadiusReply: %v", err)
	}
	if got["Filter-Id"] != "vpn" || len(got) != 1 {
		t.Fatalf("раундтрип: got %v, want %v", got, in)
	}

	if got, err := scanRadiusReply(nil); err != nil || got != nil {
		t.Fatalf("scanRadiusReply(nil) = %v, %v; want nil, nil", got, err)
	}
	if _, err := scanRadiusReply([]byte(`[1]`)); err == nil {
		t.Fatal("ожидалась ошибка разбора")
	}
}
