package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, cn string, san []string, selfSigned bool, validity time.Duration) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"TestOrg"},
		},
		DNSNames:  san,
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(validity),
	}

	parent := &tmpl
	signKey := priv
	if !selfSigned {
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate ca key: %v", err)
		}
		caTmpl := x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				CommonName:   "Test External CA",
				Organization: []string{"Let's Encrypt"},
			},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(validity * 2),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		parent = &caTmpl
		signKey = caKey
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, parent, &priv.PublicKey, signKey)
	if err != nil {
		t.Fatalf("create test cert: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestManagerChallenges(t *testing.T) {
	mgr := NewManager(Config{})

	mgr.SetChallenge("tok1", "auth1")
	got, ok := mgr.GetChallenge("tok1")
	if !ok || got != "auth1" {
		t.Fatalf("expected auth1, got %v (ok=%v)", got, ok)
	}

	mgr.DeleteChallenge("tok1")
	_, ok = mgr.GetChallenge("tok1")
	if ok {
		t.Fatalf("expected challenge to be deleted")
	}
}

func TestHTTPHandler(t *testing.T) {
	mgr := NewManager(Config{})
	mgr.SetChallenge("valid-token", "key-authorization-string-123")

	fallbackCalled := false
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fallback"))
	})

	handler := mgr.HTTPHandler(fallback)

	// 1. Valid challenge request
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/valid-token", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if rr.Body.String() != "key-authorization-string-123" {
		t.Fatalf("expected key-authorization-string-123, got %q", rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("expected Content-Type text/plain, got %q", ct)
	}

	// 2. Unknown token with fallback
	reqUnknown := httptest.NewRequest("GET", "/.well-known/acme-challenge/unknown-token", nil)
	rrUnknown := httptest.NewRecorder()
	handler.ServeHTTP(rrUnknown, reqUnknown)
	if !fallbackCalled {
		t.Fatalf("expected fallback to be called for unknown token")
	}

	// 3. Unknown token without fallback -> 404
	noFallbackHandler := mgr.HTTPHandler(nil)
	rrNoFallback := httptest.NewRecorder()
	noFallbackHandler.ServeHTTP(rrNoFallback, reqUnknown)
	if rrNoFallback.Code != http.StatusNotFound {
		t.Fatalf("expected status 404 for unknown token, got %d", rrNoFallback.Code)
	}

	// 4. Non-ACME path -> calls fallback
	fallbackCalled = false
	reqOther := httptest.NewRequest("GET", "/api/v1/healthz", nil)
	rrOther := httptest.NewRecorder()
	handler.ServeHTTP(rrOther, reqOther)
	if !fallbackCalled {
		t.Fatalf("expected fallback for non-ACME path")
	}
}

func TestParseCertPEM(t *testing.T) {
	certPEM := generateTestCert(t, "wifi.example.com", []string{"wifi.example.com", "alt.example.com"}, true, 90*24*time.Hour)

	cert, info, err := ParseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertPEM failed: %v", err)
	}

	if cert.Subject.CommonName != "wifi.example.com" {
		t.Errorf("expected Subject CN wifi.example.com, got %q", cert.Subject.CommonName)
	}
	if !info.IsSelfSigned {
		t.Errorf("expected IsSelfSigned true")
	}
	if info.DaysLeft < 85 || info.DaysLeft > 91 {
		t.Errorf("expected ~90 days left, got %d", info.DaysLeft)
	}
}

func TestShouldRenew(t *testing.T) {
	// 1. Empty cert
	need, reason := ShouldRenew(nil, "wifi.example.com")
	if !need {
		t.Errorf("expected need=true for empty cert")
	}

	// 2. Self-signed cert
	selfSignedPEM := generateTestCert(t, "wifi.example.com", []string{"wifi.example.com"}, true, 90*24*time.Hour)
	need, reason = ShouldRenew(selfSignedPEM, "wifi.example.com")
	if !need {
		t.Errorf("expected need=true for self-signed cert")
	}

	// 3. Domain mismatch
	extPEM := generateTestCert(t, "other.example.com", []string{"other.example.com"}, false, 90*24*time.Hour)
	need, reason = ShouldRenew(extPEM, "wifi.example.com")
	if !need {
		t.Errorf("expected need=true for domain mismatch")
	}

	// 4. Close to expiry (< 30 days)
	expiringPEM := generateTestCert(t, "wifi.example.com", []string{"wifi.example.com"}, false, 10*24*time.Hour)
	need, reason = ShouldRenew(expiringPEM, "wifi.example.com")
	if !need {
		t.Errorf("expected need=true for expiring cert, reason: %s", reason)
	}

	// 5. Valid external cert with > 30 days left
	validPEM := generateTestCert(t, "wifi.example.com", []string{"wifi.example.com"}, false, 80*24*time.Hour)
	need, reason = ShouldRenew(validPEM, "wifi.example.com")
	if need {
		t.Errorf("expected need=false for valid cert, got reason: %s", reason)
	}
}
