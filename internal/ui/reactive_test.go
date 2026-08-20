package ui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/chiloute/jwt-tui/internal/jwt"
)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

func rs256Fixture(t *testing.T) (token, pubPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	token, err = jwtlib.NewWithClaims(jwtlib.SigningMethodRS256,
		jwtlib.MapClaims{"sub": "1"}).SignedString(key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return token, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

const sampleJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func TestDecodeAndVerify(t *testing.T) {
	m := initialModel("", "")

	m.focus = panelEncoded
	m.setText(panelEncoded, sampleJWT)
	m.onContentChange()

	if !strings.Contains(m.text(panelHeader), "HS256") {
		t.Fatalf("header not decoded: %q", m.text(panelHeader))
	}
	if !strings.Contains(m.text(panelPayload), "John Doe") {
		t.Fatalf("payload not decoded: %q", m.text(panelPayload))
	}
	if m.algorithm != "HS256" {
		t.Fatalf("algorithm = %q, want HS256", m.algorithm)
	}
	if m.sig != jwt.SigNoKey {
		t.Fatalf("sig without secret = %v, want SigNoKey", m.sig)
	}

	m.focus = panelSecret
	m.setText(panelSecret, "wrong-secret")
	m.onContentChange()
	if m.sig != jwt.SigInvalid {
		t.Fatalf("sig with wrong secret = %v (%s), want SigInvalid", m.sig, m.sigError)
	}

	m.setText(panelSecret, "your-256-bit-secret")
	m.onContentChange()
	if m.sig != jwt.SigValid {
		t.Fatalf("sig with correct secret = %v (%s), want SigValid", m.sig, m.sigError)
	}
}

func TestWrongSecretIsInvalid(t *testing.T) {
	m := initialModel("", "")
	m.focus = panelEncoded
	m.setText(panelEncoded, sampleJWT)
	m.onContentChange()

	m.focus = panelSecret
	for _, secret := range []string{"a", "ab", "definitely-not-the-secret"} {
		m.setText(panelSecret, secret)
		m.onContentChange()
		if m.sig != jwt.SigInvalid {
			t.Fatalf("sig with secret %q = %v (%s), want SigInvalid", secret, m.sig, m.sigError)
		}
	}
}

func TestAsymmetricVerifiesWithoutRefresh(t *testing.T) {
	token, pubPEM := rs256Fixture(t)

	m := initialModel("", "")
	m.focus = panelEncoded
	m.setText(panelEncoded, token)
	m.onContentChange()

	m.focus = panelSecret
	m.setText(panelSecret, pubPEM)
	m.onContentChange()

	if m.sig != jwt.SigValid {
		t.Fatalf("sig with the matching public key = %v (%s), want SigValid", m.sig, m.sigError)
	}
	if m.errorMsg != "" {
		t.Fatalf("unexpected error message: %q", m.errorMsg)
	}
}

func TestVerifyFromFileSpec(t *testing.T) {
	token, pubPEM := rs256Fixture(t)
	path := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(path, []byte(pubPEM), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	m := initialModel(token, "@"+path)
	if m.sig != jwt.SigValid {
		t.Fatalf("sig with @file key = %v (%s), want SigValid", m.sig, m.sigError)
	}
	if m.keyResult.KeyOrigin != path {
		t.Fatalf("key origin = %q, want %q", m.keyResult.KeyOrigin, path)
	}
}

func TestSecretRoleFollowsEdit(t *testing.T) {
	m := initialModel(sampleJWT, "your-256-bit-secret")
	if role := stripANSI(m.secretRole()); role != "verify" {
		t.Fatalf("role on an untouched token = %q, want verify", role)
	}

	m.focus = panelPayload
	m.setText(panelPayload, `{"sub":"1","name":"Jane"}`)
	m.onContentChange()

	if role := stripANSI(m.secretRole()); !strings.HasPrefix(role, "sign") {
		t.Fatalf("role after editing the payload = %q, want it to start with sign", role)
	}
}

func TestSecretRoleFlagsPublicKeyForSigning(t *testing.T) {
	token, pubPEM := rs256Fixture(t)
	m := initialModel(token, pubPEM)

	m.focus = panelPayload
	m.setText(panelPayload, `{"sub":"2"}`)
	m.onContentChange()

	if role := stripANSI(m.secretRole()); !strings.Contains(role, "public key") {
		t.Fatalf("role = %q, want it to warn about the public key", role)
	}
}

func TestSecretEditPreservesToken(t *testing.T) {
	m := initialModel("", "")
	m.focus = panelEncoded
	m.setText(panelEncoded, sampleJWT)
	m.onContentChange()

	m.focus = panelSecret
	m.setText(panelSecret, "s")
	m.onContentChange()

	if got := m.text(panelEncoded); got != sampleJWT {
		t.Fatalf("secret edit rewrote the encoded panel:\n got %q\nwant %q", got, sampleJWT)
	}
}

func TestResignAfterPayloadEdit(t *testing.T) {
	m := initialModel("", "")
	m.setText(panelEncoded, sampleJWT)
	m.onContentChange()

	m.focus = panelSecret
	m.setText(panelSecret, "your-256-bit-secret")
	m.onContentChange()

	m.focus = panelPayload
	m.setText(panelPayload, "{\n  \"sub\": \"1234567890\",\n  \"name\": \"Jane Doe\"\n}")
	m.onContentChange()

	m.resignToken()
	m.refresh()
	if m.sig != jwt.SigValid {
		t.Fatalf("sig after re-sign = %v (%s), want SigValid", m.sig, m.sigError)
	}
	if m.edit != jwt.EditResigned {
		t.Fatalf("edit after re-sign = %v, want EditResigned", m.edit)
	}
	if label, _ := m.sigLabel(); label != "valid (self-signed)" {
		t.Fatalf("sig label after re-sign = %q, want %q", label, "valid (self-signed)")
	}
	if m.successMsg == "" {
		t.Fatalf("expected a re-sign success message")
	}
	if !strings.Contains(m.text(panelPayload), "Jane Doe") {
		t.Fatalf("payload lost the edit: %q", m.text(panelPayload))
	}
}

func TestReformatKeepsSignature(t *testing.T) {
	m := initialModel(sampleJWT, "your-256-bit-secret")
	if m.sig != jwt.SigValid {
		t.Fatalf("setup: sig = %v (%s), want SigValid", m.sig, m.sigError)
	}

	m.focus = panelPayload
	m.onContentChange()

	if m.sig != jwt.SigValid {
		t.Fatalf("sig after a no-op payload cycle = %v (%s), want SigValid", m.sig, m.sigError)
	}
	if m.edit != jwt.EditOriginal {
		t.Fatalf("edit after a no-op payload cycle = %v, want EditOriginal", m.edit)
	}
	if got := m.text(panelEncoded); got != sampleJWT {
		t.Fatalf("token was rewritten:\n got %q\nwant %q", got, sampleJWT)
	}
}

func TestBrokenJSONMarksDesynced(t *testing.T) {
	m := initialModel(sampleJWT, "your-256-bit-secret")

	m.focus = panelPayload
	m.setText(panelPayload, `{"sub": `)
	m.onContentChange()

	if !m.desynced {
		t.Fatal("broken payload JSON did not mark the model desynced")
	}
	if label, _ := m.sigLabel(); label != "desynced" {
		t.Fatalf("sig label = %q, want %q — a stale green tick is the bug here", label, "desynced")
	}
	if got := m.text(panelEncoded); got != sampleJWT {
		t.Fatalf("desynced rebuild touched the token: %q", got)
	}
}
