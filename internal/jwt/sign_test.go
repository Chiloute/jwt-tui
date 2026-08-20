package jwt

import (
	"strings"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

func TestSignReproducesUntouchedToken(t *testing.T) {
	info, err := ParseJWT(jwtIOToken)
	if err != nil {
		t.Fatalf("ParseJWT: %v", err)
	}
	header := decodeSegment(t, info.HeaderB64)
	payload := decodeSegment(t, info.PayloadB64)

	got, err := SignToken(header, payload, jwtIOSecret)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	if got != jwtIOToken {
		t.Fatalf("re-signing changed the token:\n got %s\nwant %s", got, jwtIOToken)
	}
}

func TestSignPreservesKeyOrder(t *testing.T) {
	header := `{"typ":"JWT","alg":"HS256"}`
	payload := `{"b":2,"a":1}`

	got, err := SignToken(header, payload, jwtIOSecret)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	info, err := ParseJWT(got)
	if err != nil {
		t.Fatalf("ParseJWT: %v", err)
	}
	decodedHeader := decodeSegment(t, info.HeaderB64)
	if decodedHeader != header {
		t.Fatalf("header bytes = %s, want %s", decodedHeader, header)
	}
	if got := decodeSegment(t, info.PayloadB64); got != payload {
		t.Fatalf("payload bytes = %s, want %s", got, payload)
	}
}

func TestSignAlgFromHeader(t *testing.T) {
	got, err := SignToken(`{"alg":"HS512"}`, `{"sub":"1"}`, jwtIOSecret)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	if res := VerifyToken(got, jwtIOSecret); res.Sig != SigValid || res.Alg != "HS512" {
		t.Fatalf("Sig = %v, Alg = %q, want valid HS512", res.Sig, res.Alg)
	}
}

func TestSignAlgNone(t *testing.T) {
	got, err := SignToken(`{"alg":"none"}`, `{"admin":true}`, "")
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	if !strings.HasSuffix(got, ".") {
		t.Fatalf("alg:none token should end in a dot with an empty signature: %q", got)
	}
	if parts := strings.Split(got, "."); len(parts) != 3 || parts[2] != "" {
		t.Fatalf("alg:none token = %q, want header.payload. with empty signature", got)
	}
	if res := VerifyToken(got, "anything"); res.Sig == SigValid {
		t.Fatal("alg:none token reported as valid")
	}
}

func TestSignAsymmetric(t *testing.T) {
	tests := []struct {
		alg string
		gen func(*testing.T) (string, string)
	}{
		{"RS256", generateRSAKeys},
		{"PS256", generateRSAKeys},
		{"ES256", generateECKeys},
		{"EdDSA", generateEd25519Keys},
	}
	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			priv, pub := tc.gen(t)
			header := `{"alg":"` + tc.alg + `"}`
			token, err := SignToken(header, `{"sub":"1"}`, priv)
			if err != nil {
				t.Fatalf("SignToken: %v", err)
			}
			if res := VerifyToken(token, pub); res.Sig != SigValid {
				t.Fatalf("Sig = %v (%s), want SigValid", res.Sig, res.SigError)
			}
		})
	}
}

func TestSignRejectsPublicKey(t *testing.T) {
	_, pub := generateRSAKeys(t)
	_, err := SignToken(`{"alg":"RS256"}`, `{"sub":"1"}`, pub)
	if err == nil || !strings.Contains(err.Error(), "private half") {
		t.Fatalf("err = %v, want a 'needs the private half' message", err)
	}
}

func TestSignErrors(t *testing.T) {
	tests := []struct {
		name           string
		header, secret string
		want           string
	}{
		{"bad header json", `{`, jwtIOSecret, "invalid header JSON"},
		{"no alg", `{"typ":"JWT"}`, jwtIOSecret, "no alg"},
		{"unsupported alg", `{"alg":"HS999"}`, jwtIOSecret, "unsupported algorithm"},
		{"no key", `{"alg":"HS256"}`, "", "key is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SignToken(tc.header, `{"sub":"1"}`, tc.secret)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestSignAfterTamper(t *testing.T) {
	info, _ := ParseJWT(jwtIOToken)
	header := decodeSegment(t, info.HeaderB64)
	tampered := `{"sub":"1234567890","name":"Jane Doe","iat":1516239022,"admin":true}`

	got, err := SignToken(header, tampered, jwtIOSecret)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	if got == jwtIOToken {
		t.Fatal("tampered token is identical to the original")
	}
	if res := VerifyToken(got, jwtIOSecret); res.Sig != SigValid {
		t.Fatalf("Sig = %v (%s), want SigValid", res.Sig, res.SigError)
	}
}

func decodeSegment(t *testing.T, seg string) string {
	t.Helper()
	b, err := jwtlib.NewParser().DecodeSegment(seg)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	return string(b)
}
