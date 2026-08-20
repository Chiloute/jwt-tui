package jwt

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func codes(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Code)
	}
	return out
}

func has(findings []Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func rawToken(t *testing.T, header, payload, sig string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc([]byte(payload)) + "." + sig
}

func analyze(t *testing.T, token, key string, now time.Time) []Finding {
	t.Helper()
	return Analyze(token, key, VerifyToken(token, key), now)
}

func TestAnalyzeFlagsAlgProblems(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"none", rawToken(t, `{"alg":"none"}`, `{"sub":"1"}`, ""), "ALG_NONE"},
		{"missing", rawToken(t, `{"typ":"JWT"}`, `{"sub":"1"}`, ""), "ALG_MISSING"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := analyze(t, tc.token, "", now)
			if !has(got, tc.want) {
				t.Fatalf("codes = %v, want %s", codes(got), tc.want)
			}
			if got[0].Sev != SevDanger {
				t.Fatalf("most severe finding = %v, want SevDanger", got[0].Sev)
			}
		})
	}
}

func TestAnalyzeFlagsDuplicateKeys(t *testing.T) {
	token := rawToken(t, `{"alg":"none","alg":"HS256"}`, `{"sub":"1"}`, "")
	if got := analyze(t, token, "", time.Now()); !has(got, "DUP_KEYS") {
		t.Fatalf("codes = %v, want DUP_KEYS", codes(got))
	}

	nested := rawToken(t, `{"alg":"HS256"}`, `{"a":{"x":1,"x":2}}`, "AAAA")
	if got := analyze(t, nested, "", time.Now()); !has(got, "DUP_KEYS") {
		t.Fatalf("nested: codes = %v, want DUP_KEYS", codes(got))
	}

	clean := rawToken(t, `{"alg":"HS256"}`, `{"a":{"x":1},"b":{"x":2}}`, "AAAA")
	if got := analyze(t, clean, "", time.Now()); has(got, "DUP_KEYS") {
		t.Fatalf("same key in sibling objects is not a duplicate: %v", codes(got))
	}
}

func TestAnalyzeFlagsPaddedBase64(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0=.AAAA"
	if got := analyze(t, token, "", time.Now()); !has(got, "B64_STRICT") {
		t.Fatalf("codes = %v, want B64_STRICT", codes(got))
	}
	if got := analyze(t, jwtIOToken, jwtIOSecret, time.Now()); has(got, "B64_STRICT") {
		t.Fatalf("a well-formed token should not trip B64_STRICT: %v", codes(got))
	}
}

func TestAnalyzeFlagsSignatureLength(t *testing.T) {
	short := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.AAAA"
	if got := analyze(t, short, "", time.Now()); !has(got, "SIG_LEN") {
		t.Fatalf("codes = %v, want SIG_LEN", codes(got))
	}
	if got := analyze(t, jwtIOToken, jwtIOSecret, time.Now()); has(got, "SIG_LEN") {
		t.Fatalf("a real HS256 signature should not trip SIG_LEN: %v", codes(got))
	}
}

func TestAnalyzeFlagsWeakHMACKey(t *testing.T) {
	got := analyze(t, jwtIOToken, jwtIOSecret, time.Now())
	if !has(got, "HMAC_KEY_LEN") {
		t.Fatalf("codes = %v, want HMAC_KEY_LEN", codes(got))
	}
	for _, f := range got {
		if f.Code == "HMAC_KEY_LEN" && f.Sev != SevWarn {
			t.Fatalf("19-byte key severity = %v, want SevWarn", f.Sev)
		}
	}

	if got := analyze(t, jwtIOToken, "", time.Now()); has(got, "HMAC_KEY_LEN") {
		t.Fatalf("no key should not be reported as weak: %v", codes(got))
	}
}

func TestAnalyzeClaims(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{"no exp", `{"sub":"1","jti":"a"}`, "EXP_MISSING"},
		{"exp before iat", `{"iat":1700000000,"exp":1699999000,"jti":"a"}`, "EXP_BEFORE_IAT"},
		{"nbf after exp", `{"iat":1700000000,"nbf":1800000000,"exp":1700000060,"jti":"a"}`, "NBF_AFTER_EXP"},
		{"iat in the future", `{"iat":1800000000,"exp":1900000000,"jti":"a"}`, "IAT_FUTURE"},
		{"lifetime over a year", `{"iat":1700000000,"exp":1800000000,"jti":"a"}`, "LIFETIME_LONG"},
		{"exp as a string", `{"iat":1700000000,"exp":"1700000060","jti":"a"}`, "TIME_CLAIM_STRING"},
		{"no jti", `{"iat":1700000000,"exp":1700000060}`, "JTI_MISSING"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := rawToken(t, `{"alg":"HS256"}`, tc.payload, strings.Repeat("A", 43))
			got := analyze(t, token, "", now)
			if !has(got, tc.want) {
				t.Fatalf("codes = %v, want %s", codes(got), tc.want)
			}
		})
	}
}

func TestAnalyzeSortsBySeverity(t *testing.T) {
	token := rawToken(t, `{"alg":"none"}`, `{"sub":"1"}`, "")
	got := analyze(t, token, "", time.Now())
	if len(got) < 2 {
		t.Fatalf("expected several findings, got %v", codes(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Sev < got[i].Sev {
			t.Fatalf("findings out of order: %v", codes(got))
		}
	}
}

func TestAnalyzeEmptyToken(t *testing.T) {
	if got := Analyze("", "", VerifyResult{}, time.Now()); got != nil {
		t.Fatalf("empty token produced findings: %v", codes(got))
	}
}
