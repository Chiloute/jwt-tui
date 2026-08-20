package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const (
	jwtIOToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
		".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
		".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	jwtIOSecret = "your-256-bit-secret"
)

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name  string
		token string
		key   string
		want  int
	}{
		{"valid", jwtIOToken, jwtIOSecret, 0},
		{"wrong secret", jwtIOToken, "nope", 1},
		{"no key", jwtIOToken, "", 1},
		{"broken token", "aaa.bbb", jwtIOSecret, 2},
		{"empty token", "", jwtIOSecret, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(Analyze(tc.token, tc.key)); got != tc.want {
				t.Fatalf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestJSONContract(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, Analyze(jwtIOToken, jwtIOSecret)); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var out struct {
		Header    map[string]interface{} `json:"header"`
		Payload   map[string]interface{} `json:"payload"`
		Signature struct {
			State string `json:"state"`
			Alg   string `json:"alg"`
		} `json:"signature"`
		Key struct {
			Encoding string `json:"encoding"`
			Bytes    int    `json:"bytes"`
		} `json:"key"`
		Findings []struct {
			Severity string `json:"severity"`
			Code     string `json:"code"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	if out.Signature.State != "valid" || out.Signature.Alg != "HS256" {
		t.Fatalf("signature = %+v, want valid HS256", out.Signature)
	}
	if out.Header["alg"] != "HS256" {
		t.Fatalf("header alg = %v, want HS256", out.Header["alg"])
	}
	if out.Key.Encoding != "plain" || out.Key.Bytes != len(jwtIOSecret) {
		t.Fatalf("key = %+v, want plain %d bytes", out.Key, len(jwtIOSecret))
	}
	if len(out.Findings) == 0 {
		t.Fatal("expected findings for the 19-byte demo secret")
	}
}

func TestJSONFailsOnBrokenToken(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, Analyze("aaa.bbb", jwtIOSecret)); err == nil {
		t.Fatal("expected an error for an undecodable token")
	}
}

func TestTextOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, Analyze(jwtIOToken, jwtIOSecret)); err != nil {
		t.Fatalf("Text: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Header", "Payload", "Signature: valid", "John Doe"} {
		if !strings.Contains(out, want) {
			t.Fatalf("text output missing %q:\n%s", want, out)
		}
	}
}
