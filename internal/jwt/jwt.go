package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type SigState int

const (
	SigEmpty SigState = iota
	SigMalformed
	SigAlgMissing
	SigAlgNone
	SigNoKey
	SigKeyUnreadable
	SigAlgConfusion
	SigInvalid
	SigValid
)

func (s SigState) String() string {
	switch s {
	case SigEmpty:
		return "empty"
	case SigMalformed:
		return "malformed"
	case SigAlgMissing:
		return "no alg"
	case SigAlgNone:
		return "alg none"
	case SigNoKey:
		return "no key"
	case SigKeyUnreadable:
		return "key unreadable"
	case SigAlgConfusion:
		return "alg confusion"
	case SigInvalid:
		return "invalid"
	case SigValid:
		return "valid"
	}
	return "unknown"
}

type TemporalState int

const (
	TempNone TemporalState = iota
	TempExpired
	TempNotYetValid
	TempValid
)

func (t TemporalState) String() string {
	switch t {
	case TempExpired:
		return "expired"
	case TempNotYetValid:
		return "not yet valid"
	case TempValid:
		return "valid"
	}
	return ""
}

type EditState int

const (
	EditOriginal EditState = iota
	EditModified
	EditResigned
)

func (e EditState) String() string {
	switch e {
	case EditOriginal:
		return "original"
	case EditModified:
		return "modified"
	case EditResigned:
		return "re-signed"
	}
	return ""
}

type VerifyResult struct {
	Sig       SigState
	Temporal  TemporalState
	Alg       string
	Typ       string
	Kid       string
	SigError  string
	Claims    map[string]interface{}
	ExpiresAt *time.Time
	NotBefore *time.Time
	IssuedAt  *time.Time

	StringTimeClaims []string

	SigBytes    int
	KeyBytes    int
	KeyTrimmed  bool
	KeyEncoding KeyEncoding
	KeyOrigin   string
	KeyPrivate  bool
}

func (r *VerifyResult) extractTemporal() {
	t := EvaluateTemporal(r.Claims, time.Now())
	r.Temporal = t.State
	r.ExpiresAt = t.ExpiresAt
	r.NotBefore = t.NotBefore
	r.IssuedAt = t.IssuedAt
	r.StringTimeClaims = t.StringClaims
}

type JWTInfo struct {
	Raw        string
	Header     map[string]interface{}
	Payload    map[string]interface{}
	Signature  string
	Algorithm  string
	HeaderB64  string
	PayloadB64 string
}

func ParseJWT(tokenString string) (*JWTInfo, error) {
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return nil, errors.New("token is empty")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header JSON: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload JSON: %w", err)
	}

	alg, _ := header["alg"].(string)

	return &JWTInfo{
		Raw:        tokenString,
		Header:     header,
		Payload:    payload,
		Signature:  parts[2],
		Algorithm:  alg,
		HeaderB64:  parts[0],
		PayloadB64: parts[1],
	}, nil
}

func PrettyJSON(s string) string {
	var js interface{}
	if err := json.Unmarshal([]byte(s), &js); err != nil {
		return s
	}
	b, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return s
	}
	return string(b)
}

func IsValidJSON(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
}

func AlgoFamily(alg string) string {
	switch {
	case strings.HasPrefix(alg, "HS"):
		return "HMAC"
	case strings.HasPrefix(alg, "RS"):
		return "RSA"
	case strings.HasPrefix(alg, "PS"):
		return "RSAPSS"
	case strings.HasPrefix(alg, "ES"):
		return "ECDSA"
	case alg == "EdDSA":
		return "Ed25519"
	case strings.EqualFold(alg, "none"):
		return "none"
	default:
		return "unknown"
	}
}

func NeedsPublicKey(alg string) bool {
	return strings.HasPrefix(alg, "RS") ||
		strings.HasPrefix(alg, "PS") ||
		strings.HasPrefix(alg, "ES") ||
		alg == "EdDSA"
}
