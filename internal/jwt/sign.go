package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func SignToken(headerJSON, payloadJSON, keySpec string) (string, error) {
	header, err := compactJSON(headerJSON)
	if err != nil {
		return "", fmt.Errorf("invalid header JSON: %w", err)
	}
	payload, err := compactJSON(payloadJSON)
	if err != nil {
		return "", fmt.Errorf("invalid payload JSON: %w", err)
	}

	alg := algFromHeader(header)
	if alg == "" {
		return "", fmt.Errorf("no alg in the header")
	}

	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)

	if strings.EqualFold(alg, "none") {
		return signingInput + ".", nil
	}

	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	key, err := ResolveKey(keySpec)
	if err != nil {
		return "", err
	}
	if key.Empty() {
		return "", fmt.Errorf("a key is required to sign %s", alg)
	}

	signingKey, err := key.SigningKey(alg, kidFromHeader(header))
	if err != nil {
		return "", err
	}

	sig, err := method.Sign(signingInput, signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func compactJSON(s string) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func algFromHeader(header []byte) string {
	var h struct {
		Alg string `json:"alg"`
	}
	_ = json.Unmarshal(header, &h)
	return h.Alg
}

func kidFromHeader(header []byte) string {
	var h struct {
		Kid string `json:"kid"`
	}
	_ = json.Unmarshal(header, &h)
	return h.Kid
}
