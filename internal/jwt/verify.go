package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var ErrKeyUnreadable = errors.New("key unreadable")

func VerifyToken(tokenString, keySpec string) VerifyResult {
	var r VerifyResult
	tokenString = strings.TrimSpace(tokenString)

	if tokenString == "" {
		r.Sig = SigEmpty
		return r
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		r.Sig = SigMalformed
		r.SigError = fmt.Sprintf("expected 3 parts, got %d", len(parts))
		return r
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		r.Sig = SigMalformed
		r.SigError = "header is not valid base64url"
		return r
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		r.Sig = SigMalformed
		r.SigError = "header is not valid JSON"
		return r
	}

	r.Alg, _ = header["alg"].(string)
	r.Typ, _ = header["typ"].(string)
	r.Kid, _ = header["kid"].(string)

	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		r.Sig = SigMalformed
		r.SigError = "payload is not valid base64url"
		return r
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		r.Sig = SigMalformed
		r.SigError = "signature is not valid base64url"
		return r
	}
	r.SigBytes = len(sigBytes)

	r.Claims = parseClaims(tokenString)
	r.extractTemporal()

	switch {
	case r.Alg == "":
		r.Sig = SigAlgMissing
		r.SigError = "no alg in the header, there is nothing to verify against"
		return r
	case strings.EqualFold(r.Alg, "none"):
		r.Sig = SigAlgNone
		r.SigError = "alg is none: this token is not signed"
		return r
	}

	resolved, err := ResolveKey(keySpec)
	if err != nil {
		r.Sig = SigKeyUnreadable
		r.SigError = err.Error()
		return r
	}
	if resolved.Empty() {
		r.Sig = SigNoKey
		return r
	}
	r.KeyEncoding = resolved.Encoding
	r.KeyOrigin = resolved.Origin
	r.KeyPrivate = resolved.Private
	r.KeyBytes = len(resolved.Bytes)

	if AlgoFamily(r.Alg) == "HMAC" && resolved.isAsymmetric(r.Kid) {
		r.Sig = SigAlgConfusion
		r.SigError = resolved.Encoding.String() +
			" key with an HMAC alg — algorithm confusion, refusing to verify"
		return r
	}
	if NeedsPublicKey(r.Alg) && resolved.Encoding == EncPlain {
		r.Sig = SigKeyUnreadable
		r.SigError = r.Alg + " needs a PEM, DER or JWKS key, got a plain string"
		return r
	}

	r.Sig, r.SigError = verifyWith(tokenString, r.Alg, r.Kid, resolved)

	if r.Sig == SigInvalid && AlgoFamily(r.Alg) == "HMAC" && resolved.Encoding == EncPlain {
		if trimmed := bytes.TrimRight(resolved.Bytes, " \t\r\n"); len(trimmed) != len(resolved.Bytes) {
			alt := resolved
			alt.Bytes = trimmed
			if sig, sigErr := verifyWith(tokenString, r.Alg, r.Kid, alt); sig == SigValid {
				r.Sig, r.SigError = sig, sigErr
				r.KeyTrimmed = true
				r.KeyBytes = len(trimmed)
			}
		}
	}

	return r
}

func verifyWith(tokenString, alg, kid string, key Key) (SigState, string) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return key.VerificationKey(token.Method.Alg(), kid)
	}

	token, err := jwt.Parse(tokenString, keyFunc,
		jwt.WithValidMethods([]string{alg}),
		jwt.WithoutClaimsValidation(),
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrKeyUnreadable):
			return SigKeyUnreadable, err.Error()
		case errors.Is(err, jwt.ErrTokenMalformed):
			return SigMalformed, err.Error()
		}
		return SigInvalid, err.Error()
	}
	if !token.Valid {
		return SigInvalid, "library reported the token as not valid"
	}
	return SigValid, ""
}

func parseClaims(tokenString string) map[string]interface{} {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil
	}
	return claims
}
