package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Severity int

const (
	SevInfo Severity = iota
	SevWarn
	SevDanger
)

func (s Severity) String() string {
	switch s {
	case SevDanger:
		return "danger"
	case SevWarn:
		return "warn"
	}
	return "info"
}

type Finding struct {
	Sev    Severity
	Code   string
	Title  string
	Detail string
}

func Analyze(rawToken, key string, res VerifyResult, now time.Time) []Finding {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil
	}

	var findings []Finding
	findings = append(findings, algFindings(res)...)
	findings = append(findings, encodingFindings(rawToken)...)
	findings = append(findings, keyFindings(key, res)...)
	findings = append(findings, claimFindings(res, now)...)

	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Sev > findings[j].Sev
	})
	return findings
}

func algFindings(res VerifyResult) []Finding {
	switch res.Sig {
	case SigAlgNone:
		return []Finding{{SevDanger, "ALG_NONE", "alg is none",
			"The token carries no signature. Anyone can rewrite the payload. " +
				"A verifier that honours alg:none is trivially bypassed."}}
	case SigAlgMissing:
		return []Finding{{SevDanger, "ALG_MISSING", "no alg in the header",
			"Nothing says how this token was signed, so nothing can check it."}}
	case SigAlgConfusion:
		return []Finding{{SevDanger, "ALG_CONFUSION", "algorithm confusion",
			"The header asks for HMAC while the key is a PEM. That is the " +
				"RS256->HS256 trick: the MAC key becomes the public key text, " +
				"which an attacker also has. Verification was refused."}}
	}
	return nil
}

func encodingFindings(rawToken string) []Finding {
	var findings []Finding

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil
	}

	for i, name := range []string{"header", "payload", "signature"} {
		if strings.ContainsAny(parts[i], "=+/") {
			findings = append(findings, Finding{SevWarn, "B64_STRICT",
				"non-standard base64 in the " + name,
				"Contains '=', '+' or '/'. RFC 7515 requires unpadded base64url."})
		}
	}

	for i, name := range []string{"header", "payload"} {
		decoded, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			continue
		}
		for _, dup := range duplicateKeys(decoded) {
			findings = append(findings, Finding{SevDanger, "DUP_KEYS",
				"duplicate key " + dup + " in the " + name,
				"Go keeps the last one, other parsers keep the first. A token " +
					"with two alg or two exp entries can mean different things " +
					"to your tooling and to the server that issued it."})
		}
	}

	return findings
}

func keyFindings(key string, res VerifyResult) []Finding {
	var findings []Finding

	if res.KeyTrimmed {
		findings = append(findings, Finding{SevWarn, "KEY_TRAILING_WS",
			"the key had trailing whitespace",
			"It only verifies once the trailing whitespace is stripped. Whatever " +
				"issued this token used the trimmed key, so your copy has a stray " +
				"newline in it."})
	}

	if res.Sig == SigValid && NeedsPublicKey(res.Alg) && !res.KeyPrivate {
		findings = append(findings, Finding{SevInfo, "KEY_PUBLIC_ONLY",
			"public key only",
			"The signature verifies, but this key can't re-sign. Point at the " +
				"private key if you want to tamper with the token and re-sign it."})
	}

	if res.KeyEncoding == EncJWKS && res.Kid == "" {
		findings = append(findings, Finding{SevWarn, "JWKS_KID_MISSING",
			"no kid with a JWK set",
			"The token has no kid, so there's nothing to pick a key by. It only " +
				"works because the set holds a single key."})
	}

	if want, ok := sigLen(res.Alg); ok && res.SigBytes > 0 && res.SigBytes != want {
		findings = append(findings, Finding{SevDanger, "SIG_LEN",
			fmt.Sprintf("signature is %d bytes, %s needs %d", res.SigBytes, res.Alg, want),
			"The signature can't be a valid " + res.Alg + " one at this length, " +
				"whatever key you try."})
	}
	if strings.HasPrefix(res.Alg, "RS") || strings.HasPrefix(res.Alg, "PS") {
		if res.SigBytes > 0 && res.SigBytes < 128 {
			findings = append(findings, Finding{SevDanger, "SIG_LEN",
				fmt.Sprintf("signature is only %d bytes for %s", res.SigBytes, res.Alg),
				"An RSA signature is as long as the modulus, so at least 128 bytes " +
					"even for a (already too small) 1024-bit key."})
		}
	}

	if AlgoFamily(res.Alg) == "HMAC" && res.KeyBytes > 0 {
		if want, ok := hmacKeyLen(res.Alg); ok && res.KeyBytes < want {
			sev := SevWarn
			if res.KeyBytes < 8 {
				sev = SevDanger
			}
			findings = append(findings, Finding{sev, "HMAC_KEY_LEN",
				fmt.Sprintf("HMAC key is %d bytes, %s wants at least %d", res.KeyBytes, res.Alg, want),
				"RFC 7518 §3.2 asks for a key at least as long as the hash output. " +
					"Short secrets are worth trying a wordlist against."})
		}
	}

	return findings
}

func claimFindings(res VerifyResult, now time.Time) []Finding {
	if res.Claims == nil {
		return nil
	}
	var findings []Finding

	for _, name := range res.StringTimeClaims {
		findings = append(findings, Finding{SevWarn, "TIME_CLAIM_STRING",
			name + " is a string, not a number",
			"RFC 7519 says these are NumericDate. Strict verifiers will either " +
				"reject the token or ignore the claim entirely."})
	}

	if res.ExpiresAt == nil {
		findings = append(findings, Finding{SevWarn, "EXP_MISSING", "no exp claim",
			"This token never expires on its own. If it leaks, it stays useful."})
	}

	if res.ExpiresAt != nil && res.IssuedAt != nil {
		if res.ExpiresAt.Before(*res.IssuedAt) {
			findings = append(findings, Finding{SevDanger, "EXP_BEFORE_IAT",
				"exp is before iat",
				"The token expires before it was issued, so it was never valid."})
		} else if res.ExpiresAt.Sub(*res.IssuedAt) > 365*24*time.Hour {
			findings = append(findings, Finding{SevWarn, "LIFETIME_LONG",
				"lifetime over a year",
				fmt.Sprintf("Valid for %.0f days. Long-lived bearer tokens are hard to revoke.",
					res.ExpiresAt.Sub(*res.IssuedAt).Hours()/24)})
		}
	}

	if res.NotBefore != nil && res.ExpiresAt != nil && res.NotBefore.After(*res.ExpiresAt) {
		findings = append(findings, Finding{SevDanger, "NBF_AFTER_EXP", "nbf is after exp",
			"The validity window is empty: the token is never usable."})
	}

	if res.IssuedAt != nil && res.IssuedAt.After(now.Add(time.Minute)) {
		findings = append(findings, Finding{SevWarn, "IAT_FUTURE", "iat is in the future",
			"Either the issuer's clock is off or the claim was tampered with."})
	}

	if _, ok := res.Claims["jti"]; !ok {
		findings = append(findings, Finding{SevInfo, "JTI_MISSING", "no jti claim",
			"Without a unique id there's nothing to key replay protection on."})
	}

	return findings
}

func sigLen(alg string) (int, bool) {
	switch alg {
	case "HS256":
		return 32, true
	case "HS384":
		return 48, true
	case "HS512", "ES256", "EdDSA":
		return 64, true
	case "ES384":
		return 96, true
	case "ES512":
		return 132, true
	}
	return 0, false
}

func hmacKeyLen(alg string) (int, bool) {
	switch alg {
	case "HS256":
		return 32, true
	case "HS384":
		return 48, true
	case "HS512":
		return 64, true
	}
	return 0, false
}

func duplicateKeys(raw []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var dups []string

	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				name, _ := k.(string)
				if seen[name] {
					dups = append(dups, name)
				}
				seen[name] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		case json.Delim('['):
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		}
		return nil
	}

	_ = walk()
	return dups
}
