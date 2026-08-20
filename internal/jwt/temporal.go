package jwt

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type Temporal struct {
	State     TemporalState
	ExpiresAt *time.Time
	NotBefore *time.Time
	IssuedAt  *time.Time

	StringClaims []string
}

func EvaluateTemporal(claims map[string]interface{}, now time.Time) Temporal {
	var t Temporal
	if claims == nil {
		return t
	}

	var wasString bool
	t.ExpiresAt, wasString = claimTime(claims, "exp")
	if wasString {
		t.StringClaims = append(t.StringClaims, "exp")
	}
	t.NotBefore, wasString = claimTime(claims, "nbf")
	if wasString {
		t.StringClaims = append(t.StringClaims, "nbf")
	}
	t.IssuedAt, wasString = claimTime(claims, "iat")
	if wasString {
		t.StringClaims = append(t.StringClaims, "iat")
	}

	switch {
	case t.ExpiresAt != nil && now.After(*t.ExpiresAt):
		t.State = TempExpired
	case t.NotBefore != nil && now.Before(*t.NotBefore):
		t.State = TempNotYetValid
	case t.ExpiresAt != nil || t.NotBefore != nil:
		t.State = TempValid
	}
	return t
}

func claimTime(claims map[string]interface{}, name string) (*time.Time, bool) {
	switch v := claims[name].(type) {
	case float64:
		t := time.Unix(int64(v), 0)
		return &t, false
	case json.Number:
		if n, err := v.Int64(); err == nil {
			t := time.Unix(n, 0)
			return &t, false
		}
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			t := time.Unix(n, 0)
			return &t, true
		}
	}
	return nil, false
}
