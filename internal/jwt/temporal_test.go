package jwt

import (
	"testing"
	"time"
)

func TestEvaluateTemporal(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name   string
		claims map[string]interface{}
		want   TemporalState
	}{
		{"no claims", nil, TempNone},
		{"no temporal claims", map[string]interface{}{"sub": "x"}, TempNone},
		{"expired", map[string]interface{}{"exp": float64(now.Unix() - 1)}, TempExpired},
		{"still valid", map[string]interface{}{"exp": float64(now.Unix() + 60)}, TempValid},
		{"not yet valid", map[string]interface{}{"nbf": float64(now.Unix() + 60)}, TempNotYetValid},
		{"exp wins over nbf", map[string]interface{}{
			"exp": float64(now.Unix() - 1),
			"nbf": float64(now.Unix() + 60),
		}, TempExpired},
		{"exp as string", map[string]interface{}{"exp": "1699999999"}, TempExpired},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := EvaluateTemporal(tc.claims, now).State; got != tc.want {
				t.Fatalf("state = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvaluateTemporalFollowsTheClock(t *testing.T) {
	exp := time.Unix(1_700_000_000, 0)
	claims := map[string]interface{}{"exp": float64(exp.Unix())}

	if got := EvaluateTemporal(claims, exp.Add(-time.Second)).State; got != TempValid {
		t.Fatalf("before expiry: %v, want TempValid", got)
	}
	if got := EvaluateTemporal(claims, exp.Add(time.Second)).State; got != TempExpired {
		t.Fatalf("after expiry: %v, want TempExpired", got)
	}
}

func TestEvaluateTemporalFlagsStringClaims(t *testing.T) {
	got := EvaluateTemporal(map[string]interface{}{
		"exp": "1700000060",
		"iat": float64(1_700_000_000),
	}, time.Unix(1_700_000_000, 0))

	if len(got.StringClaims) != 1 || got.StringClaims[0] != "exp" {
		t.Fatalf("StringClaims = %v, want [exp]", got.StringClaims)
	}
	if got.ExpiresAt == nil {
		t.Fatal("a string exp should still be parsed, not dropped")
	}
}
