package highlight

import "testing"

func TestJSONTrailingBackslashDoesNotPanic(t *testing.T) {
	for _, s := range []string{`"\`, `{"a":"x\`} {
		_ = JSON(s)
	}
}
