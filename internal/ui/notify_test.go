package ui

import (
	"strings"
	"testing"

	"github.com/anotherhadi/ilovetui/notification"
)

// queuedToasts runs the toast cmds queued on m and returns them, draining m.pending.
func queuedToasts(m *model) []notification.Toast {
	var out []notification.Toast
	for _, cmd := range m.pending {
		if msg, ok := cmd().(notification.ShowMsg); ok {
			out = append(out, msg.Toast)
		}
	}
	m.pending = nil
	return out
}

func TestResignShowsToastInView(t *testing.T) {
	m := initialModel(sampleJWT, "your-256-bit-secret")
	m.width, m.height = 100, 30
	m.recalcSizes()

	m.resignToken()
	toasts := queuedToasts(&m)
	if len(toasts) != 1 || toasts[0].Kind != notification.Success {
		t.Fatalf("queued toasts = %+v, want one success toast", toasts)
	}

	next, _ := m.Update(notification.ShowMsg{Toast: toasts[0]})
	if view := stripANSI(next.(model).View().Content); !strings.Contains(view, toasts[0].Title) {
		t.Fatalf("view does not render the toast %q", toasts[0].Title)
	}
	if next.(model).pending != nil {
		t.Fatalf("Update must drain pending toasts")
	}
}

func TestSignatureErrorIsAToastOnceAndNotAStatusLine(t *testing.T) {
	m := initialModel(sampleJWT, "wrong-secret")
	m.width, m.height = 100, 30
	m.recalcSizes()

	toasts := queuedToasts(&m)
	if len(toasts) != 1 || toasts[0].Kind != notification.Error || toasts[0].Title != "Signature" {
		t.Fatalf("queued toasts = %+v, want one signature error toast", toasts)
	}
	m.refresh() // same error again: must not re-notify
	if again := queuedToasts(&m); len(again) != 0 {
		t.Fatalf("unchanged error re-notified: %+v", again)
	}
	if view := stripANSI(m.View().Content); strings.Contains(view, m.sigError) {
		t.Fatalf("signature error %q still rendered inline", m.sigError)
	}
}
