package ui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

func TestOverlaysFitHeight(t *testing.T) {
	overlays := map[string]rune{"docs": 'd', "analysis": 'a'}

	for name, k := range overlays {
		for _, size := range [][2]int{{80, 24}, {120, 40}, {100, 30}} {
			w, h := size[0], size[1]
			var m tea.Model = initialModel(sampleJWT, "your-256-bit-secret")
			m, _ = m.Update(tea.WindowSizeMsg{Width: w, Height: h})
			m, _ = m.Update(tea.KeyPressMsg(tea.Key{Text: string(k), Code: k}))
			out := m.(model).View().Content
			lines := strings.Count(out, "\n") + 1
			if lines > h {
				t.Errorf("%s %dx%d: view is %d lines, exceeds height %d", name, w, h, lines, h)
			}
			if lipgloss.Width(out) > w {
				t.Errorf("%s %dx%d: view width %d exceeds %d", name, w, h, lipgloss.Width(out), w)
			}
		}
	}
}

func TestAnalysisOverlayOpens(t *testing.T) {
	var m tea.Model = initialModel(sampleJWT, "your-256-bit-secret")
	m, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m, _ = m.Update(tea.KeyPressMsg(tea.Key{Text: "a", Code: 'a'}))

	if !m.(model).showAnalysis {
		t.Fatal("pressing a did not open the analysis overlay")
	}
	// jwt.io's demo secret is 19 bytes, so there is always something to say
	if len(m.(model).findings) == 0 {
		t.Fatal("no findings for the jwt.io sample token")
	}
	if !strings.Contains(m.(model).View().Content, "HMAC key is 19 bytes") {
		t.Error("the weak-key finding is not rendered in the overlay")
	}

	m, _ = m.Update(tea.KeyPressMsg(tea.Key{Text: "a", Code: 'a'}))
	if m.(model).showAnalysis {
		t.Fatal("pressing a again did not close the overlay")
	}
}
