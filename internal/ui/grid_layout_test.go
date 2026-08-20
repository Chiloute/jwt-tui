package ui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// TestMainGridStaysAlignedWhenNarrow guards against two ways the main 2x2
// grid can render wider than the terminal as it shrinks:
//   - panel titles (which vary in length, e.g. "Secret · verify ✓") overflowing
//     their box width and bleeding into the neighboring column
//   - the help bar failing to truncate to the terminal width (bubbles' help
//     component can skip truncation when even its ellipsis wouldn't fit)
//
// Either overflow stretches every line in the view via JoinVertical padding,
// so any single overflowing line breaks alignment across the whole grid.
func TestMainGridStaysAlignedWhenNarrow(t *testing.T) {
	for w := 20; w <= 140; w++ {
		for _, h := range []int{12, 20, 24, 30} {
			for _, empty := range []bool{true, false} {
				var m tea.Model
				if empty {
					m = initialModel("", "")
				} else {
					m = initialModel(sampleJWT, "your-256-bit-secret")
				}
				m, _ = m.Update(tea.WindowSizeMsg{Width: w, Height: h})
				out := m.(model).View().Content

				for i, line := range strings.Split(out, "\n") {
					if lw := lipgloss.Width(line); lw > w {
						t.Fatalf("%dx%d empty=%v: line %d is %d wide, exceeds terminal width %d: %q",
							w, h, empty, i, lw, w, stripANSI(line))
					}
				}
			}
		}
	}
}

// TestMainGridFillsAllocatedSpace guards against the grid rendering smaller
// than the terminal (leaving unused columns/rows) as opposed to overflowing
// it. A uniform under-fill can't be caught by a max-width check alone, since
// every line shrinks together and JoinVertical has nothing wider to pad
// against — so this asserts the view's width and height exactly match what
// was requested.
func TestMainGridFillsAllocatedSpace(t *testing.T) {
	for w := 20; w <= 140; w++ {
		for _, h := range []int{12, 20, 24, 30} {
			for _, empty := range []bool{true, false} {
				var m tea.Model
				if empty {
					m = initialModel("", "")
				} else {
					m = initialModel(sampleJWT, "your-256-bit-secret")
				}
				m, _ = m.Update(tea.WindowSizeMsg{Width: w, Height: h})
				out := m.(model).View().Content
				lines := strings.Split(out, "\n")

				if len(lines) != h {
					t.Fatalf("%dx%d empty=%v: view is %d lines tall, want %d",
						w, h, empty, len(lines), h)
				}
				for i, line := range lines {
					if lw := lipgloss.Width(line); lw != w {
						t.Fatalf("%dx%d empty=%v: line %d is %d wide, want %d: %q",
							w, h, empty, i, lw, w, stripANSI(line))
					}
				}
			}
		}
	}
}

// TestFullHelpBarStaysAlignedWhenNarrow is the same check with the full
// (toggled) help bar shown, which renders multiple columns instead of the
// single-line short help.
func TestFullHelpBarStaysAlignedWhenNarrow(t *testing.T) {
	for w := 20; w <= 140; w++ {
		for _, h := range []int{20, 24, 30} {
			var m tea.Model = initialModel(sampleJWT, "your-256-bit-secret")
			m, _ = m.Update(tea.WindowSizeMsg{Width: w, Height: h})
			m, _ = m.Update(tea.KeyPressMsg(tea.Key{Text: "?", Code: '?'}))
			out := m.(model).View().Content

			for i, line := range strings.Split(out, "\n") {
				if lw := lipgloss.Width(line); lw > w {
					t.Fatalf("%dx%d: line %d is %d wide, exceeds terminal width %d: %q",
						w, h, i, lw, w, stripANSI(line))
				}
			}
		}
	}
}
