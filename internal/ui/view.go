package ui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/anotherhadi/ilovetui/bubbles"
	"github.com/anotherhadi/ilovetui/helpbar"
	theme "github.com/anotherhadi/ilovetui/style"

	"github.com/chiloute/jwt-tui/internal/jwt"
	"github.com/chiloute/jwt-tui/internal/keys"
)

var (
	mutedStyle   = lipgloss.NewStyle().Foreground(theme.S.Muted)
	successStyle = lipgloss.NewStyle().Foreground(theme.S.Success).Bold(true)
	warningStyle = lipgloss.NewStyle().Foreground(theme.S.Warning).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(theme.S.Error).Bold(true)
)

func (m model) View() tea.View {
	var content string
	switch {
	case m.width == 0:
		content = ""
	case !m.size.Fits(m.width, m.height):
		content = m.size.View(m.width, m.height)
	case m.overlay == overlayDocs:
		content = m.renderDocsView()
	case m.overlay == overlayAnalysis:
		content = m.renderAnalysisView()
	default:
		content = m.renderMainView()
	}
	v := tea.NewView(m.notif.Render(content))
	v.AltScreen = true
	return v
}

func (m model) renderMainView() string {
	leftW, rightW, topH, bottomH := m.grid()

	encoded := m.renderPanel(panelEncoded, m.encodedTitle(), leftW, topH)
	header := m.renderPanel(panelHeader, m.panelTitle(panelHeader, "Header"), rightW, topH)
	secret := m.renderPanel(panelSecret, m.secretTitle(), leftW, bottomH)
	payload := m.renderPanel(panelPayload, m.payloadTitle(), rightW, bottomH)

	left := lipgloss.JoinVertical(lipgloss.Left, encoded, secret)
	right := lipgloss.JoinVertical(lipgloss.Left, header, payload)
	main := lipgloss.JoinHorizontal(lipgloss.Top, left, right)

	parts := []string{main}
	if line := m.statusLine(); line != "" {
		parts = append(parts, line)
	}
	parts = append(parts, m.renderHelpBar())

	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

func panelBorder(focused bool) lipgloss.Style {
	if focused {
		return theme.S.PanelFocused.Padding(0, 1)
	}
	return theme.S.Panel.Padding(0, 1)
}

func overlayHelp(width int, close key.Binding) string {
	hb := helpbar.New(helpbar.WithGlobal(keys.Overlay(close)...))
	hb.SetWidth(width)
	return hb.View()
}

func (m model) renderDocsView() string {
	window := panelBorder(false).Render(bubbles.ViewportView(&m.docsVP))
	return lipgloss.JoinVertical(lipgloss.Left, window, overlayHelp(m.width, keys.Keys.Docs))
}

func (m model) renderAnalysisView() string {
	window := theme.RenderWithTitle(panelBorder(false), m.analysisTitle(),
		bubbles.ViewportView(&m.analysisVP), m.width, m.height-2)
	return lipgloss.JoinVertical(lipgloss.Left, window, overlayHelp(m.width, keys.Keys.Analysis))
}

func (m model) analysisTitle() string {
	title := lipgloss.NewStyle().Foreground(theme.S.Primary).Bold(true).Render("Analysis")
	if len(m.findings) == 0 {
		return title + mutedStyle.Render(" · nothing to report")
	}
	return title + mutedStyle.Render(" · ") + m.findingsCount()
}

func (m model) findingsCount() string {
	worst := jwt.SevInfo
	for _, f := range m.findings {
		if f.Sev > worst {
			worst = f.Sev
		}
	}
	return severityStyle(worst).Render(fmt.Sprintf("⚠ %d", len(m.findings)))
}

func severityStyle(sev jwt.Severity) lipgloss.Style {
	switch sev {
	case jwt.SevDanger:
		return errorStyle
	case jwt.SevWarn:
		return warningStyle
	}
	return mutedStyle
}

func (m model) renderPanel(fs int, title string, w, h int) string {
	return theme.RenderWithTitle(panelBorder(m.focus == fs), title, m.renderPanelContent(fs), w, h)
}

func (m model) renderPanelContent(fs int) string {
	p := &m.panels[fs]
	// text drawn outside a viewport must be wrapped and clipped by hand or the box grows
	fit := lipgloss.NewStyle().Width(p.vp.Width()).MaxHeight(p.vp.Height())
	if p.editing {
		return p.ta.View()
	}
	if fs == panelSecret {
		return fit.Render(m.renderSecretContent())
	}
	if p.ta.Value() == "" {
		return fit.Render(mutedStyle.Render(panelPlaceholders[fs]))
	}
	return bubbles.ViewportView(&p.vp)
}

func (m model) renderSecretContent() string {
	spec := m.panels[panelSecret].ta.Value()
	body := m.secretBody(spec)

	res := m.keyResult
	var parts []string
	if fam := jwt.AlgoFamily(m.algorithm); m.algorithm != "" && fam != "unknown" {
		parts = append(parts, "("+fam+")")
	}
	if res.KeyEncoding != jwt.EncNone {
		enc := res.KeyEncoding.String()
		if res.KeyEncoding != jwt.EncPlain {
			if res.KeyPrivate {
				enc += " private"
			} else {
				enc += " public"
			}
		}
		parts = append(parts, enc)
	}
	if res.KeyBytes > 0 {
		parts = append(parts, fmt.Sprintf("%d bytes", res.KeyBytes))
	}
	if res.KeyOrigin != "" {
		parts = append(parts, res.KeyOrigin)
	}

	hint := mutedStyle.Render(strings.Join(parts, " · "))
	if res.KeyTrimmed {
		hint += warningStyle.Render("  trailing whitespace stripped")
	}

	return body + "\n\n" + hint
}

func (m model) secretBody(spec string) string {
	if spec == "" {
		return mutedStyle.Render("HMAC secret, or @file / b64: / PEM / JWKS")
	}
	trimmed := strings.TrimSpace(spec)
	if strings.HasPrefix(trimmed, "@") {
		return trimmed
	}
	if rest, ok := strings.CutPrefix(trimmed, "b64:"); ok {
		return "b64:" + strings.Repeat("*", len([]rune(rest)))
	}
	if strings.Contains(spec, "-----BEGIN") || strings.HasPrefix(trimmed, "{") {
		return mutedStyle.Render(fmt.Sprintf("%s pasted (%d bytes)", m.keyResult.KeyEncoding, len(spec)))
	}
	return strings.Repeat("*", len([]rune(spec)))
}

func (m model) panelTitle(fs int, name string) string {
	focused := m.focus == fs
	c := theme.S.Subtle
	if focused {
		c = theme.S.Primary
	}
	title := lipgloss.NewStyle().Foreground(c).Bold(focused).Render(name)
	if focused && m.panels[fs].editing {
		title += mutedStyle.Render(" [edit]")
	}
	return title
}

func (m model) sigLabel() (label, symbol string, st lipgloss.Style) {
	switch {
	case m.desynced:
		return "desynced", "⚠", warningStyle
	case m.sig == jwt.SigValid && m.edit == jwt.EditResigned:
		return "valid (self-signed)", "✓", warningStyle
	case m.sig == jwt.SigValid:
		return m.sig.String(), "✓", successStyle
	case m.sig == jwt.SigEmpty, m.sig == jwt.SigNoKey:
		return m.sig.String(), "·", mutedStyle
	}
	return m.sig.String(), "✗", errorStyle
}

func (m model) encodedTitle() string {
	title := m.panelTitle(panelEncoded, "Encoded")
	switch m.edit {
	case jwt.EditModified:
		title += warningStyle.Render(" (modified)")
	case jwt.EditResigned:
		title += warningStyle.Render(" (re-signed)")
	}
	return title
}

func (m model) temporalSymbol() string {
	switch m.temporal {
	case jwt.TempValid:
		return successStyle.Render("✓")
	case jwt.TempExpired, jwt.TempNotYetValid:
		return errorStyle.Render("✗")
	default:
		return mutedStyle.Render("·")
	}
}

func (m model) secretTitle() string {
	title := m.panelTitle(panelSecret, "Secret") + mutedStyle.Render(" · ") + m.secretRole()
	_, symbol, st := m.sigLabel()
	return title + mutedStyle.Render(" ") + st.Render(symbol)
}

func (m model) secretRole() string {
	if m.edit == jwt.EditModified || m.edit == jwt.EditResigned {
		role := "sign"
		if m.keyResult.KeyEncoding != jwt.EncPlain && m.keyResult.KeyEncoding != jwt.EncNone && !m.keyResult.KeyPrivate {
			return warningStyle.Render(role + " · public key")
		}
		return mutedStyle.Render(role)
	}
	return mutedStyle.Render("verify")
}

func (m model) payloadTitle() string {
	return m.panelTitle(panelPayload, "Payload") + mutedStyle.Render(" · ") + m.temporalSymbol()
}

func (m model) statusLine() string {
	if m.sigError != "" && m.sig != jwt.SigValid && m.sig != jwt.SigEmpty {
		return lipgloss.NewStyle().MaxWidth(m.width).Render(errorStyle.Render(" " + m.sigError))
	}
	return ""
}

func (m model) helpExtras() []key.Binding {
	if m.help.ShowAll {
		return keys.Extra()
	}
	return nil
}

// renderHelpBar is the helpbar with the signature state right-aligned on its last line.
func (m model) renderHelpBar() string {
	label, _, st := m.sigLabel()
	sigStr := st.Render(label)
	if len(m.findings) > 0 {
		sigStr = m.findingsCount() + mutedStyle.Render(" · ") + sigStr
	}

	lines := strings.Split(m.help.View(m.helpExtras()...), "\n")
	last := lines[len(lines)-1]
	if pad := m.width - lipgloss.Width(last) - lipgloss.Width(sigStr); pad >= 1 {
		lines[len(lines)-1] = last + strings.Repeat(" ", pad) + sigStr
	}
	return strings.Join(lines, "\n")
}
