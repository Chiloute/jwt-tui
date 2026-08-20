package ui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	ilovetui "github.com/anotherhadi/ilovetui"

	"github.com/chiloute/jwt-tui/internal/jwt"
	"github.com/chiloute/jwt-tui/internal/keys"
	"github.com/chiloute/jwt-tui/internal/style"
)

var (
	mutedStyle   = lipgloss.NewStyle().Foreground(ilovetui.S.Muted)
	successStyle = lipgloss.NewStyle().Foreground(ilovetui.S.Success).Bold(true)
	warningStyle = lipgloss.NewStyle().Foreground(ilovetui.S.Warning).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(ilovetui.S.Error).Bold(true)
)

func (m model) View() tea.View {
	var content string
	switch {
	case m.width == 0:
		content = ""
	case m.showDocs:
		content = m.renderDocsView()
	case m.showAnalysis:
		content = m.renderAnalysisView()
	default:
		content = m.renderMainView()
	}
	v := tea.NewView(content)
	v.AltScreen = true
	return v
}

func (m model) renderMainView() string {
	leftW := m.width / 2
	rightW := m.width - leftW

	helpH := keys.BarHeight(m.showHelp, m.width)
	statusH := 0
	if m.statusLine() != "" {
		statusH = 1
	}
	availH := m.height - helpH - statusH
	if availH < 4 {
		availH = 4
	}
	topH := availH / 2
	bottomH := availH - topH

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

func (m model) renderDocsView() string {
	docsBorder := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ilovetui.S.Subtle).
		Padding(0, 1)

	window := docsBorder.Render(ilovetui.ViewportView(&m.docsVP))

	hm := ilovetui.NewHelp()
	hm.SetWidth(m.width)

	helpStr := hm.View(keys.DocsKeyMap{})

	return lipgloss.JoinVertical(lipgloss.Left, window, helpStr)
}

func (m model) renderAnalysisView() string {
	border := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ilovetui.S.Subtle).
		Padding(0, 1)

	window := style.RenderWithTitle(border, m.analysisTitle(),
		ilovetui.ViewportView(&m.analysisVP), m.width, m.height-2)

	hm := ilovetui.NewHelp()
	hm.SetWidth(m.width)

	return lipgloss.JoinVertical(lipgloss.Left, window, hm.View(keys.AnalysisKeyMap{}))
}

func (m model) analysisTitle() string {
	title := lipgloss.NewStyle().Foreground(ilovetui.S.Primary).Bold(true).Render("Analysis")
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
	border := style.PanelBorder(m.focus == fs)
	content := m.renderPanelContent(fs)
	return style.RenderWithTitle(border, title, content, w, h)
}

func (m model) renderPanelContent(fs int) string {
	p := &m.panels[fs]
	if p.editing {
		return p.ta.View()
	}
	if fs == panelSecret {
		return m.renderSecretContent()
	}
	if p.ta.Value() == "" {
		return mutedStyle.Render(panelPlaceholders[fs])
	}
	return ilovetui.ViewportView(&p.vp)
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
	c := ilovetui.S.Subtle
	if focused {
		c = ilovetui.S.Primary
	}
	title := lipgloss.NewStyle().Foreground(c).Bold(focused).Render(name)
	if focused && m.panels[fs].editing {
		title += mutedStyle.Render(" [edit]")
	}
	return title
}

func (m model) sigSymbol() string {
	switch {
	case m.desynced:
		return warningStyle.Render("⚠")
	case m.sig == jwt.SigValid && m.edit == jwt.EditResigned:
		return warningStyle.Render("✓")
	case m.sig == jwt.SigValid:
		return successStyle.Render("✓")
	case m.sig == jwt.SigNoKey, m.sig == jwt.SigEmpty:
		return mutedStyle.Render("·")
	}
	return errorStyle.Render("✗")
}

func (m model) sigLabel() (string, lipgloss.Style) {
	switch {
	case m.desynced:
		return "desynced", warningStyle
	case m.sig == jwt.SigValid && m.edit == jwt.EditResigned:
		return "valid (self-signed)", warningStyle
	case m.sig == jwt.SigValid:
		return m.sig.String(), successStyle
	case m.sig == jwt.SigEmpty, m.sig == jwt.SigNoKey:
		return m.sig.String(), mutedStyle
	}
	return m.sig.String(), errorStyle
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
	return title + mutedStyle.Render(" ") + m.sigSymbol()
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
	switch {
	case m.errorMsg != "":
		return lipgloss.NewStyle().MaxWidth(m.width).Render(errorStyle.Render(" " + m.errorMsg))
	case m.successMsg != "":
		return lipgloss.NewStyle().MaxWidth(m.width).Render(successStyle.Render(" " + m.successMsg))
	case m.sigError != "" && m.sig != jwt.SigValid && m.sig != jwt.SigEmpty:
		return lipgloss.NewStyle().MaxWidth(m.width).Render(errorStyle.Render(" " + m.sigError))
	}
	return ""
}

func (m model) renderHelpBar() string {
	hm := ilovetui.NewHelp()
	hm.SetWidth(m.width)
	hm.ShowAll = m.showHelp

	helpStr := hm.View(keys.HelpKeyMap{Width: m.width})

	label, st := m.sigLabel()
	sigStr := st.Render(label)
	if len(m.findings) > 0 {
		sigStr = m.findingsCount() + mutedStyle.Render(" · ") + sigStr
	}

	lines := strings.Split(helpStr, "\n")
	// bubbles' help component can fail to truncate to hm.SetWidth when even
	// its ellipsis wouldn't fit (see help.Model.shouldAddItem), so clamp
	// every line ourselves or an overflowing bar stretches the whole view.
	for i, line := range lines {
		if lipgloss.Width(line) > m.width {
			lines[i] = lipgloss.NewStyle().MaxWidth(m.width).Render(line)
		}
	}
	last := lines[len(lines)-1]
	pad := m.width - lipgloss.Width(last) - lipgloss.Width(sigStr)
	if pad >= 1 {
		lines[len(lines)-1] = last + strings.Repeat(" ", pad) + sigStr
	}
	return strings.Join(lines, "\n")
}
