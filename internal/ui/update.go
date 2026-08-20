package ui

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/glamour/v2"
	"charm.land/lipgloss/v2"
	ilovetui "github.com/anotherhadi/ilovetui"

	"github.com/chiloute/jwt-tui/internal/jwt"
	"github.com/chiloute/jwt-tui/internal/keys"
)

type clearStatusMsg struct{}

type temporalTickMsg struct{}

func autoClearStatus() tea.Cmd {
	return tea.Tick(3*time.Second, func(_ time.Time) tea.Msg {
		return clearStatusMsg{}
	})
}

func temporalTick() tea.Cmd {
	return tea.Tick(time.Second, func(_ time.Time) tea.Msg {
		return temporalTickMsg{}
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.recalcSizes()
		if m.showDocs {
			m.renderDocs()
		}
		if m.showAnalysis {
			m.renderAnalysis()
		}
		return m, nil

	case tea.ClipboardMsg:
		content := msg.String()
		if content != "" {
			p := m.pendingPastePanel
			m.focus = p
			m.setText(p, content)
			m.onContentChange()
		}
		return m, nil

	case clearStatusMsg:
		m.errorMsg = ""
		m.successMsg = ""
		m.recalcSizes()
		return m, nil

	case temporalTickMsg:
		m.temporal = jwt.EvaluateTemporal(m.claims, time.Now()).State
		return m, temporalTick()

	case editorFinishedMsg:
		m.applyEditorResult(msg)
		m.recalcSizes()
		return m, autoClearStatus()

	case tea.KeyPressMsg:
		if m.showDocs {
			switch {
			case key.Matches(msg, keys.Keys.Quit):
				return m, tea.Quit
			case key.Matches(msg, keys.Keys.Docs), msg.String() == "esc":
				m.showDocs = false
				return m, nil
			default:
				var cmd tea.Cmd
				m.docsVP, cmd = m.docsVP.Update(msg)
				return m, cmd
			}
		}

		if m.showAnalysis {
			switch {
			case key.Matches(msg, keys.Keys.Quit):
				return m, tea.Quit
			case key.Matches(msg, keys.Keys.Analysis), msg.String() == "esc":
				m.showAnalysis = false
				return m, nil
			default:
				var cmd tea.Cmd
				m.analysisVP, cmd = m.analysisVP.Update(msg)
				return m, cmd
			}
		}

		if m.panels[m.focus].editing {
			if s := msg.String(); s == "esc" || s == "ctrl+c" {
				m.exitEditMode()
				return m, nil
			}
			p := &m.panels[m.focus]
			prev := p.ta.Value()
			var cmd tea.Cmd
			p.ta, cmd = p.ta.Update(msg)
			if p.ta.Value() != prev {
				m.onContentChange()
			}
			return m, cmd
		}

		return m.handleViewKey(msg)

	default:
		if m.panels[m.focus].editing {
			p := &m.panels[m.focus]
			var cmd tea.Cmd
			p.ta, cmd = p.ta.Update(msg)
			return m, cmd
		}
		return m, nil
	}
}

func (m model) handleViewKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, keys.Keys.Quit):
		return m, tea.Quit

	case key.Matches(msg, keys.Keys.CycleFocus):
		m.focus = (m.focus + 1) % 4
		return m, nil

	case msg.String() == "shift+tab":
		m.focus = (m.focus + 3) % 4
		return m, nil

	case key.Matches(msg, keys.Keys.Edit):
		return m, m.enterEditMode()

	case key.Matches(msg, keys.Keys.ExternalEdit):
		return m, m.openInEditor()

	case key.Matches(msg, keys.Keys.Clear):
		m.clearPanel()
		return m, nil

	case key.Matches(msg, keys.Keys.Copy):
		return m, tea.SetClipboard(m.text(m.focus))

	case key.Matches(msg, keys.Keys.Paste):
		m.pendingPastePanel = m.focus
		return m, tea.ReadClipboard

	case key.Matches(msg, keys.Keys.Resign):
		m.resignToken()
		m.refresh()
		return m, autoClearStatus()

	case key.Matches(msg, keys.Keys.Refresh):
		switch m.focus {
		case panelEncoded:
			m.decodeFromEncoded()
		case panelHeader, panelPayload:
			m.rebuildEncoded()
		}
		m.refresh()
		return m, autoClearStatus()

	case key.Matches(msg, keys.Keys.HelpToggle):
		m.showHelp = !m.showHelp
		m.recalcSizes()
		return m, nil

	case key.Matches(msg, keys.Keys.Docs):
		m.showHelp = false
		m.showDocs = true
		m.renderDocs()
		return m, nil

	case key.Matches(msg, keys.Keys.Analysis):
		m.showHelp = false
		m.showAnalysis = true
		m.renderAnalysis()
		return m, nil

	default:
		var cmd tea.Cmd
		m.panels[m.focus].vp, cmd = m.panels[m.focus].vp.Update(msg)
		return m, cmd
	}
}

func (m *model) onContentChange() {
	switch m.focus {
	case panelEncoded:
		m.decodeFromEncoded()
	case panelHeader, panelPayload:
		m.rebuildEncoded()
	case panelSecret:
		if m.edit == jwt.EditModified || m.edit == jwt.EditResigned {
			m.resignToken()
		}
	}
	m.refresh()
}

func (m *model) refresh() {
	enc, key := m.text(panelEncoded), m.text(panelSecret)
	result := jwt.VerifyToken(enc, key)
	m.sig = result.Sig
	m.temporal = result.Temporal
	m.sigError = result.SigError
	m.claims = result.Claims
	m.keyResult = result
	m.findings = jwt.Analyze(enc, key, result, time.Now())
	if m.showAnalysis {
		m.renderAnalysis()
	}
	m.recalcSizes()
}

func (m *model) decodeFromEncoded() {
	m.errorMsg = ""
	m.successMsg = ""
	m.desynced = false
	m.edit = jwt.EditOriginal

	info, err := jwt.ParseJWT(m.text(panelEncoded))
	if err != nil {
		if m.text(panelEncoded) != "" {
			m.errorMsg = err.Error()
		}
		m.setText(panelHeader, "")
		m.setText(panelPayload, "")
		m.algorithm = ""
		m.originalToken = ""
		return
	}

	m.setText(panelHeader, jwt.PrettyJSON(marshalJSON(info.Header)))
	m.setText(panelPayload, jwt.PrettyJSON(marshalJSON(info.Payload)))
	m.algorithm = info.Algorithm
	m.originalToken = info.Raw
}

func (m *model) rebuildEncoded() {
	m.errorMsg = ""
	m.successMsg = ""

	header := m.text(panelHeader)
	payload := m.text(panelPayload)
	if header == "" || payload == "" || !jwt.IsValidJSON(header) || !jwt.IsValidJSON(payload) {
		m.desynced = true
		m.errorMsg = "invalid JSON in header or payload"
		return
	}
	m.desynced = false

	var headerB64, payloadB64, signature string
	if cur, err := jwt.ParseJWT(m.text(panelEncoded)); err == nil {
		headerB64, payloadB64, signature = cur.HeaderB64, cur.PayloadB64, cur.Signature
	}
	if !jsonEqual(header, headerB64) {
		headerB64 = compactB64(header)
	}
	if !jsonEqual(payload, payloadB64) {
		payloadB64 = compactB64(payload)
	}

	rebuilt := headerB64 + "." + payloadB64 + "." + signature
	m.setText(panelEncoded, rebuilt)
	m.algorithm = algOf(header)
	if rebuilt == strings.TrimSpace(m.originalToken) {
		m.edit = jwt.EditOriginal
	} else {
		m.edit = jwt.EditModified
	}
}

func (m *model) resignToken() {
	m.errorMsg = ""
	m.successMsg = ""

	header := m.text(panelHeader)
	payload := m.text(panelPayload)
	if header == "" || payload == "" {
		m.errorMsg = "nothing to sign"
		return
	}
	if !jwt.IsValidJSON(header) || !jwt.IsValidJSON(payload) {
		m.errorMsg = "invalid JSON in header or payload"
		return
	}

	signed, err := jwt.SignToken(header, payload, m.text(panelSecret))
	if err != nil {
		m.errorMsg = err.Error()
		return
	}

	m.setText(panelEncoded, signed)
	m.edit = jwt.EditResigned
	m.successMsg = "token re-signed"
}

func (m *model) renderDocs() {
	width := m.docsVP.Width()
	if width < 40 {
		width = 40
	}

	if m.docsRendered != "" && m.docsWidth == width {
		m.docsVP.SetContent(m.docsRendered)
		m.docsVP.SetYOffset(0)
		return
	}

	renderer, err := glamour.NewTermRenderer(
		glamour.WithStyles(ilovetui.GlamourStyleConfig()),
		glamour.WithWordWrap(width),
	)
	if err != nil {
		m.docsVP.SetContent(jwtDocsMD)
		return
	}
	rendered, err := renderer.Render(jwtDocsMD)
	if err != nil {
		m.docsVP.SetContent(jwtDocsMD)
		return
	}
	m.docsRendered = rendered
	m.docsWidth = width
	m.docsVP.SetContent(rendered)
	m.docsVP.SetYOffset(0)
}

func (m *model) renderAnalysis() {
	width := m.analysisVP.Width()
	if width < 40 {
		width = 40
	}

	if len(m.findings) == 0 {
		m.analysisVP.SetContent(mutedStyle.Render("Nothing to report on this token."))
		m.analysisVP.SetYOffset(0)
		return
	}

	var b strings.Builder
	for i, f := range m.findings {
		if i > 0 {
			b.WriteString("\n\n")
		}
		st := severityStyle(f.Sev)
		b.WriteString(st.Render(strings.ToUpper(f.Sev.String())))
		b.WriteString("  ")
		b.WriteString(lipgloss.NewStyle().Bold(true).Render(f.Title))
		b.WriteString(mutedStyle.Render("  " + f.Code))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Width(width).Foreground(ilovetui.S.Subtle).Render(f.Detail))
	}

	m.analysisVP.SetContent(b.String())
	m.analysisVP.SetYOffset(0)
}

func marshalJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func compactB64(jsonStr string) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(jsonStr)); err == nil {
		return base64.RawURLEncoding.EncodeToString(buf.Bytes())
	}
	return base64.RawURLEncoding.EncodeToString([]byte(jsonStr))
}

func algOf(headerJSON string) string {
	var h map[string]interface{}
	if err := json.Unmarshal([]byte(headerJSON), &h); err != nil {
		return ""
	}
	alg, _ := h["alg"].(string)
	return alg
}

func jsonEqual(jsonStr, b64Str string) bool {
	if b64Str == "" {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(b64Str)
	if err != nil {
		return false
	}
	var a, b interface{}
	if err := json.Unmarshal([]byte(jsonStr), &a); err != nil {
		return false
	}
	if err := json.Unmarshal(decoded, &b); err != nil {
		return false
	}
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	return string(ra) == string(rb)
}
