package ui

import (
	_ "embed"

	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	ilovetui "github.com/anotherhadi/ilovetui"

	"github.com/chiloute/jwt-tui/internal/highlight"
	"github.com/chiloute/jwt-tui/internal/jwt"
	"github.com/chiloute/jwt-tui/internal/keys"
	"github.com/chiloute/jwt-tui/internal/style"
)

//go:embed docs.md
var jwtDocsMD string

const (
	panelEncoded = iota
	panelHeader
	panelPayload
	panelSecret
)

var panelPlaceholders = [4]string{
	"Paste or type JWT token...",
	"{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}",
	"{\n  \"sub\": \"1234567890\",\n  \"name\": \"John Doe\",\n  \"iat\": 1516239022\n}",
	"",
}

type panelState struct {
	vp      viewport.Model
	ta      textarea.Model
	editing bool
}

type model struct {
	panels [4]panelState
	focus  int

	originalToken string
	algorithm     string

	errorMsg   string
	successMsg string

	sig      jwt.SigState
	temporal jwt.TemporalState
	edit     jwt.EditState
	sigError string

	desynced bool

	keyResult jwt.VerifyResult

	claims   map[string]interface{}
	findings []jwt.Finding

	pendingPastePanel int

	showHelp     bool
	showDocs     bool
	docsVP       viewport.Model
	docsRendered string
	docsWidth    int

	showAnalysis bool
	analysisVP   viewport.Model

	width, height int
}

func initialModel(token, secret string) model {
	m := model{
		focus: panelEncoded,
		edit:  jwt.EditOriginal,
	}
	for i := range m.panels {
		ta := ilovetui.NewTextarea(false)
		vp := ilovetui.NewViewport()
		vp.SoftWrap = true
		m.panels[i].ta = ta
		m.panels[i].vp = vp
	}
	m.docsVP = ilovetui.NewViewport()
	m.docsVP.SoftWrap = true
	m.analysisVP = ilovetui.NewViewport()
	m.analysisVP.SoftWrap = true

	if secret != "" {
		m.setText(panelSecret, secret)
	}
	if token != "" {
		m.setText(panelEncoded, token)
		m.decodeFromEncoded()
	}
	m.refresh()
	return m
}

func (m model) Init() tea.Cmd {
	return temporalTick()
}

func (m *model) text(panel int) string { return m.panels[panel].ta.Value() }

func (m *model) setText(panel int, s string) {
	m.panels[panel].ta.SetValue(s)
	m.setViewportContent(panel, s)
}

func (m *model) setViewportContent(panel int, raw string) {
	switch panel {
	case panelHeader, panelPayload:
		m.panels[panel].vp.SetContent(highlight.JSON(raw))
	case panelEncoded:
		m.panels[panel].vp.SetContent(highlight.JWT(raw))
	}
}

func (m *model) recalcSizes() {
	if m.width == 0 || m.height == 0 {
		return
	}

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

	border := style.PanelBorder(false)
	setPanel := func(idx, w, h int) {
		cw, ch := style.PanelContentSize(border, w, h)
		m.panels[idx].vp.SetWidth(cw)
		m.panels[idx].vp.SetHeight(ch)
		m.panels[idx].ta.SetWidth(cw)
		m.panels[idx].ta.SetHeight(ch)
	}
	setPanel(panelEncoded, leftW, topH)
	setPanel(panelHeader, rightW, topH)
	setPanel(panelSecret, leftW, bottomH)
	setPanel(panelPayload, rightW, bottomH)

	m.docsVP.SetHeight(max(1, m.height-3))
	m.docsVP.SetWidth(max(1, m.width-4))
	m.analysisVP.SetHeight(max(1, m.height-4))
	m.analysisVP.SetWidth(max(1, m.width-4))
}

func (m *model) enterEditMode() tea.Cmd {
	p := &m.panels[m.focus]
	p.editing = true
	return p.ta.Focus()
}

func (m *model) exitEditMode() {
	p := &m.panels[m.focus]
	if !p.editing {
		return
	}
	p.editing = false
	p.ta.Blur()
	m.setViewportContent(m.focus, p.ta.Value())
	m.onContentChange()
}

func (m *model) clearPanel() {
	p := &m.panels[m.focus]
	p.editing = false
	p.ta.Blur()
	m.setText(m.focus, "")
	m.onContentChange()
}
