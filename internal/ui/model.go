package ui

import (
	_ "embed"

	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/anotherhadi/ilovetui/bubbles"
	"github.com/anotherhadi/ilovetui/helpbar"
	"github.com/anotherhadi/ilovetui/minsize"
	"github.com/anotherhadi/ilovetui/notification"
	theme "github.com/anotherhadi/ilovetui/style"

	"github.com/chiloute/jwt-tui/internal/highlight"
	"github.com/chiloute/jwt-tui/internal/jwt"
	"github.com/chiloute/jwt-tui/internal/keys"
)

//go:embed docs.md
var jwtDocsMD string

const (
	panelEncoded = iota
	panelHeader
	panelPayload
	panelSecret
)

const (
	overlayNone = iota
	overlayDocs
	overlayAnalysis
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

	notif notification.Model
	// toasts queued by *model helpers; Update drains them into tea.Cmds.
	pending []tea.Cmd

	sig      jwt.SigState
	temporal jwt.TemporalState
	edit     jwt.EditState
	sigError string

	desynced bool

	keyResult jwt.VerifyResult

	claims   map[string]interface{}
	findings []jwt.Finding

	pendingPastePanel int

	help    helpbar.Model
	size    minsize.Model
	overlay int

	docsVP       viewport.Model
	docsRendered string
	docsWidth    int
	analysisVP   viewport.Model

	width, height int
}

func initialModel(token, secret string) model {
	m := model{
		focus: panelEncoded,
		edit:  jwt.EditOriginal,
		notif: notification.New(notification.WithPosition(notification.TopRight)),
		help:  helpbar.New(helpbar.WithToggle(keys.Keys.HelpToggle), helpbar.WithGlobal(keys.Short()...)),
		// shortcut: floor matches the smallest size the layout tests cover; raise it together with them
		size: minsize.New(20, 12),
	}
	for i := range m.panels {
		ta := bubbles.NewTextarea(false)
		vp := bubbles.NewViewport()
		vp.SoftWrap = true
		m.panels[i].ta = ta
		m.panels[i].vp = vp
	}
	m.docsVP = bubbles.NewViewport()
	m.docsVP.SoftWrap = true
	m.analysisVP = bubbles.NewViewport()
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

	m.help.SetWidth(m.width)
	leftW, rightW, topH, bottomH := m.grid()

	frame := panelBorder(false).GetHorizontalFrameSize()
	setPanel := func(idx, w, h int) {
		// one row goes to the title line drawn above the box, one to the bottom border
		cw, ch := max(1, w-frame), max(1, theme.ContentHeight(h))
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

// grid splits the screen into the 2x2 panel layout, minus the help bar.
func (m model) grid() (leftW, rightW, topH, bottomH int) {
	leftW = m.width / 2
	rightW = m.width - leftW
	availH := max(4, m.height-m.help.Height(m.helpExtras()...))
	topH = availH / 2
	return leftW, rightW, topH, availH - topH
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

// notify queues a toast. id makes repeated events (e.g. one per keystroke)
// replace the previous toast instead of stacking.
func (m *model) notify(id, title, msg string, kind notification.Kind) {
	m.pending = append(m.pending, notification.Show(title, msg, kind, notification.WithID(id)))
}
