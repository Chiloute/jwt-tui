package keys

import (
	"strings"

	"charm.land/bubbles/v2/key"

	"github.com/chiloute/jwt-tui/internal/config"
)

type KeyMap struct {
	Quit         key.Binding
	CycleFocus   key.Binding
	Edit         key.Binding
	ExternalEdit key.Binding
	Docs         key.Binding
	Analysis     key.Binding
	HelpToggle   key.Binding
	Clear        key.Binding
	Copy         key.Binding
	Paste        key.Binding
	Resign       key.Binding
	Refresh      key.Binding
}

var Keys *KeyMap

func init() { Init(config.Default()) }

func Init(cfg *config.Config) {
	kb := cfg.Keybindings
	Keys = &KeyMap{
		Quit:         binding(kb.Quit, "quit"),
		CycleFocus:   binding(kb.CycleFocus, "cycle focus"),
		Edit:         binding(kb.Edit, "insert"),
		ExternalEdit: binding(kb.ExternalEdit, "edit in $EDITOR"),
		Docs:         binding(kb.Docs, "docs"),
		Analysis:     binding(kb.Analysis, "analysis"),
		HelpToggle:   binding(kb.HelpToggle, "toggle help"),
		Clear:        binding(kb.Clear, "clear panel"),
		Copy:         binding(kb.Copy, "copy"),
		Paste:        binding(kb.Paste, "paste"),
		Resign:       binding(kb.Resign, "re-sign"),
		Refresh:      binding(kb.Refresh, "refresh"),
	}
}

func binding(s, help string) key.Binding {
	ks := parseKeys(s)
	return key.NewBinding(key.WithKeys(ks...), key.WithHelp(strings.Join(ks, "/"), help))
}

func parseKeys(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if k := strings.TrimSpace(p); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func shortList() []key.Binding {
	return []key.Binding{
		Keys.CycleFocus, Keys.Edit, Keys.ExternalEdit, Keys.Analysis, Keys.Docs,
		Keys.HelpToggle, Keys.Quit,
	}
}

func fullList() []key.Binding {
	return []key.Binding{
		Keys.CycleFocus, Keys.Edit, Keys.ExternalEdit, Keys.Analysis, Keys.Docs,
		Keys.HelpToggle, Keys.Quit, Keys.Clear, Keys.Resign, Keys.Refresh,
		Keys.Copy, Keys.Paste,
	}
}

type HelpKeyMap struct {
	Width int
}

func (k HelpKeyMap) ShortHelp() []key.Binding  { return shortList() }
func (k HelpKeyMap) FullHelp() [][]key.Binding { return chunkByWidth(fullList(), k.Width) }

type DocsKeyMap struct{}

func (k DocsKeyMap) ShortHelp() []key.Binding { return overlayHelp(Keys.Docs) }

func (k DocsKeyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }

type AnalysisKeyMap struct{}

func (k AnalysisKeyMap) ShortHelp() []key.Binding { return overlayHelp(Keys.Analysis) }

func (k AnalysisKeyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }

func overlayHelp(close key.Binding) []key.Binding {
	keys := append(close.Keys(), "esc")
	return []key.Binding{
		key.NewBinding(key.WithKeys(keys...), key.WithHelp(strings.Join(keys, "/"), "close")),
		key.NewBinding(key.WithKeys("j", "down"), key.WithHelp("j/↓", "scroll down")),
		key.NewBinding(key.WithKeys("k", "up"), key.WithHelp("k/↑", "scroll up")),
		Keys.Quit,
	}
}

func chunkByWidth(bindings []key.Binding, width int) [][]key.Binding {
	cols := width / 26
	if cols < 2 {
		cols = 2
	} else if cols > 6 {
		cols = 6
	}
	perCol := (len(bindings) + cols - 1) / cols
	var out [][]key.Binding
	for i := 0; i < len(bindings); i += perCol {
		end := i + perCol
		if end > len(bindings) {
			end = len(bindings)
		}
		out = append(out, bindings[i:end])
	}
	return out
}

func BarHeight(showAll bool, width int) int {
	if !showAll {
		return 1
	}
	groups := chunkByWidth(fullList(), width)
	max := 0
	for _, g := range groups {
		if len(g) > max {
			max = len(g)
		}
	}
	return max
}
