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

// Short is the always-visible help bar. Extra is appended when help is expanded.
func Short() []key.Binding {
	return []key.Binding{Keys.CycleFocus, Keys.Edit, Keys.ExternalEdit, Keys.Analysis, Keys.Docs, Keys.Quit}
}

func Extra() []key.Binding {
	return []key.Binding{Keys.Clear, Keys.Resign, Keys.Refresh, Keys.Copy, Keys.Paste}
}

// Overlay is the help bar of a full-screen overlay closed by close or esc.
func Overlay(close key.Binding) []key.Binding {
	keys := append(close.Keys(), "esc")
	return []key.Binding{
		key.NewBinding(key.WithKeys(keys...), key.WithHelp(strings.Join(keys, "/"), "close")),
		key.NewBinding(key.WithKeys("j", "down"), key.WithHelp("j/↓", "scroll down")),
		key.NewBinding(key.WithKeys("k", "up"), key.WithHelp("k/↑", "scroll up")),
		Keys.Quit,
	}
}
