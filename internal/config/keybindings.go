package config

type Keybindings struct {
	Quit         string `yaml:"quit"`
	CycleFocus   string `yaml:"cycle_focus"`
	Edit         string `yaml:"edit"`
	ExternalEdit string `yaml:"external_edit"`
	Docs         string `yaml:"docs"`
	Analysis     string `yaml:"analysis"`
	HelpToggle   string `yaml:"help_toggle"`
	Clear        string `yaml:"clear"`
	Copy         string `yaml:"copy"`
	Paste        string `yaml:"paste"`
	Resign       string `yaml:"resign"`
	Refresh      string `yaml:"refresh"`
}

func (k *Keybindings) merge(user Keybindings) {
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&k.Quit, user.Quit)
	set(&k.CycleFocus, user.CycleFocus)
	set(&k.Edit, user.Edit)
	set(&k.ExternalEdit, user.ExternalEdit)
	set(&k.Docs, user.Docs)
	set(&k.Analysis, user.Analysis)
	set(&k.HelpToggle, user.HelpToggle)
	set(&k.Clear, user.Clear)
	set(&k.Copy, user.Copy)
	set(&k.Paste, user.Paste)
	set(&k.Resign, user.Resign)
	set(&k.Refresh, user.Refresh)
}
