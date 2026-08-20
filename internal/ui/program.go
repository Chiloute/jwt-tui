package ui

import (
	tea "charm.land/bubbletea/v2"
)

func Run(token, secret string) error {
	p := tea.NewProgram(initialModel(token, secret))
	_, err := p.Run()
	return err
}
