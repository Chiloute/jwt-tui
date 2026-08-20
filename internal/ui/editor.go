package ui

import (
	"os"
	"os/exec"
	"strings"

	tea "charm.land/bubbletea/v2"
)

type editorFinishedMsg struct {
	panel int
	path  string
	err   error
}

var panelFileExt = [4]string{".jwt", ".json", ".json", ".key"}

func editorArgv() []string {
	for _, name := range []string{"VISUAL", "EDITOR"} {
		if fields := strings.Fields(os.Getenv(name)); len(fields) > 0 {
			return fields
		}
	}
	return []string{"vim"}
}

func editorFileContent(panelText string) string {
	if panelText == "" || strings.HasSuffix(panelText, "\n") {
		return panelText
	}
	return panelText + "\n"
}

func (m *model) openInEditor() tea.Cmd {
	panel := m.focus

	path, err := m.writeEditorFile(panel)
	if err != nil {
		m.errorMsg = "editor: " + err.Error()
		m.recalcSizes()
		return autoClearStatus()
	}

	argv := append(editorArgv(), path)
	cmd := exec.Command(argv[0], argv[1:]...)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return editorFinishedMsg{panel: panel, path: path, err: err}
	})
}

func (m *model) writeEditorFile(panel int) (string, error) {
	f, err := os.CreateTemp("", "jwt-tui-*"+panelFileExt[panel])
	if err != nil {
		return "", err
	}
	path := f.Name()

	if _, err := f.WriteString(editorFileContent(m.text(panel))); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func (m *model) applyEditorResult(msg editorFinishedMsg) {
	defer os.Remove(msg.path)

	if msg.err != nil {
		m.errorMsg = "editor: " + msg.err.Error()
		return
	}

	data, err := os.ReadFile(msg.path)
	if err != nil {
		m.errorMsg = "editor: " + err.Error()
		return
	}

	if string(data) == editorFileContent(m.text(msg.panel)) {
		return
	}

	m.focus = msg.panel
	m.setText(msg.panel, trimFinalNewline(string(data)))
	m.onContentChange()
}

func trimFinalNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}
