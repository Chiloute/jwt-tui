package ui

import (
	"os"
	"strings"
	"testing"

	"github.com/chiloute/jwt-tui/internal/jwt"
)

func TestEditorArgv(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	if got := editorArgv(); len(got) != 1 || got[0] != "vim" {
		t.Fatalf("editorArgv without env = %v, want [vim]", got)
	}

	t.Setenv("EDITOR", "nvim -u NONE")
	if got := editorArgv(); len(got) != 3 || got[0] != "nvim" {
		t.Fatalf("editorArgv from EDITOR = %v, want [nvim -u NONE]", got)
	}

	t.Setenv("VISUAL", "code -w")
	if got := editorArgv(); got[0] != "code" {
		t.Fatalf("editorArgv = %v, want VISUAL to win over EDITOR", got)
	}
}

func TestExternalEditorRoundTrip(t *testing.T) {
	m := initialModel(sampleJWT, "")
	m.focus = panelPayload

	path, err := m.writeEditorFile(panelPayload)
	if err != nil {
		t.Fatalf("writeEditorFile: %v", err)
	}
	if !strings.HasSuffix(path, ".json") {
		t.Fatalf("payload temp file = %q, want a .json suffix", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp file: %v", err)
	}
	if got := string(data); !strings.HasSuffix(got, "\n") ||
		strings.TrimSuffix(got, "\n") != m.text(panelPayload) {
		t.Fatalf("temp file = %q, want the panel text plus a final newline", got)
	}

	if err := os.WriteFile(path, []byte("{\n  \"sub\": \"admin\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.applyEditorResult(editorFinishedMsg{panel: panelPayload, path: path})

	if !strings.Contains(m.text(panelPayload), "admin") {
		t.Fatalf("payload after edit = %q, want the edited content", m.text(panelPayload))
	}
	if m.edit != jwt.EditModified {
		t.Fatalf("edit state = %v, want EditModified", m.edit)
	}
	if info, err := jwt.ParseJWT(m.text(panelEncoded)); err != nil {
		t.Fatalf("encoded not rebuilt: %v", err)
	} else if info.Payload["sub"] != "admin" {
		t.Fatalf("encoded payload = %v, want sub=admin", info.Payload)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temp file %s not removed", path)
	}
}

func TestExternalEditorStripsFinalNewline(t *testing.T) {
	m := initialModel(sampleJWT, "")
	m.focus = panelSecret

	path, err := m.writeEditorFile(panelSecret)
	if err != nil {
		t.Fatalf("writeEditorFile: %v", err)
	}
	if err := os.WriteFile(path, []byte("your-256-bit-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.applyEditorResult(editorFinishedMsg{panel: panelSecret, path: path})

	if got := m.text(panelSecret); got != "your-256-bit-secret" {
		t.Fatalf("secret = %q, want the editor's final newline stripped", got)
	}
	if m.sig != jwt.SigValid {
		t.Fatalf("sig = %v (%s), want SigValid", m.sig, m.sigError)
	}
}

func TestExternalEditorNoChangeLeavesPanelUntouched(t *testing.T) {
	for _, secret := range []string{"your-256-bit-secret", "trailing-newline-secret\n"} {
		m := initialModel(sampleJWT, secret)
		m.focus = panelSecret

		path, err := m.writeEditorFile(panelSecret)
		if err != nil {
			t.Fatalf("writeEditorFile: %v", err)
		}
		m.applyEditorResult(editorFinishedMsg{panel: panelSecret, path: path})

		if got := m.text(panelSecret); got != secret {
			t.Fatalf("secret after a no-op edit = %q, want %q", got, secret)
		}
	}
}

func TestExternalEditorFailureKeepsPanel(t *testing.T) {
	m := initialModel(sampleJWT, "your-256-bit-secret")
	m.focus = panelEncoded

	path, err := m.writeEditorFile(panelEncoded)
	if err != nil {
		t.Fatalf("writeEditorFile: %v", err)
	}
	m.applyEditorResult(editorFinishedMsg{panel: panelEncoded, path: path, err: os.ErrNotExist})

	if m.text(panelEncoded) != sampleJWT {
		t.Fatalf("token = %q, want it untouched after an editor failure", m.text(panelEncoded))
	}
	if !strings.HasPrefix(m.errorMsg, "editor:") {
		t.Fatalf("errorMsg = %q, want an editor: prefix", m.errorMsg)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temp file %s not removed", path)
	}
}
