package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultKeybindings(t *testing.T) {
	c := Default()
	if c.Keybindings.Quit != "ctrl+c,q" {
		t.Fatalf("default quit = %q, want ctrl+c,q", c.Keybindings.Quit)
	}
	if c.Keybindings.Docs != "d" {
		t.Fatalf("default docs = %q, want d", c.Keybindings.Docs)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if c.Keybindings.Quit != "ctrl+c,q" {
		t.Fatalf("quit = %q, want default", c.Keybindings.Quit)
	}
}

func TestLoadOverridesOnlyProvidedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("keybindings:\n  quit: \"Q\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Keybindings.Quit != "Q" {
		t.Fatalf("quit = %q, want Q (overridden)", c.Keybindings.Quit)
	}
	if c.Keybindings.Docs != "d" {
		t.Fatalf("docs = %q, want d (default kept)", c.Keybindings.Docs)
	}
}
