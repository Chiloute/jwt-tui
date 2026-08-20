package config

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed default_config.yaml
var defaultConfig []byte

type Config struct {
	Keybindings Keybindings `yaml:"keybindings"`
}

var Global *Config

func Default() *Config {
	var c Config
	_ = yaml.Unmarshal(defaultConfig, &c)
	return &c
}

func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			Global = cfg
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	var user Config
	if err := yaml.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.Keybindings.merge(user.Keybindings)

	Global = cfg
	return cfg, nil
}

func WriteDefaultConfig(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, defaultConfig, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
