package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/pflag"

	"github.com/chiloute/jwt-tui/internal/config"
	"github.com/chiloute/jwt-tui/internal/keys"
	"github.com/chiloute/jwt-tui/internal/report"
	"github.com/chiloute/jwt-tui/internal/ui"
)

// injectee au build via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	var (
		flagConfig           = pflag.StringP("config", "c", "", "path to config file")
		flagAddDefaultConfig = pflag.Bool("add-default-config", false, "write the default config file to the config path and exit")
		flagToken            = pflag.StringP("token", "t", "", "pre-fill the encoded JWT token")
		flagSecret           = pflag.StringP("secret", "s", "", "key: plain, b64:..., @file or PEM/JWKS")
		flagPrint            = pflag.BoolP("print", "p", false, "decode and verify on stdout, no TUI")
		flagJSON             = pflag.BoolP("json", "j", false, "machine-readable output, implies --print")
		flagExitZero         = pflag.Bool("exit-zero", false, "always exit 0, even on an invalid signature")
		flagVersion          = pflag.Bool("version", false, "print the version and exit")
	)
	pflag.CommandLine.SetOutput(os.Stdout)
	pflag.Usage = func() {
		fmt.Println("Usage: jwt-tui [flags] [token]")
		fmt.Println()
		pflag.PrintDefaults()
	}
	pflag.Parse()

	if *flagVersion {
		fmt.Printf("jwt-tui %s\n", version)
		return
	}

	if *flagToken == "" && pflag.NArg() > 0 {
		t := pflag.Arg(0)
		flagToken = &t
	}

	cfgPath := defaultConfigPath()
	if *flagConfig != "" {
		cfgPath = *flagConfig
	}

	if *flagAddDefaultConfig {
		if err := config.WriteDefaultConfig(cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "write-config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("default config written to %s\n", cfgPath)
		return
	}

	if *flagPrint || *flagJSON {
		if *flagToken == "" {
			fmt.Fprintln(os.Stderr, "a token is required in print mode")
			os.Exit(2)
		}
		r := report.Analyze(*flagToken, *flagSecret)
		var err error
		if *flagJSON {
			err = report.JSON(os.Stdout, r)
		} else {
			err = report.Text(os.Stdout, r)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
		if *flagExitZero {
			os.Exit(0)
		}
		os.Exit(report.ExitCode(r))
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	keys.Init(cfg)

	if err := ui.Run(*flagToken, *flagSecret); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func defaultConfigPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "jwt-tui", "config.yaml")
}
