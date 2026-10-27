# Development

Build, test and release of `jwt-tui`.

## Commands

```sh
go run ./cmd/jwt-tui   # run the TUI
go build ./...
go test ./...
go vet ./...
```

## Nix

```sh
nix develop   # go, gopls, gotools, staticcheck, gomod2nix, git hooks
nix build     # result/bin/jwt-tui
```

The dev shell installs pre-commit hooks: `gofmt`, `govet`, `staticcheck`, and `gomod2nix --outdir ./nix` when `go.mod` or `go.sum` change. `nix/gomod2nix.toml` is generated; do not edit it by hand.

On `dependabot/**` branches, `.github/workflows/dependabot-nix.yml` regenerates `nix/gomod2nix.toml` and pushes it.

## Tests

Tests sit next to the code (`internal/*/*_test.go`). The UI tests cover layout (`grid_layout_test.go`, `docs_layout_test.go`), the external editor and the reactive flow between panels.

## Release

Pushing a tag `v*` runs `.github/workflows/release.yml`, which runs GoReleaser with `.github/.goreleaser.yaml`:

- Linux `amd64` and `arm64`, `CGO_ENABLED=0`, archives `jwt-tui_linux_<arch>.tar.gz`, `checksums.txt`.
- Version injected with `-X main.version={{.Version}}`.
- Releases are marked prerelease while the project is v0.x.
- Commits starting with `docs:`, `test:` or `ci:` are left out of the changelog.

## Notes on the code

- `internal/ui/docs.md` is the reference shown by `d`, embedded with `go:embed`. Keep it in line with these pages when keys, flags or finding codes change.
