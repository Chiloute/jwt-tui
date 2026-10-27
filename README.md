# jwt-tui

Terminal UI in Go to decode, edit and re-sign JSON Web Tokens, with a non-interactive mode (`--print`, `--json`) for scripts and CI. Aimed at people testing JWT handling.

Four panels (Encoded, Header, Payload, Secret) stay in sync: editing any of them rebuilds the others and recomputes signature validity, expiry and edit state.

## Prerequisites

- Go 1.26 to build from source (`go.mod` pins `go 1.26.4`)
- Or Nix with flakes
- Release binaries: Linux amd64 and arm64 only (`.github/.goreleaser.yaml`)

## Installation

```sh
go install github.com/chiloute/jwt-tui/cmd/jwt-tui@latest
```

Without installing, with Nix:

```sh
nix run github:chiloute/jwt-tui
```

As a flake input (NixOS or home-manager):

```nix
inputs.jwt-tui.url = "github:chiloute/jwt-tui";
# then
environment.systemPackages = [ inputs.jwt-tui.packages.${pkgs.system}.default ];
```

## Usage

```sh
jwt-tui                                # empty interface
jwt-tui <token>                        # a bare argument is the token
jwt-tui -t <token> -s mysecret         # pre-fill token and secret
jwt-tui -t <token> -s @~/keys/pub.pem  # key read from a file
```

Print mode, no TUI, exit code `0` when the signature is valid:

```sh
jwt-tui -p -s mysecret <token>
jwt-tui -p -j -s @jwks.json <token> | jq '.findings[] | select(.severity=="danger")'
```

An inline `-s` value is visible in `ps` and in shell history. For a real key, use `-s @file` or paste it into the Secret panel.

In the TUI, `?` shows the key bar, `a` the security analysis, `d` a built-in JWT reference.

## Supported algorithms

`HS256/384/512`, `RS256/384/512`, `PS256/384/512`, `ES256/384/512`, `EdDSA` (Ed25519) and `none`.

## Documentation

- [docs/cli.md](docs/cli.md): flags, exit codes, JSON output
- [docs/keys.md](docs/keys.md): key formats, verification and re-signing rules
- [docs/analysis.md](docs/analysis.md): finding codes of the security analysis
- [docs/configuration.md](docs/configuration.md): config file, keybindings, external editor
- [docs/architecture.md](docs/architecture.md): packages and data flow
- [docs/development.md](docs/development.md): build, tests, Nix, release
- [CONTRIBUTING.md](CONTRIBUTING.md): how to send a pull request

## Limits

- Re-signing from a JWK Set is refused for RSA, EC and Ed25519; give a PEM or DER private key. A JWK Set can still verify, and can hold an `oct` key for HMAC.
- A PEM, DER or JWK Set asymmetric key against an `HS*` header is refused (`alg confusion`), never reported as valid.
- Release binaries are marked prerelease (v0.x).

## License

[MIT](LICENSE)
