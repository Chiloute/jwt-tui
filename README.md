# jwt-tui

A terminal UI to **decode, tamper with, and re-sign** JSON Web Tokens (JWTs).

Built with [Bubble Tea](https://charm.land/bubbletea) and [Lipgloss](https://charm.land/lipgloss),
themed with [ilovetui](https://github.com/anotherhadi/ilovetui).

## Features

- **Decode**: paste a JWT and instantly see the pretty-printed header and payload.
- **Tamper**: edit the header or payload JSON; the encoded token is rebuilt on the fly.
- **Your editor**: `E` opens the focused panel in `$EDITOR` (vim by default); on exit the
  result flows back through the same reactive path as a keystroke.
- **Re-sign**: produce a fresh, valid signature after edits (`R`), signing the exact
  header and payload bytes so an untouched token round-trips unchanged.
- **Flexible keys**: plain text, `b64:...`, `@file`, PEM, DER, or a JWK Set with the key
  chosen by the token's `kid`.
- **Real-time state**: signature validity, expiry (`exp`/`nbf`), and edit state are
  recomputed on every keystroke, shown as a 3-axis status bar. A token you signed
  yourself reads `valid (self-signed)`, never a plain green `valid`.
- **Security analysis** (`a`): algorithm confusion, `alg: none`, weak HMAC keys,
  duplicate JSON keys, bad signature lengths, and claims that don't add up.
- **Scriptable**: `--print` / `--json` decode and verify without the TUI, with CI-friendly
  exit codes.
- **4-panel layout**: Encoded, Header, Secret, and Payload all visible and editable at once.
- **Themeable**: colors follow [ilovetui](https://github.com/anotherhadi/ilovetui), so a theme
  change applies across all compatible TUIs at once.
- **Rebindable keys**: customize every keybinding in the config file.
- **Built-in reference**: press `d` for a JWT cheat-sheet (claims, algorithms, security, config).
- **Broad algorithm support**:
  - HMAC: `HS256`, `HS384`, `HS512` (shared secret)
  - RSA: `RS256/384/512`, `PS256/384/512` (PEM/DER/JWK)
  - ECDSA: `ES256`, `ES384`, `ES512` (PEM/DER/JWK)
  - EdDSA: `Ed25519` (PEM/DER/JWK)
  - `none`

> **Verification** accepts an HMAC secret or a **public** key (a private key works too — its
> public half is derived). **Re-signing** requires the HMAC secret or a **private** key.
> Keys are given as plain text, `b64:...`, `@file`, or pasted PEM / JWK Set.
>
> An asymmetric key against an `HS*` header is refused rather than verified: that pairing is
> the RS256→HS256 confusion attack, and reporting it as `valid` would be the wrong answer.

## Installation

<details>
<summary>Go install</summary>

Requires Go 1.26+:

```sh
go install github.com/chiloute/jwt-tui/cmd/jwt-tui@latest
```

</details>

<details>
<summary>Nix (temporary run, no install)</summary>

```sh
nix run github:chiloute/jwt-tui
```

</details>

<details>
<summary>NixOS / home-manager (flake)</summary>

Add jwt-tui to your flake inputs:

```nix
inputs.jwt-tui.url = "github:chiloute/jwt-tui";
```

Then add the package to your system or home-manager packages:

```nix
# NixOS
environment.systemPackages = [ inputs.jwt-tui.packages.${pkgs.system}.default ];
# home-manager
home.packages = [ inputs.jwt-tui.packages.${pkgs.system}.default ];
```

</details>

## Usage

```sh
jwt-tui                                   # launch on an empty interface
jwt-tui -t <token>                        # pre-fill the JWT token
jwt-tui -t <token> -s mysecret            # pre-fill token and secret
jwt-tui -t <token> -s @~/keys/pub.pem     # key from a file
jwt-tui <token>                           # a bare argument is treated as the token
jwt-tui -p -s mysecret <token>            # decode and verify on stdout, no TUI
jwt-tui -p -j -s @jwks.json <token>       # machine-readable output
```

Fill the **Secret** panel to verify or re-sign. A key is given as plain text, `b64:...`,
`@file`, or a pasted PEM / JWK Set; see the built-in reference (`d`) for the full list.
Copy/paste use the terminal clipboard (OSC 52), so it works over SSH in a supporting terminal.

Print mode exits `0` for a valid signature, `1` for an invalid one, `2` when the token can't
be decoded.

Press `?` for the help bar, `a` for the security analysis, and `d` for the JWT reference.

```
Usage: jwt-tui [flags] [token]

  -t, --token string     pre-fill the encoded JWT token
  -s, --secret string    key: plain, b64:..., @file or PEM/JWKS
  -p, --print            decode and verify on stdout, no TUI
  -j, --json             machine-readable output, implies --print
      --exit-zero        always exit 0, even on an invalid signature
  -c, --config string    path to config file
      --add-default-config   write the default config file and exit
```

### Keybindings

Default view-mode keys (all rebindable — see Configuration). Press `e`/`enter` to edit a panel,
`esc` to leave editing.

| Key            | Action                |
| -------------- | --------------------- |
| `tab`          | Cycle focus           |
| `e` / `enter`  | Edit focused panel    |
| `E`            | Edit focused panel in `$EDITOR` |
| `a`            | Toggle security analysis |
| `d`            | Toggle JWT reference  |
| `?`            | Toggle help bar       |
| `x`            | Clear focused panel   |
| `R` / `ctrl+r` | Re-sign token         |
| `r`            | Refresh / re-parse    |
| `y`            | Copy to clipboard     |
| `p` / `ctrl+v` | Paste from clipboard  |
| `ctrl+c` / `q` | Quit                  |

`E` hands the focused panel to `$VISUAL`, then `$EDITOR`, falling back to `vim` (arguments
are honored, e.g. `EDITOR="nvim -u NONE"`). The panel goes to a `0600` temporary file —
`.json` for the header and payload, so your editor colors it — deleted as soon as the editor
exits; the **Secret** panel included, so its contents do briefly touch disk. The final newline
your editor adds is stripped, otherwise a secret edited this way would silently stop verifying.

## Configuration

The config file lives at `~/.config/jwt-tui/config.yaml` (or `$XDG_CONFIG_HOME`). If it does not
exist, the built-in defaults are used. Generate a starting point with:

```sh
jwt-tui --add-default-config
```

Only the keys you set override the defaults. Each action maps to a comma-separated list of key
names; an uppercase letter means the shifted key.

```yaml
keybindings:
  quit: "ctrl+c,q"
  cycle_focus: "tab"
  edit: "e,enter"
  external_edit: "E"
  docs: "d"
  analysis: "a"
  help_toggle: "?"
  clear: "x"
  copy: "y"
  paste: "p,ctrl+v"
  resign: "R,ctrl+r"
  refresh: "r"
```

Colors are themed separately via [ilovetui](https://github.com/anotherhadi/ilovetui) at
`~/.config/ilovetui/config.yaml`.

## Development

```sh
go run ./cmd/jwt-tui   # launch the TUI
go build ./...         # build
go test ./...
go vet ./...

nix develop            # dev shell (go, gopls, gotools, staticcheck)
nix build              # -> result/bin/jwt-tui
```

Project layout:

```
cmd/jwt-tui/        # entrypoint (flags, config load)
internal/jwt/       # JWT/crypto logic, decoupled from the TUI
internal/ui/        # Bubble Tea layer (model, update, view)
internal/config/    # YAML config (keybindings)
internal/keys/      # keybindings -> bindings + help
internal/highlight/ # JSON/JWT syntax coloring
internal/style/     # panel borders + title rendering
```

## License

[MIT](./LICENSE)
