# Configuration

Config file, keybindings and external editor.

## Config file

Path: `$XDG_CONFIG_HOME/jwt-tui/config.yaml`, else `~/.config/jwt-tui/config.yaml`. `--config` overrides it. A missing file means defaults. A file that cannot be read or parsed stops the TUI with `config: <error>` and exit code `1`.

```sh
jwt-tui --add-default-config
```

writes the defaults (mode `0600`, parent directory created) and overwrites an existing file. Keys you omit keep their default.

The only section is `keybindings`. Each value is a comma-separated list of Bubble Tea key names; an uppercase letter is the shifted key.

| Option | Default | Action |
| --- | --- | --- |
| `quit` | `ctrl+c,q` | Quit. |
| `cycle_focus` | `tab` | Next panel. `shift+tab` goes back and is not configurable. |
| `edit` | `e,enter` | Edit the focused panel. `esc` leaves editing. |
| `external_edit` | `E` | Edit the focused panel in an external editor. |
| `docs` | `d` | Toggle the built-in JWT reference. |
| `analysis` | `a` | Toggle the security analysis. |
| `help_toggle` | `?` | Toggle the key bar. |
| `clear` | `x` | Clear the focused panel. |
| `copy` | `y` | Copy the focused panel. |
| `paste` | `p,ctrl+v` | Paste into the focused panel. |
| `resign` | `R,ctrl+r` | Re-sign with the key in the Secret panel. |
| `refresh` | `r` | Re-parse the Encoded panel. |

```yaml
keybindings:
  quit: "ctrl+c,q"
  resign: "R,ctrl+r"
```

Colors are not set here. They come from [ilovetui](https://github.com/anotherhadi/ilovetui), configured in `~/.config/ilovetui/config.yaml`.

## Clipboard

Copy and paste use the terminal clipboard (OSC 52), so they work over SSH if the terminal supports it.

## External editor

`E` opens the focused panel in `$VISUAL`, else `$EDITOR`, else `vim`. Arguments are kept: `EDITOR="nvim -u NONE"`.

1. The panel text is written to a temporary file from `os.CreateTemp` (mode `0600`) with the extension `.jwt` (Encoded), `.json` (Header, Payload) or `.key` (Secret).
2. jwt-tui waits for the editor to exit and deletes the file.
3. If the content changed, it goes through the same path as a keystroke: a changed payload rebuilds the token, a changed secret reruns verification.

The Secret panel is written to disk like the others, briefly. The final newline added by the editor is removed, otherwise an HMAC secret would end in `\n` and stop verifying.
