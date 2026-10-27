# Command line

Flags, exit codes and output formats of `jwt-tui`.

```
jwt-tui [flags] [token]
```

## Flags

| Flag | Short | Default | Effect |
| --- | --- | --- | --- |
| `--token` | `-t` | empty | Pre-fills the Encoded panel. A bare argument does the same when `-t` is absent. |
| `--secret` | `-s` | empty | Key, see [keys.md](keys.md). |
| `--print` | `-p` | off | Decodes and verifies on stdout, no TUI. |
| `--json` | `-j` | off | JSON output. Implies `--print`. |
| `--exit-zero` | | off | Exit code `0` even when the signature is not valid. Print mode only. |
| `--config` | `-c` | `$XDG_CONFIG_HOME/jwt-tui/config.yaml`, else `~/.config/jwt-tui/config.yaml` | Config file path. |
| `--add-default-config` | | off | Writes the default config to the config path and exits. Overwrites an existing file. |
| `--version` | | off | Prints `jwt-tui <version>` (`dev` for a plain `go build`). |

Print mode without a token writes `a token is required in print mode` to stderr and exits `2`.

## Exit codes (print mode)

| Code | Meaning |
| --- | --- |
| `0` | Signature valid. |
| `1` | Any other signature state: `invalid`, `no key`, `alg none`, `alg confusion`, `key unreadable`, and so on. |
| `2` | Token cannot be decoded, or the output could not be written. |

`--exit-zero` forces `0` after a successful decode. A token that cannot be decoded still exits `2`.

## Text output

```sh
jwt-tui -p -s mysecret <token>
```

Prints `Header` and `Payload` as indented JSON, then `Signature: <state>` (with the error in parentheses when there is one), `Temporal:  <state>` when `exp` or `nbf` is present, then an `Analysis` section listing `[severity] title (CODE)` per finding. Codes are listed in [analysis.md](analysis.md).

## JSON output

```sh
jwt-tui -p -j -s @jwks.json "$TOKEN"
```

| Field | Content |
| --- | --- |
| `header`, `payload` | Decoded objects. |
| `signature.state` | `valid`, `invalid`, `no key`, `alg none`, `alg confusion`, `key unreadable`, `malformed`, `no alg`, `empty`. |
| `signature.alg`, `signature.error` | Algorithm from the header, error text. |
| `temporal.state` | `valid`, `expired`, `not yet valid`, or `none`. |
| `temporal.exp`, `.nbf`, `.iat` | Timestamps, `null` when absent. |
| `key.encoding` | `plain`, `PEM`, `DER`, `JWKS`, or `none`. |
| `key.origin` | File path when the key came from `@file`. |
| `key.private`, `key.bytes` | Whether the key can sign, key size in bytes. |
| `findings[]` | `severity` (`info`, `warn`, `danger`), `code`, `title`, `detail`. |

Example: fail a CI job on any `danger` finding.

```sh
jwt-tui -p -j --exit-zero -s @jwks.json "$TOKEN" \
  | jq -e '[.findings[] | select(.severity=="danger")] | length == 0'
```

## Errors outside print mode

An unreadable or invalid config file prints `config: <error>` to stderr and exits `1`. A missing file is not an error; defaults apply.
