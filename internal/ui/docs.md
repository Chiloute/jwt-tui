# JWT Reference

## Structure

A JSON Web Token is three Base64URL-encoded parts joined by dots:

```
header.payload.signature
```

- **Header**: algorithm and token type
- **Payload**: claims (statements about an entity)
- **Signature**: HMAC or asymmetric over header + payload

The header and payload are readable by anyone. JWTs are _signed_, not _encrypted_.
Use JWE if you need confidentiality.

## Header

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Common header parameters:

| Param | Description                                |
| ----- | ------------------------------------------ |
| `alg` | Signing algorithm (`HS256`, `RS256`, etc.) |
| `typ` | Token type: always `JWT`                   |
| `kid` | Key ID: hint for which key to use          |
| `cty` | Content type: used for nested JWTs         |

## Payload (Claims)

**Registered claims** (all optional, but recommended):

| Claim | Type   | Description                             |
| ----- | ------ | --------------------------------------- |
| `iss` | string | Issuer: who created the token           |
| `sub` | string | Subject: principal the token is about   |
| `aud` | string | Audience: intended recipient(s)         |
| `exp` | number | Expiration time (Unix timestamp)        |
| `nbf` | number | Not before: token valid after this time |
| `iat` | number | Issued at (Unix timestamp)              |
| `jti` | string | JWT ID: unique identifier               |

**Private claims** are any additional fields agreed upon by the parties.

## Algorithms

| Algorithm | Type           | Key type                  |
| --------- | -------------- | ------------------------- |
| `HS256`   | HMAC + SHA-256 | Shared secret             |
| `HS384`   | HMAC + SHA-384 | Shared secret             |
| `HS512`   | HMAC + SHA-512 | Shared secret             |
| `RS256`   | RSA + SHA-256  | RSA key pair              |
| `RS384`   | RSA + SHA-384  | RSA key pair              |
| `RS512`   | RSA + SHA-512  | RSA key pair              |
| `PS256`   | RSA-PSS + SHA-256 | RSA key pair           |
| `PS384`   | RSA-PSS + SHA-384 | RSA key pair           |
| `PS512`   | RSA-PSS + SHA-512 | RSA key pair           |
| `ES256`   | ECDSA + P-256  | EC key pair               |
| `ES384`   | ECDSA + P-384  | EC key pair               |
| `ES512`   | ECDSA + P-521  | EC key pair               |
| `EdDSA`   | Ed25519        | Ed25519 key pair          |
| `none`    | No signature   | Never use in production   |

## Signature Computation

For HMAC algorithms:

```
signature = HMAC-SHA256(
  base64url(header) + "." + base64url(payload),
  secret
)
```

The final token:

```
base64url(header) + "." + base64url(payload) + "." + base64url(signature)
```

## Security

- **Never use `alg: none`**: disables signature verification entirely.
- Use **long, random secrets**: at least 256 bits (32 bytes) for HS256.
- Always validate **`exp`** (expiration) and **`nbf`** (not before).
- Validate **`iss`** and **`aud`** to prevent token reuse across services.
- The payload is **base64-encoded, not encrypted**: never store passwords or PII.
- Prefer **asymmetric algorithms** (RS256, ES256, EdDSA) for public-facing APIs.
- Store secrets in environment variables or a secrets manager, never in code.

### Algorithm confusion

A verifier that picks its algorithm from the token's own `alg` header can be
tricked: take an `RS256` service, forge a token that says `HS256`, and compute
the HMAC using the **public** key as the shared secret. The server reads
`alg: HS256`, reaches for its RSA public key, and validates a token you signed.

jwt-tui refuses this pairing outright — a PEM key against an `HS*` header is
reported as `alg confusion`, never as `valid`. Press `a` for the details.

## Analysis (`a`)

Beyond the signature, jwt-tui reports what a verifier might trip over:

- **Encoding** — padded or non-url-safe base64 (RFC 7515 §2), duplicate JSON
  keys (Go keeps the last, other parsers keep the first), signature lengths that
  can't match the declared algorithm.
- **Key strength** — HMAC secrets shorter than the hash output, which RFC 7518
  §3.2 forbids, and keys that only work once trailing whitespace is stripped.
- **Claims** — missing `exp`, `exp` before `iat`, `nbf` after `exp`, `iat` in
  the future, lifetimes over a year, timestamps sent as strings, missing `jti`.

## Keybindings

In view mode. Press `e`/`enter` to edit a panel, then `esc` to leave editing.

| Key          | Action (config name)          |
| ------------ | ----------------------------- |
| `tab`        | Cycle focus (`cycle_focus`)   |
| `shift+tab`  | Cycle focus backwards         |
| `e` / `enter`| Edit focused panel (`edit`)   |
| `E`          | Edit focused panel in `$EDITOR` (`external_edit`) |
| `a`          | Toggle security analysis (`analysis`) |
| `d`          | Toggle this reference (`docs`)|
| `?`          | Toggle help bar (`help_toggle`) |
| `ctrl+c` / `q` | Quit (`quit`)               |
| `x`          | Clear focused panel (`clear`) |
| `R` / `ctrl+r` | Re-sign token (`resign`)    |
| `r`          | Refresh / re-parse (`refresh`)|
| `y`          | Copy to clipboard (`copy`)    |
| `p` / `ctrl+v` | Paste from clipboard (`paste`) |

### External editor (`E`)

`E` opens the focused panel in a real editor instead of the built-in textarea —
useful for a large payload, or for anything you'd rather edit with folds, search
and undo.

The editor is `$VISUAL`, then `$EDITOR`, falling back to `vim`. The value may
carry arguments (`EDITOR="nvim -u NONE"`). jwt-tui waits for it to exit, then
reads the file back and feeds it through the same reactive path as a normal
edit: a payload comes back as a rebuilt token, a secret comes back as a new
verification.

The panel is written to a temporary file named for its content — `.json` for the
header and payload, so the editor picks up JSON syntax — created with `0600`
permissions and deleted as soon as the editor exits. The **Secret** panel is no
exception: its contents do briefly touch disk.

The final newline your editor adds is stripped. Without that, a secret edited
this way would end in `\n` and silently stop verifying.

## Keys and secrets

The `Secret` panel and `-s`/`--secret` take one string, resolved by prefix:

| Input                        | Meaning                              |
| ---------------------------- | ------------------------------------ |
| `hunter2`                    | raw bytes, an HMAC secret            |
| `b64:aHVudGVyMg==`           | base64 of the key (any alphabet)     |
| `@~/keys/id_rsa.pem`         | read the key from a file (`~` and paths expand) |
| `@./jwks.json`               | a JWK Set, the key picked by the token's `kid` |
| `-----BEGIN PUBLIC KEY-----` | PEM pasted directly                  |
| `{"keys":[...]}`             | JWK Set pasted directly              |

PEM, DER and JWK Sets are accepted; a private key is used for both verifying and
re-signing, a public key for verifying only. A key file is re-read when it
changes on disk.

A PEM, DER or JWK-set key against an `HS*` header is refused as algorithm
confusion, never reported as valid.

## Command-line

```
jwt-tui [flags] [token]
```

| Flag                   | Description                                   |
| ---------------------- | --------------------------------------------- |
| `-t`, `--token`        | Pre-fill the encoded JWT (also a bare arg)    |
| `-s`, `--secret`       | Key: plain, `b64:...`, `@file` or PEM/JWKS    |
| `-p`, `--print`        | Decode and verify on stdout, no TUI           |
| `-j`, `--json`         | Machine-readable output (implies `--print`)   |
| `--exit-zero`          | Always exit 0, even on an invalid signature   |
| `-c`, `--config`       | Path to a config file                         |
| `--add-default-config` | Write the default config file and exit        |

Print mode exits `0` for a valid signature, `1` for an invalid one, `2` when the
token can't be decoded — usable as a CI check.

```
jwt-tui -s "your-256-bit-secret" eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
jwt-tui -p -j -s @./jwks.json "$TOKEN" | jq '.findings[] | select(.severity=="danger")'
```

## Configuration

jwt-tui looks for a config file at `~/.config/jwt-tui/config.yaml`
(or `$XDG_CONFIG_HOME/jwt-tui/config.yaml`). If it does not exist, the
built-in defaults are used automatically.

To get a starting point you can edit, run:

```
jwt-tui --add-default-config
```

This writes the default config (or to the path given with `--config`). Only the
keys you set override the defaults; anything omitted keeps its default value.

Currently the config holds the **keybindings**. Each action maps to a
comma-separated list of key names (e.g. `"ctrl+c,q"`); an uppercase letter means
the shifted key (e.g. `"R"`).

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

Colors are themed separately via ilovetui at
`~/.config/ilovetui/config.yaml` (Base16 palette).
