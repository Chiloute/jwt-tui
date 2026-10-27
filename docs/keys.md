# Keys and secrets

How the Secret panel and `-s` resolve a key, and what each key can do.

## Input forms

One string, resolved in this order (`jwt.ResolveKey`):

| Input | Meaning |
| --- | --- |
| `hunter2` | Raw bytes, an HMAC secret. |
| `b64:aHVudGVyMg==` | Base64 of the key. Standard, URL-safe, padded or not. |
| `@~/keys/id_rsa.pem` | Read from a file. A leading `~/` expands to the home directory. |
| `-----BEGIN PUBLIC KEY-----…` | PEM pasted in the panel. |
| `{"keys":[…]}` | JWK Set pasted in the panel. |

The encoding is detected from the content: `-----BEGIN` gives PEM, a leading `{` gives JWKS, a leading byte `0x30` from a file or `b64:` gives DER, anything else is plain.

A key file is cached by path, size and modification time, so edits on disk are picked up on the next refresh.

## What a key can do

| Key | Verify | Re-sign |
| --- | --- | --- |
| Plain string / `b64:` | `HS*` | `HS*` |
| Public key (PEM, DER) | `RS*`, `PS*`, `ES*`, `EdDSA` | no |
| Private key (PEM, DER) | same, public half derived | same family as the key |
| JWK Set | Key chosen by the token's `kid` | `HS*` with an `oct` key only |

Re-signing with a JWK Set holding an RSA, EC or Ed25519 key is refused with `signing from a JWK set is not supported, give the private key as PEM or DER`.

A plain string against `RS*`, `PS*`, `ES*` or `EdDSA` gives `key unreadable`: `<alg> needs a PEM, DER or JWKS key, got a plain string`.

## Algorithm confusion

If the header says `HS256`, `HS384` or `HS512` and the key is PEM, DER, or a JWKS entry that is asymmetric, verification is not attempted. The state is `alg confusion`. Using the public key text as an HMAC secret is the classic RS256 to HS256 downgrade, and a `valid` result would be wrong.

## Trailing whitespace

If an HMAC check fails with a plain key that ends in space, tab or newline, jwt-tui retries with the whitespace stripped. A match reports `valid` and adds the `KEY_TRAILING_WS` finding.

## Self-signed tokens

After `R` (re-sign), the status bar reads `valid (self-signed)` in the warning color instead of plain `valid`. The token was produced here, not by the issuer.

Editing the header or payload rebuilds the Encoded panel and keeps the old signature, so the state becomes `invalid` and the edit state `modified`. Only the part you changed is re-encoded (compact JSON); an untouched part keeps its original base64. `R` then signs the compacted header and payload with the key in the Secret panel and sets the edit state to `re-signed`.
