# Security analysis

Finding codes reported by `a` in the TUI and in the `findings` of print mode (`jwt.Analyze`).

Findings are sorted by severity, `danger` first. Severities: `danger`, `warn`, `info`. Titles and details are stripped of control characters before display, since header values can contain anything.

## Algorithm

| Code | Severity | Raised when |
| --- | --- | --- |
| `ALG_NONE` | danger | `alg` is `none` (any case). |
| `ALG_MISSING` | danger | The header has no `alg`. |
| `ALG_CONFUSION` | danger | `HS*` header with a PEM, DER or asymmetric JWK key. Verification is refused. |

## Encoding

| Code | Severity | Raised when |
| --- | --- | --- |
| `B64_STRICT` | warn | A part contains `=`, `+` or `/`. RFC 7515 wants unpadded base64url. One finding per part. |
| `DUP_KEYS` | danger | A JSON object in the header or payload repeats a key. Go keeps the last value, other parsers keep the first. |

## Key

| Code | Severity | Raised when |
| --- | --- | --- |
| `KEY_TRAILING_WS` | warn | The HMAC key only verifies once trailing whitespace is removed. |
| `KEY_PUBLIC_ONLY` | info | The signature is valid for an asymmetric algorithm but the key cannot sign. |
| `JWKS_KID_MISSING` | warn | A JWK Set is used and the token has no `kid`. |
| `SIG_LEN` | danger | Signature length does not match the algorithm, or is under 128 bytes for `RS*`/`PS*`. |
| `HMAC_KEY_LEN` | warn, danger under 8 bytes | HMAC key shorter than the hash output (RFC 7518 §3.2). |

Expected signature sizes in bytes: `HS256` 32, `HS384` 48, `HS512` 64, `ES256` 64, `ES384` 96, `ES512` 132, `EdDSA` 64.

## Claims

Only evaluated when the payload decodes as a JSON object.

| Code | Severity | Raised when |
| --- | --- | --- |
| `TIME_CLAIM_STRING` | warn | `exp`, `nbf` or `iat` is a numeric string instead of a number. |
| `EXP_MISSING` | warn | No `exp`. |
| `EXP_BEFORE_IAT` | danger | `exp` is earlier than `iat`. |
| `LIFETIME_LONG` | warn | `exp - iat` is over 365 days. |
| `NBF_AFTER_EXP` | danger | `nbf` is later than `exp`. |
| `IAT_FUTURE` | warn | `iat` is more than one minute ahead of the local clock. |
| `JTI_MISSING` | info | No `jti`. |

## Temporal state

Separate from the findings. `expired` if `exp` is past, `not yet valid` if `nbf` is ahead, `valid` if either claim exists and neither fails, empty otherwise. The TUI recomputes it every second, so a token expires on screen without a keystroke.
