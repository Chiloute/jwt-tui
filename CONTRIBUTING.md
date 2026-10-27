# Contributing

How to send a change that gets merged without back and forth.

## Before you start

- Bug or small fix: open the PR directly.
- New feature, new flag, behavior change: open an issue first and describe what you want. A PR that adds something nobody agreed on is the most common reason for a rejection.
- Security problem: do not open a public issue. TODO: add a private contact (security advisory or email).

## Setup

```sh
git clone https://github.com/chiloute/jwt-tui && cd jwt-tui
nix develop          # optional: go, staticcheck, git hooks
go test ./...
```

Without Nix you need Go 1.26 and `gofmt`, `go vet` and `staticcheck` run by hand. The Nix shell runs them for you on each commit.

## Making the PR

1. Branch from `main`: `fix/short-name`, `feat/short-name`, `docs/short-name`.
2. One PR, one subject. A bug fix and a refactor go in two PRs.
3. Keep the diff small. Do not reformat or rename files you do not need to touch.
4. Run before pushing:

   ```sh
   gofmt -l .      # prints nothing
   go vet ./...
   staticcheck ./...
   go test ./...
   ```

5. Push and open the PR against `main`.

## Commit messages

Conventional Commits, as in the history:

```
fix: clamp highlight.JSON string scan to input length
refactor(jwt): decode payload once
test: add reproducer for highlight.JSON panic on trailing backslash
docs: describe finding codes
```

Types in use: `fix`, `feat`, `refactor`, `test`, `docs`, `ci`. Scope (`jwt`, `ui`, `deps`) is optional. Subject in the imperative, under 72 characters, no final period. `docs:`, `test:` and `ci:` commits are left out of the release changelog.

## What the PR needs

- **A test** for any bug fix (it fails before the fix, passes after) and for any new behavior. Tests sit next to the code in `*_test.go`. For a bug, a separate `test:` commit before the `fix:` commit is welcome.
- **Docs updated** if you change a flag, a key, a config option or a finding code: the matching page in [docs/](docs/) and `internal/ui/docs.md` (the reference shown by `d`).
- **`nix/gomod2nix.toml` regenerated** if you touch `go.mod` or `go.sum` (`gomod2nix --outdir ./nix`, done by the pre-commit hook in `nix develop`). Do not edit it by hand.
- **No new dependency** for a few lines of code. If you add one, say why in the PR.

## PR description

Three lines are enough:

- What changes and why.
- How you tested it (command, token, screenshot of the TUI if the UI changed).
- Linked issue, if any: `Closes #12`.

## Code rules specific to this project

- `internal/jwt` must not import `internal/ui`.
- Anything from a token (header values, claims) can contain control characters. Pass it through `printable` before it reaches the terminal.
- A key of the wrong family is never reported as `valid`. Do not weaken the `alg confusion` check.
- Match the style around your change: naming, comment density, error handling.

## Review

Expect a first answer in a few days. Push fixes as new commits during review; they are squashed at merge. Releases are cut by the maintainer by pushing a `v*` tag, see [docs/development.md](docs/development.md#release).
