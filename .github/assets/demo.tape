# jwt-tui demo: decode, edit the payload, re-sign, security analysis, print mode.
# Regenerate (from the repo root): nix run --inputs-from . nixpkgs#vhs -- .github/assets/demo.tape

Output .github/assets/demo.gif

Require go

Set Shell "bash"
Set FontSize 15
Set Width 1400
Set Height 820
Set Padding 16
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

# HS256 token signed with "demo-secret": {"sub":"42","name":"Alice","role":"user",...}
Hide
Type "go build -o /tmp/jwt-tui ./cmd/jwt-tui && export PATH=/tmp:$PATH && clear"
Enter
Type "T=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsIm5hbWUiOiJBbGljZSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzYyOTA1NjAwLCJleHAiOjQxMDI0NDQ4MDB9.dBigTHgldVArocgQQNFEfX954F4eBO5NyWXY4aaYhiQ && clear"
Enter
Sleep 3s
Show

Type 'jwt-tui -t "$T" -s demo-secret'
Sleep 500ms
Enter
Sleep 2.5s

# Payload panel: clear it and type a forged payload
Tab
Sleep 400ms
Tab
Sleep 800ms
Type "x"
Sleep 400ms
Type "e"
Type '{"sub":"42","name":"Alice","role":"admin","exp":4102444800}'
Sleep 400ms
Escape
Sleep 2s

# Re-sign with the key in the Secret panel
Type "R"
Sleep 2.5s

# Security analysis
Type "a"
Sleep 3.5s
Type "a"
Sleep 800ms

Type "q"
Sleep 800ms

# Non-interactive mode, for scripts and CI
Type 'jwt-tui -p -s demo-secret "$T"'
Sleep 400ms
Enter
Sleep 4s
