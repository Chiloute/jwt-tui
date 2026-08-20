{
  pkgs,
  gitHooksLib,
  gomod2nixPkgs,
}: let
  hooks = gitHooksLib.run {
    src = ../.;
    hooks = {
      gofmt.enable = true;
      govet.enable = true;
      staticcheck.enable = true;
      gomod2nix = {
        enable = true;
        name = "gomod2nix";
        entry = "gomod2nix --outdir ./nix";
        language = "system";
        files = "go\\.(mod|sum)$";
        pass_filenames = false;
      };
    };
  };
in
  pkgs.mkShell {
    packages = with pkgs;
      [
        go
        gopls
        gotools
        go-tools # staticcheck
        gomod2nixPkgs.gomod2nix
      ]
      ++ hooks.enabledPackages;

    shellHook =
      hooks.shellHook
      + ''
        echo "jwt-tui — dev shell"
        echo "  go run ./cmd/jwt-tui   # lancer le TUI"
        echo "  go test ./...          # tests"
        echo "  nix build              # compiler le binaire (result/bin/jwt-tui)"
      '';
  }
