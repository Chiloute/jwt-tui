{
  pkgs,
  buildGoApplication,
}: let
  pname = "jwt-tui";
  version = "0.2.0";
  ldflags = ["-s" "-w" "-X main.version=${version}"];
  pkg = buildGoApplication {
    inherit pname version ldflags;
    src = ../.;
    modules = ./gomod2nix.toml;
    meta = with pkgs.lib; {
      description = "Décodeur/reforgeur de JWT en TUI (HMAC, RSA, ECDSA, Ed25519)";
      homepage = "https://github.com/chiloute/jwt-tui";
      license = licenses.mit;
      mainProgram = "jwt-tui";
      platforms = platforms.linux;
    };
  };
in {
  "${pname}" = pkg;
  default = pkg;
}
