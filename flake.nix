{
  description = "EchoVault dev env";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rustfmt" "clippy" "rust-src" ];
        };
        rustAnalyzer = pkgs.rust-analyzer;
      in {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs; [ openssl sqlite ];
          packages = with pkgs; [
            rustToolchain
            rustAnalyzer
            sccache
            mold
            just
            sqlx-cli
          ];

          RUSTC_WRAPPER = "${pkgs.sccache}/bin/sccache";
          CARGO_BUILD_RUSTFLAGS = "-C link-arg=-fuse-ld=mold";

          PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" [ pkgs.openssl.dev ];

          # Defaults for local dev
          EV_LISTEN = "0.0.0.0:8080";
          EV_DATA_DIR = "./data";
          EV_DATABASE_URL = "sqlite:./data/echovault.db?mode=rwc";
          EV_JWT_SECRET = "dev-secret-change-me";
          EV_PUBLIC_ORIGIN = "http://127.0.0.1:8080";
          EV_JWT_TTL_SECS = "900";
          EV_REFRESH_TTL_SECS = "2592000";

          DATABASE_URL = "sqlite:./data/echovault.db?mode=rwc";

          shellHook = ''
            export CARGO_TERM_COLOR=always
            export RUST_LOG=''${RUST_LOG:-info}
            mkdir -p "$EV_DATA_DIR"
          '';
        };

        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
