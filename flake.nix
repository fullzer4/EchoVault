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
            # optional helpers
            sqlx-cli
          ];

          RUSTC_WRAPPER = "${pkgs.sccache}/bin/sccache";
          CARGO_BUILD_RUSTFLAGS = "-C link-arg=-fuse-ld=mold";

          PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" [ pkgs.openssl.dev ];

          # For sqlx (enable offline later if desired)
          DATABASE_URL = "sqlite://./echovault.db";

          shellHook = ''
            export CARGO_TERM_COLOR=always
            export RUST_LOG=''${RUST_LOG:-info}
            echo "Dev shell: cargo in apps/server (workspace soon)"
          '';
        };

        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
