{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;

          # Prevent duplicated reports.
          config.allowAliases = false;

          overlays = [
            (final: prev: {
              # Ensure we are using the latest version of Go, or we will get
              # many findings of vulnerable stdlib packages.
              # go_1_22 = prev.go_1_22.overrideAttrs (finalAttrs: _prevAttrs: {
              #   version = "1.22.3";
              #   src = final.fetchurl {
              #     url = "https://go.dev/dl/go${finalAttrs.version}.src.tar.gz";
              #     hash = "sha256-gGSO80+QMZPXKlnA3/AZ9fmK4MmqE63gsOy/+ZGnb2g=";
              #   };
              # });
            })
          ];
        };
        lib = pkgs.lib;

        # The Go vulnerability database.
        # Version is based on the modified field of index/db.json in the archive.
        govulndb = pkgs.buildGoModule {
          pname = "govuln";
          version = "0-unstable-2025-01-29";

          src = pkgs.fetchFromGitHub {
            owner = "golang";
            repo = "vulndb";
            rev = "2db00b4cd84ec07683fce47c4fa55aaaf9fe0520";
            leaveDotGit = true;
            deepClone = true;
            hash = "sha256-DRSEA7ZmmUSVWYZ0fxO134nW2IorB4g7WrK5OinPxvo=";
          };

          vendorHash = "sha256-u2h0zqZvbXFp+CxzZdeRn6ZNZGl1PwMzyqlZgVla0gk=";

          subPackages = [ "cmd/gendb" ];

          installPhase = ''
            go run ./cmd/gendb -out $out
          '';
        };

        # Helper script to govulncheck a module against the downloaded database.
        govulncheck-script = pkgs.writeShellApplication {
          name = "govulncheck-script";
          runtimeInputs = with pkgs; [
            govulncheck
            go
          ];
          text = ''govulncheck -db file://${govulndb} -C "$@" ./...'';
        };

        # Filter for Go packages based on some well known attributes buildGoModule will add.
        # This is not precise and likely flawed. It doesn't handle nested package sets correctly.
        # Number of packages found with this is close enough to the number of findings grepping
        # nixpkgs for "buildGoModule", so it's good enough for now.
        isGoPkg =
          name: pkg:
          (
            (builtins.tryEval pkg).success
            && lib.isAttrs pkg
            && lib.hasAttr "src" pkg
            && lib.hasAttr "go" pkg
            && lib.hasAttr "goModules" pkg
          );

        # Construct a file mapping package name to src path.
        goPkgs = lib.filterAttrs isGoPkg pkgs;
        goPkgsSrcs = lib.mapAttrsToList (
          name: pkg:
          (lib.concatStringsSep " " [
            name
            pkg.src
          ])
        ) goPkgs;
        goPkgsSrcsFile = pkgs.writeText "goPkgsList" (lib.concatStringsSep "\n" goPkgsSrcs);

        # Iterate over the list of Go package path srcs and run govulncheck on them.
        # Run as 'nix run .#govulncheck-srcs |& tee report.txt'
        govulncheck-srcs = pkgs.writeShellApplication {
          name = "govulncheck-srcs";
          runtimeInputs = with pkgs; [
            govulncheck
            go
          ];
          text = ''
            # Read Go packages from file, line by line, format is "name src"
            while IFS= read -r line; do
              name=$(echo "$line" | cut -d ' ' -f 1)
              src=$(echo "$line" | cut -d ' ' -f 2)
              echo "Checking nixpkg $name"
              govulncheck -db file://${govulndb} -C "$src" ./... 2>&1 || true
            done < ${goPkgsSrcsFile}
          '';
        };

        # Some bash to get something useful out of the govulncheck-srcs report.
        report-tool = pkgs.writeShellApplication {
          name = "report-tool";
          runtimeInputs = with pkgs; [
            curl
            gawk
            gnugrep
            gnused
            jq
            ripgrep
          ];
          text = builtins.readFile ./report-tool.sh;
        };
      in
      {
        packages = {
          inherit
            govulncheck-script
            govulncheck-srcs
            govulndb
            report-tool
            ;
        };
        devShells = {
          default = pkgs.mkShell {
            packages = [ report-tool ];
          };
        };
      }
    );
}
