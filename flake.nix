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
              go_1_23 = prev.go_1_23.overrideAttrs (
                finalAttrs: _prevAttrs: {
                  version = "1.23.6";
                  src = final.fetchurl {
                    url = "https://go.dev/dl/go${finalAttrs.version}.src.tar.gz";
                    hash = "sha256-A5xbBOZSedrO7opvcecL0Fz1uAF4K293xuGeLtBREiI=";
                  };
                }
              );
            })
          ];
        };
        lib = pkgs.lib;

        # The Go vulnerability database.
        govulndb = pkgs.buildGoModule {
          pname = "govuln";
          version = "0-unstable-2025-02-18";

          src = pkgs.fetchFromGitHub {
            owner = "golang";
            repo = "vulndb";
            rev = "dbe3f0cf88afa5f29bc18ce8c1ee6e63c1e59d76";
            deepClone = true;
            # Deep clone is needed as the vulndb is constructed from the repo metadata.
            # However, .git isn't reproducible, mostly because of the unstable pack format.
            # We unpack these files, eating the huge increase in disk usage.
            # See https://github.com/NixOS/nixpkgs/issues/8567#issuecomment-133393592.
            postFetch = ''
              pushd $out
              tmpdir=$(mktemp -d)
              mv .git/objects/pack/*.pack $tmpdir
              rm -r .git/objects/pack
              rm .git/objects/info/packs
              for pack in $tmpdir/*.pack; do
                git unpack-objects < $pack
              done
              popd
            '';
            hash = "sha256-IjUL01tv8z/aYELEadX6TrjPkdZLKbhzU/RQUDlpCOI=";
          };

          vendorHash = "sha256-TRmAtXJwVL+rY6oszMU4aLxCV0SiKG4CT9ydKIO74zw=";

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

        # This tries to count the total number of module dependencies in nixpkgs.
        # Main goal here is to get an expectation for the goPackages size of gobuild.nix.
        go-modules-total =
          pkgs.runCommand "go-count-modules-total"
            {
              buildInputs = with pkgs; [ go ];
            }
            ''
              mkdir -p $out
              tmpfile=$(mktemp)

              while IFS= read -r line; do
                src=$(echo "$line" | cut -d ' ' -f 2)
                cat $src/go.mod >> $tmpfile || echo "$src" >> $out/not-included.txt
              done < ${goPkgsSrcsFile}

              cat $tmpfile |
                sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//' |
                sed -E 's/[[:space:]]*\/\/ indirect$//' |
                grep -v '^go' |
                grep -v '^//' |
                grep -v '^module' |
                grep -v '^require (' |
                grep -v '^replace' |
                grep -v '^exclude' |
                grep -v '^)$' |
                grep -v '^retract' |
                grep -v '^toolchain' |
                grep -v '^v[0-9]\+\.[0-9]\+\.[0-9]\+' |
                cut -d' ' -f1 |
                sort -u > $out/modules.txt
            '';
      in
      {
        packages = {
          inherit
            govulncheck-script
            govulncheck-srcs
            govulndb
            go-modules-total
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
