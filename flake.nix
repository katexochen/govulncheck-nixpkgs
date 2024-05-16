{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;

          # Prevent duplicated reports.
          config.allowAliases = false;

          overlays = [
            (final: prev: {
              go_1_22 = prev.go_1_22.overrideAttrs (finalAttrs: _prevAttrs: {
                version = "1.22.3";
                src = final.fetchurl {
                  url = "https://go.dev/dl/go${finalAttrs.version}.src.tar.gz";
                  hash = "sha256-gGSO80+QMZPXKlnA3/AZ9fmK4MmqE63gsOy/+ZGnb2g=";
                };
              });
            })
          ];
        };
        lib = pkgs.lib;

        govulndb = pkgs.fetchzip {
          pname = "govulndb";
          version = "0-unstable-2024-05-14";
          url = "https://vuln.go.dev/vulndb.zip";
          hash = "sha256-oCNFLOp72XXvx8kM9umiZDeMcsC+bi2QibZ3eCD2nyM=";
          stripRoot = false;
        };

        govulncheck-script = pkgs.writeShellApplication {
          name = "govulncheck-script";
          runtimeInputs = with pkgs; [ govulncheck go ];
          text = ''govulncheck -db file://${govulndb} -C "$@" ./...'';
        };

        isGoPkg = name: pkg: (
          (builtins.tryEval pkg).success
          && lib.isAttrs pkg
          && lib.hasAttr "src" pkg
          && lib.hasAttr "go" pkg
          && lib.hasAttr "goModules" pkg
        );

        goPkgs = lib.filterAttrs isGoPkg pkgs;
        goPkgsSources = lib.mapAttrsToList (name: pkg: (lib.concatStringsSep " " [ name pkg.src ])) goPkgs;
        goPkgsList = lib.concatStringsSep "\n" goPkgsSources;
        goPkgsListFile = pkgs.writeText "goPkgsList" goPkgsList;

        govulncheck-srcs-script = pkgs.writeShellApplication {
          name = "govulncheck-srcs.sh";
          runtimeInputs = with pkgs; [ govulncheck go ];
          text = ''
            exitcode=0
            # Read Go packages from file, line by line, format is "name src"
            while IFS= read -r line; do
              name=$(echo "$line" | cut -d ' ' -f 1)
              src=$(echo "$line" | cut -d ' ' -f 2)
              echo "Checking nixpkg $name" | tee /dev/stderr
              govulncheck -db file://${govulndb} -C "$src" ./... || exitcode=$?
            done < ${goPkgsListFile}
            exit $exitcode
          '';
        };

        govulncheck-srcs = pkgs.runCommand "govulncheck-srcs"
          { nativeBuildInputs = [ govulncheck-srcs-script ]; }
          ''
            export HOME=$TMPDIR
            govulncheck-srcs.sh > $out
          '';

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
      });
}
