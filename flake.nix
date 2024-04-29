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
          config = {
            allowAliases = false;
            allowUnfree = true;
            allowBroken = true;
            allowUnsupportedSystem = true;
            allowInsecurePredicate = (pkg: true);
            android_sdk.accept_license = true;
          };
        };
        lib = pkgs.lib;

        govulndb = pkgs.fetchzip {
          pname = "govulndb";
          version = "0-unstable-2023-04-22";
          url = "https://vuln.go.dev/vulndb.zip";
          hash = "sha256-BUxmq57f5/wkMnZ2am9IS5KFVGpY2CtuqAz9IcOIBxc=";
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
        goPkgsNames = builtins.toString (lib.attrNames goPkgs);
        goPkgsSources = lib.mapAttrsToList (name: pkg: (lib.concatStringsSep " " [ name pkg.src ])) goPkgs;
        goPkgsList = lib.concatStringsSep "\n" goPkgsSources;
        goPkgsListFile = pkgs.writeText "goPkgsList" goPkgsList;

        govulncheck-go-srouces = pkgs.writeShellApplication {
          name = "govulncheck-nixpkgs";
          runtimeInputs = with pkgs; [ govulncheck go ];
          text = ''
            exitcode=0
            # Read Go packages from file, line by line, format is "name src"
            while IFS= read -r line; do
              name=$(echo "$line" | cut -d ' ' -f 1)
              src=$(echo "$line" | cut -d ' ' -f 2)
              echo "Checking nixpkg $name"
              govulncheck -db file://${govulndb} -C "$src" ./... || exitcode=$?
            done < ${goPkgsListFile}
            exit $exitcode
          '';
        };

        govulncheck-pkg = name: pkg: (pkg.overrideAttrs (oldAttrs: {
          nativeBuildInputs = oldAttrs.nativeBuildInputs ++ [ pkgs.govulncheck ];
          buildPhase = ''
            runHook preBuild

            mkdir -p $out
            if ! govulncheck -db file://${govulndb} ./... | tee ${name}.report; then
              mv ${name}.report $out/${name}.report
            fi

            for output in $man $wordlists $bin $dev $testing_infra; do
              mkdir -p $output
            done

            runHook postBuild
          '';
          doCheck = false;
          dontInstall = true;
          doInstallCheck = false;
          dontFixup = true;
          doDist = false;
        }));

        govulncheck-nixpkgs = pkgs.symlinkJoin {
          name = "govulncheck-nixpkgs";
          paths = lib.mapAttrsToList govulncheck-pkg goPkgs;
        };
      in
      {
        packages = {
          inherit
            govulncheck-script
            govulndb
            goPkgsList
            goPkgsListFile
            govulncheck-go-srouces
            govulncheck-pkg
            govulncheck-nixpkgs
            ;
          uplosi = pkgs.uplosi;
          hello = pkgs.hello;
        };
      });
}
