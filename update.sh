#!/usr/bin/env bash

set -euo pipefail

function nixEval() {
    scriptdir="$(dirname -- "$( realpath -e -- "${BASH_SOURCE[0]}")")"
    nix eval --impure --raw --expr "(builtins.getFlake \"${scriptdir}\").outputs.packages.x86_64-linux.${1}"
}

echo "Updating nix flake inputs..." >&2

nix flake update --commit-lock-file

echo "Updating govulndb..." >&2

govulndbURL=$(nixEval govulndb.url)
currentHash=$(nixEval govulndb.outputHash)
currentVersion=$(nixEval govulndb.version)
tmpdir=$(mktemp -d)
trap 'rm -rf $tmpdir' EXIT
pushd "${tmpdir}" > /dev/null
curl -fsSLO "${govulndbURL}"
unzip -q vulndb.zip
rm vulndb.zip
newVersionDate=$(jq -re '.modified' index/db.json | cut -d'T' -f1)
newVersion="0-unstable-${newVersionDate}"
newHash=$(nix hash path --type sha256 .)
popd > /dev/null
sed -i "s/${currentVersion}/${newVersion}/" flake.nix
sed -i "s/${currentHash}/${newHash}/" flake.nix
if git diff --quiet --exit-code flake.nix; then
    echo "govulndb is already up-to-date"
else
    echo "govulndb: ${currentVersion} -> ${newVersion}"
    git add flake.nix
    git commit -m "govulndb: update to ${newVersion}"
fi
