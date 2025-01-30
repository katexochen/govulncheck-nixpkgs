#!/usr/bin/env bash

set -euo pipefail

echo "Updating nix flake inputs..." >&2
nix flake update --commit-lock-file

echo "Updating govulndb..." >&2
nix-update --version=branch --commit --flake govulndb
