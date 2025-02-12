#!/usr/bin/env bash

sed -i '1,/^Checking nixpkg/ {/^Checking nixpkg/!d}' report.txt
