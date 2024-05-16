#!/usr/bin/env bash

function substituteWithCVEIfAvailable() {
    vulndbURL=$GOVULNDB_URL
    if [[ -z "$vulndbURL" ]]; then
        cat -
        return
    fi
    vulnIdx=$(curl -fsSL "$vulndbURL/index/vulns.json")
    while read -r vuln; do
        cve=$(
            echo "$vulnIdx" |
            jq -r ".[] | select(.id == \"$vuln\") | .aliases.[]" |
            grep CVE || true
        )
        if [[ -n "$cve" ]]; then
            echo "$cve"
        else
            echo "$vuln"
        fi
    done
}

cmd=$1
case $cmd in
    "stats")
        pkgs=$(grep -c 'Checking nixpkg' report.txt)
        vulns=$(grep -c 'Vulnerability #' report.txt)
        vulnPkgs=$(
            grep -E '(Checking nixpkg|Vulnerability #)' report.txt |
            rg --multiline 'Checking nixpkg.*\n.*Vulnerability #' |
            grep -c 'Checking nixpkg'
        )
        vulnPerc=$(( 100 * vulnPkgs / pkgs ))
        echo "Packages checked:      $pkgs"
        echo "Vulnerable packages:   $vulnPkgs ($vulnPerc%)"
        echo "Total vulnerabilities: $vulns"
       ;;
    "list")
        grep -E '(Checking nixpkg|Vulnerability #)' report.txt | less
        ;;
    "report")
        pkgName=$2
        awk "/Checking nixpkg ${pkgName}/,/for more details/" report.txt
        ;;
    "findings")
        pkgName=$2
        awk "/Checking nixpkg ${pkgName}/,/for more details/" report.txt |
        grep  'More info: ' |
        sed 's/\s*More info: //'
        ;;
    "mark")
        pkgName=$2
        awk "/Checking nixpkg ${pkgName}/,/for more details/" report.txt |
        grep 'Vulnerability #' |
        sed 's/\s*Vulnerability #[[:digit:]]*: //' |
        substituteWithCVEIfAvailable |
        sort -ur |
        sed 's/^/"/' |
        sed 's/$/"/'
        ;;
    "fix")
        pkgName=$2
        while read -r fix; do
            modName=$(echo "$fix" | cut -d' ' -f1)
            modVersion=$(echo "$fix" | cut -d' ' -f2)
            echo "go get -u $modName@$modVersion"
            echo "go mod tidy"
            echo "git diff -q --exit-code || git commit -am \"update $modName to $modVersion\""
        done < <(
            awk "/Checking nixpkg ${pkgName}/,/for more details/" report.txt |
            grep 'Fixed in:' |
            sed 's/\s*Fixed in: //' |
            awk -F@ '{print $1 " " $2}' |
            sort -k1,1 -k2Vr |
            awk '!seen[$1]++'
        )
        ;;
    *)
        cat <<EOF

Usage: $0 <command> [args]

Commands:
    stats
        Show statistics about the report.

    list
        List all packages checked and their vulnerabilities.

    report <pkgName>
        Show the report for a specific package.

    findings <pkgName>
        List the found vulnerabilities (URL) for a specific package.

    mark <pkgName>
        Show the vulnerabilities for a specific package in a format that can be
        used to mark the package as vulnerable in the nixpkgs repository.

    fix <pkgName>
        Show the commands to fix the vulnerabilities upstream.

EOF
        ;;
esac
