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

cmd=${1:-}
case $cmd in
    "stats")
        discovered=$($0 discovered | wc -l)
        failed=$($0 failed | wc -l)
        scanned=$($0 scanned | wc -l)
        vulnerable=$($0 vulnerable | wc -l)
        nonvulnerable=$($0 non-vulnerable | wc -l)

        # ensure failed + scanned = discovered
        if [[ $discovered -ne $((failed + scanned)) ]]; then
            echo -e "Error: $discovered (discovered) != $failed (failed) + $scanned (scanned)\n"
        fi
        # ensure scanned = vulnerable + non-vulnerable
        if [[ $scanned -ne $((vulnerable + nonvulnerable)) ]]; then
            echo -e "Error: $scanned (scanned) != $vulnerable (vulnerable) + $nonvulnerable (non-vulnerable)\n"
        fi

        vulns=$(rg -c 'Vulnerability #' report.txt)
        echo "Packages discovered:   $discovered"
        echo "Packages failed:       $failed ($(( 100 * failed / discovered ))%)"
        echo "Packages scanned:      $scanned ($(( 100 * scanned / discovered ))%)"
        echo "Packages vulnerable:   $vulnerable ($(( 100 * vulnerable / scanned ))% of scanned)"
        echo "Total vulnerabilities: $vulns"
       ;;
    "discovered")
        rg -NI 'Checking nixpkg ([^\s]+)' -or '$1' report.txt
        ;;
    "failed")
        rg -NI 'Checking nixpkg|govulncheck: (loading packages|no go.mod file)' report.txt |
        rg --multiline 'Checking nixpkg ([^\s]+)\ngovulncheck' -or '$1'
        ;;
    "scanned")
        rg -NI 'Checking nixpkg|Vulnerability #|govulncheck:' report.txt |
        rg --multiline -v 'Checking nixpkg ([^\s]+)\ngovulncheck:' |
        rg 'Checking nixpkg ([^\s]+)' -or '$1'
        ;;
    "vulnerable")
        rg -NI 'Checking nixpkg|Vulnerability #' report.txt |
        rg --multiline 'Checking nixpkg ([^\s]+)\n\s*Vulnerability #' -or '$1'
        ;;
    "non-vulnerable")
        rg -NI 'Checking nixpkg|Vulnerability #|govulncheck:' report.txt |
        rg --multiline -v 'Checking nixpkg [^\s]+\n(Vulnerability #|govulncheck:)' |
        rg 'Checking nixpkg ([^\s]+)' -or '$1'
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

    discovered
        List packages which were tried to be checked.

    failed
        List packages for which the check failed.

    scanned
        List packages that were successfully scanned.

    vulnerable
        List packages that have vulnerabilities.

    non-vulnerable
        List packages that do not have vulnerabilities.

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
