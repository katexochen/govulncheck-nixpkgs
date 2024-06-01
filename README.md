## Govulncheck on nixpkgs

This project runs [govulncheck](https://go.dev/blog/govulncheck) on the source of Go packages
in [nixpkgs](https://github.com/NixOS/nixpkgs) to identify security vulnerabilities not handled
downstream (due to missing updates) or upstream (unmaintained or unaware projects).

Scans use a pinned version of nixpkgs and the [govulndb](https://vuln.go.dev/) so that the results
are reproducible. The [scan report](https://github.com/katexochen/govulncheck-nixpkgs/blob/main/report.txt)
is tracked as part of this repo. It can be inspected with the `report-tool`, which gives an overview and
allows easy access to the relevant part of the report.

```
❯ report-tool stats
Packages discovered:   2090
Packages failed:       344 (16%)
Packages scanned:      1746 (83%)
Packages vulnerable:   567 (32% of scanned)
Total vulnerabilities: 1247
```

### Current limitations

- Primitive package discovery (see `isGoPkg`)
  - Only looking at package attributes to identify Go packages
  - Not recuring into nested attribute sets
  - `rg -c 'buildGo\d*Module (|rec )\{' | awk -F: '{s+=$2} END {print s}'` on nixpkgs gives 2074 findings,
    so the 2090 packages found by the heuristic might should at least be somewhat close
- Checks are running directly on `src`
  - `patches` not taken into account
  - `cgo` dependencies are not present (see `report-tool failed`)
  - `srcRoot`, `subPackages` etc not taken into account (some failures as `go.mod` is not found)
  - `goModules` isn't used by the govulncheck invocation
- Scan is not running in the sandbox
- All the [limitations of govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck#hdr-Limitations)
- Only covers nixpkgs-unstable (support for releases upcoming)
- Report lacks a structured format. I couldn't befriend with the JSONline output of govulncheck, it misses
  some important info like scan failures, which won't be part of the structured output. The current report
  can be somehow worked with using the report-tool. In the future, some kind of website would be nice to
  present the results.


### `report-tool`

```
Usage: report-tool <command> [args]

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
```
