# PipelineGuard Scan

A composite GitHub Action that runs [Trivy](https://github.com/aquasecurity/trivy),
[Checkov](https://github.com/bridgecrewio/checkov), [Gitleaks](https://github.com/gitleaks/gitleaks),
and [Grype](https://github.com/anchore/grype) against your repo and fails
the build if anything is found at or above a severity threshold you choose.

Standalone: everything runs inside your own CI job. It does not talk to any
external service, store results anywhere, or require an account - it's a
separate, self-contained pass/fail check, not connected to
[PipelineGuard's](https://github.com/sitardaniel/pipelineguard-app) own
scheduled scanning/dashboard/alerting system.

## Usage

```yaml
name: CI
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: sitardaniel/pipelineguard-action@main
        with:
          fail-on: HIGH
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan, relative to the repo root |
| `fail-on` | `HIGH` | Minimum severity that fails the build: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `NONE` to only report without ever failing |
| `scanners` | `trivy,checkov,gitleaks,grype` | Comma-separated list - drop scanners that don't apply to your repo (e.g. skip `checkov` if you have no Terraform) |

## Notes

- Gitleaks scans the current file tree (`--no-git`), not commit history -
  this is a per-push CI gate, so it only needs to catch secrets present
  right now, not re-flag every historical (possibly already-rotated)
  commit on every single run.
- Results are written to `$GITHUB_STEP_SUMMARY` (visible on the Actions run
  summary page) - nothing is uploaded or stored anywhere else.
- Requires Docker on the runner (available by default on GitHub-hosted
  `ubuntu-latest` runners).
