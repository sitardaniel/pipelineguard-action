#!/usr/bin/env python3
"""
BaghGuard Action - aggregate scanner results and decide pass/fail.

Parses the same JSON shapes the main BaghGuard system's normalizer
already parses (trivy/checkov/gitleaks/grype), minus the Postgres/
multi-user attribution - this runs standalone in CI.
"""

import argparse
import json
import os
import sys

SEVERITY_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}


def parse_trivy(data: dict) -> list:
    findings = []
    for result in data.get('Results', []) or []:
        target = result.get('Target', '')
        for vuln in result.get('Vulnerabilities', []) or []:
            findings.append({
                'scanner': 'trivy',
                'severity': (vuln.get('Severity') or 'UNKNOWN').upper(),
                'id': vuln.get('VulnerabilityID', ''),
                'file': target,
                'detail': (vuln.get('Title') or vuln.get('Description') or '')[:200],
            })
        for misconfig in result.get('Misconfigurations', []) or []:
            findings.append({
                'scanner': 'trivy',
                'severity': (misconfig.get('Severity') or 'UNKNOWN').upper(),
                'id': misconfig.get('ID', ''),
                'file': target,
                'detail': (misconfig.get('Title') or misconfig.get('Message') or '')[:200],
            })
    return findings


def parse_checkov(data) -> list:
    findings = []
    checks = data if isinstance(data, list) else [data]
    for check_result in checks:
        if not isinstance(check_result, dict):
            continue
        failed = (check_result.get('results') or {}).get('failed_checks') or []
        for check in failed:
            severity = (check.get('severity') or 'MEDIUM').upper()
            findings.append({
                'scanner': 'checkov',
                'severity': severity,
                'id': check.get('check_id', ''),
                'file': check.get('file_path', ''),
                'detail': (check.get('check_name') or '')[:200],
            })
    return findings


def parse_gitleaks(data) -> list:
    if not isinstance(data, list):
        data = []
    return [{
        'scanner': 'gitleaks',
        'severity': 'HIGH',  # all secrets are treated as high severity
        'id': leak.get('RuleID', 'secret'),
        'file': leak.get('File', ''),
        'detail': f"Secret detected: {leak.get('Description', leak.get('RuleID', 'Unknown'))}"[:200],
    } for leak in data]


def parse_grype(data: dict) -> list:
    findings = []
    for match in data.get('matches', []) or []:
        vuln = match.get('vulnerability', {}) or {}
        artifact = match.get('artifact', {}) or {}
        locations = artifact.get('locations') or [{}]
        findings.append({
            'scanner': 'grype',
            'severity': (vuln.get('severity') or 'UNKNOWN').upper(),
            'id': vuln.get('id', ''),
            'file': locations[0].get('path', ''),
            'detail': f"{artifact.get('name', '')} {artifact.get('version', '')}".strip(),
        })
    return findings


PARSERS = {
    'trivy.json': parse_trivy,
    'checkov.json': parse_checkov,
    'gitleaks.json': parse_gitleaks,
    'grype.json': parse_grype,
}


def load_findings(results_dir: str) -> list:
    findings = []
    for filename, parser in PARSERS.items():
        path = os.path.join(results_dir, filename)
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"::warning::Could not parse {filename}: {e}")
            continue
        findings.extend(parser(data))
    return findings


def write_summary(findings: list, fail_on: str, failed: bool):
    counts = {}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    lines = ['# BaghGuard scan results', '']
    if not findings:
        lines.append('No findings.')
    else:
        lines.append('| Severity | Count |')
        lines.append('|---|---|')
        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'):
            if counts.get(sev):
                lines.append(f'| {sev} | {counts[sev]} |')
        lines.append('')
        lines.append('| Scanner | Severity | ID | File | Detail |')
        lines.append('|---|---|---|---|---|')
        ordered = sorted(findings, key=lambda f: -SEVERITY_RANK.get(f['severity'], 0))
        for f in ordered[:25]:
            lines.append(f"| {f['scanner']} | {f['severity']} | {f['id']} | {f['file']} | {f['detail']} |")
        if len(findings) > 25:
            lines.append('')
            lines.append(f'_...and {len(findings) - 25} more findings not shown._')

    lines.append('')
    lines.append(f'**fail-on**: `{fail_on}` -> {"FAILED" if failed else "passed"}')

    text = '\n'.join(lines)
    print(text)

    summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary_path:
        with open(summary_path, 'a') as f:
            f.write(text + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fail-on', default='HIGH')
    parser.add_argument('--results-dir', default='.baghguard')
    args = parser.parse_args()

    fail_on = args.fail_on.upper()
    findings = load_findings(args.results_dir)

    if fail_on == 'NONE':
        write_summary(findings, fail_on, failed=False)
        sys.exit(0)

    threshold = SEVERITY_RANK.get(fail_on)
    if threshold is None:
        print(
            f"::error::Invalid fail-on value '{args.fail_on}' - must be one of "
            "CRITICAL, HIGH, MEDIUM, LOW, NONE",
            file=sys.stderr,
        )
        sys.exit(2)

    failed = any(SEVERITY_RANK.get(f['severity'], 0) >= threshold for f in findings)
    write_summary(findings, fail_on, failed)
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
