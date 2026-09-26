# InfraGuard

A Python command-line tool that reviews explicit Docker Compose settings before deployment. It produces prioritized remediation reports and CI-friendly JSON or SARIF, without running containers, connecting to infrastructure, or changing configuration.

## Try it

Python 3.11+:

```sh
python -m venv .venv
# Activate the environment using your shell's activation command.
python -m pip install -e .
python -m infra_guard examples/risky.compose.yaml
# Exit 1 is expected: the fixture deliberately contains high-risk settings.
python -m infra_guard examples/hardened.compose.yaml --fail-on medium
python -m unittest discover -s tests -v
```

The example images and digest are **static scanner fixtures**, not deployable applications.

## Ten focused checks

| Rule | Configuration concern |
| --- | --- |
| IG001 | Privileged containers |
| IG002 | Missing explicit non-root user, or explicit root |
| IG003 | Writable root filesystem |
| IG004 | Missing or disabled explicit health check |
| IG005 | Image reference without an immutable digest |
| IG006 | Published ports beyond IPv4/IPv6 loopback |
| IG007 | Shared host network or PID namespace |
| IG008 | Docker socket mounts |
| IG009 | Missing positive memory limits |
| IG010 | Literal values in credential-like environment keys |

Findings include severity, service, configuration field, remediation, and a stable fingerprint. Credential **values** are never copied into findings. Both short and long port/volume forms are handled. Duplicate YAML keys and unsafe YAML tags are rejected.

## Reports and CI

```sh
python -m infra_guard compose.yaml --format json --output report.json
python -m infra_guard compose.yaml --format markdown --output report.md
python -m infra_guard compose.yaml --format sarif --output report.sarif
```

Exit codes: **0** passes the selected threshold, **1** has active findings at or above that threshold, **2** indicates invalid input or an I/O error. The default threshold is high; `--fail-on medium` includes all supported severities, and `--fail-on none` generates reports without a risk gate. Reports are written even when the risk gate fails.

SARIF contains physical file locations and logical service/field locations. It does not invent source line numbers. The included workflow tests Python 3.11–3.13 and gates the hardened fixture.

## Time-bound exceptions

Copy the fingerprint from a JSON finding into a reviewed exceptions file:

```json
[
  {
    "fingerprint": "REPLACE_WITH_24_HEX_CHARS",
    "owner": "platform-team",
    "reason": "Temporary lab device access, tracked in internal change request",
    "expires": "2026-12-31"
  }
]
```

```sh
python -m infra_guard compose.yaml --exceptions exceptions.json --format json
```

Excepted findings remain visible. An exception is active through its expiry date in UTC; expired exceptions stop suppressing the gate automatically. Invalid or duplicate exceptions fail closed. Fingerprints include the input path, service, rule, and field, so run from a consistent repository-relative path in CI.

## Evidence and limitations

[Generated example report](docs/example-report.md) · [Design and supported scope](docs/design.md) · [Original learning plan](docs/original-learning-plan.md)

Twelve automated tests cover all rule categories, secret redaction, alternate syntax, stable fingerprints, expiry, invalid exceptions, malformed input, YAML safety, exit codes, and SARIF structure.

This is a portfolio posture checker, **not a compliance certification, vulnerability scanner, secret-discovery engine, or complete Compose validator**. It does not resolve environment files, inspect images, inspect Dockerfiles, merge multiple Compose files, or validate runtime behavior. Missing explicit controls may be inherited from an image; review each finding in context. Normalize merged Compose configuration before scanning it. Reports and exceptions may contain service names or operator-written notes, so review them before sharing.

The repository replaces the Road_To_Portfolio tutorial collection. Earlier exercises, including previously tracked dependencies, remain available in Git history. The current tree focuses on the infrastructure scanner.
