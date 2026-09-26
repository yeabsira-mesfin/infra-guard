import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from .scanner import RULES, apply_exceptions, load_document, scan


def sarif(findings, source):
    results = []
    for finding in findings:
        result = {"ruleId": finding.rule_id, "level": "error" if finding.severity == "high" else "warning",
                  "message": {"text": f"{finding.service}: {finding.message} {finding.remediation}"},
                  "locations": [{"physicalLocation": {"artifactLocation": {"uri": source}}, "logicalLocations": [{"fullyQualifiedName": f"services.{finding.service}.{finding.field}"}]}],
                  "partialFingerprints": {"configurationFinding/v1": finding.fingerprint}}
        if finding.suppressed:
            result["suppressions"] = [{"kind": "external", "justification": finding.exception["reason"]}]
        results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "InfraGuard", "version": "1.0.0", "rules": [{"id": key, "shortDescription": {"text": value[0]}, "help": {"text": value[1]}} for key, value in RULES.items()]}}, "results": results}]}


def markdown(findings, source):
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ")
    lines = ["# Infrastructure posture report", "", f"Source: `{cell(source)}`", "",
             "| Severity | Rule | Service | Finding | Action |", "| --- | --- | --- | --- | --- |"]
    for f in findings:
        state = "excepted" if f.suppressed else f.severity
        lines.append("| " + " | ".join(map(cell, [state, f.rule_id, f.service, f.message, f.remediation])) + " |")
    if not findings:
        lines += ["", "No findings in the supported checks. This is not a compliance certification."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan explicit Docker Compose settings locally. Never runs containers or contacts services.")
    parser.add_argument("config", type=Path)
    parser.add_argument("--format", choices=["json", "markdown", "sarif"], default="markdown")
    parser.add_argument("--exceptions", type=Path)
    parser.add_argument("--fail-on", choices=["high", "medium", "none"], default="high")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        source = args.config.as_posix()
        findings = scan(load_document(args.config), source)
        if args.exceptions:
            findings = apply_exceptions(findings, json.loads(args.exceptions.read_text()), datetime.now(timezone.utc).date())
        report = {"schema_version": 1, "source": source, "findings": [f.to_dict() for f in findings], "summary": {
            "high": sum(f.severity == "high" and not f.suppressed for f in findings),
            "medium": sum(f.severity == "medium" and not f.suppressed for f in findings),
            "suppressed": sum(f.suppressed for f in findings)}}
        output = markdown(findings, source) if args.format == "markdown" else json.dumps(sarif(findings, source) if args.format == "sarif" else report, indent=2) + "\n"
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        threshold = {"none": set(), "high": {"high"}, "medium": {"high", "medium"}}[args.fail_on]
        return int(any(not f.suppressed and f.severity in threshold for f in findings))
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"infra-guard: {exc}", file=sys.stderr)
        return 2
