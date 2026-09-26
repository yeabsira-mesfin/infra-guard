import contextlib
from datetime import date
import io
import json
from pathlib import Path
import tempfile
import unittest
from infra_guard.cli import main, sarif
from infra_guard.scanner import apply_exceptions, load_document, scan


def safe_service():
    return {"image": "example.invalid/app@sha256:" + "a" * 64, "user": "10001:10001", "read_only": True,
            "healthcheck": {"test": ["CMD", "true"]}, "mem_limit": "256m", "ports": ["127.0.0.1:8080:80"]}


class ScannerTests(unittest.TestCase):
    def scan_service(self, **overrides):
        return scan({"services": {"api": {**safe_service(), **overrides}}})

    def test_hardened_explicit_settings_pass(self):
        self.assertEqual(self.scan_service(), [])

    def test_all_risky_categories_are_reported(self):
        findings = self.scan_service(image="app:latest", user="0:0", read_only=False, healthcheck={"disable": True},
                                     privileged=True, ports=["8080:80"], network_mode="host", volumes=["/var/run/docker.sock:/var/run/docker.sock"], mem_limit="0", environment={"API_TOKEN": "synthetic-only"})
        self.assertEqual({f.rule_id for f in findings}, {f"IG{i:03}" for i in range(1, 11)})

    def test_literal_secret_values_never_enter_reports(self):
        findings = self.scan_service(environment={"DATABASE_PASSWORD": "must-not-appear"})
        serialized = json.dumps([f.to_dict() for f in findings]) + json.dumps(sarif(findings, "compose.yaml"))
        self.assertNotIn("must-not-appear", serialized)
        self.assertIn("DATABASE_PASSWORD", serialized)

    def test_secret_references_and_file_variables_are_not_literal_findings(self):
        self.assertEqual(self.scan_service(environment=["API_TOKEN=${API_TOKEN}", "PASSWORD_FILE=/run/secrets/password"]), [])

    def test_ipv6_and_long_syntax_loopback_ports(self):
        self.assertEqual(self.scan_service(ports=["[::1]:8080:80", {"host_ip": "127.0.0.1", "published": 8000, "target": 80}]), [])
        self.assertEqual(self.scan_service(ports=[{"published": 8000, "target": 80}])[0].rule_id, "IG006")

    def test_limits_under_deploy_are_recognized(self):
        service = safe_service(); del service["mem_limit"]
        service["deploy"] = {"resources": {"limits": {"memory": "256M"}}}
        self.assertEqual(scan({"services": {"api": service}}), [])

    def test_fingerprints_survive_unrelated_setting_changes(self):
        a = self.scan_service(privileged=True)[0]
        b = self.scan_service(privileged=True, command="something else")[0]
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_expiring_exceptions_keep_findings_visible(self):
        findings = self.scan_service(privileged=True)
        entry = {"fingerprint": findings[0].fingerprint, "owner": "platform", "reason": "Temporary local device test", "expires": "2026-09-26"}
        self.assertTrue(apply_exceptions(findings, [entry], date(2026, 9, 26))[0].suppressed)
        expired = apply_exceptions(findings, [entry], date(2026, 9, 27))[0]
        self.assertFalse(expired.suppressed); self.assertTrue(expired.exception["expired"])

    def test_unjustified_or_duplicate_exceptions_fail_closed(self):
        findings = self.scan_service(privileged=True)
        entry = {"fingerprint": findings[0].fingerprint, "owner": "platform", "reason": "no", "expires": "2026-09-26"}
        with self.assertRaises(ValueError): apply_exceptions(findings, [entry])
        entry["reason"] = "Documented local exception"
        with self.assertRaises(ValueError): apply_exceptions(findings, [entry, entry])

    def test_invalid_shapes_do_not_silently_pass(self):
        for document in [{}, {"services": []}, {"services": {"api": None}}]:
            with self.assertRaises(ValueError): scan(document)
        for extra in [{"ports": "8080"}, {"environment": "TOKEN=example"}, {"volumes": [False]}]:
            with self.assertRaises(ValueError): self.scan_service(**extra)

    def test_duplicate_keys_and_unsafe_yaml_tags_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            for data in ["services: {}\nservices: {}", "!!python/object/apply:os.system ['echo unsafe']"]:
                path.write_text(data)
                with self.assertRaises(ValueError): load_document(path)

    def test_cli_severity_exit_codes_and_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "compose.json"; output = Path(directory) / "report.json"
            path.write_text(json.dumps({"services": {"api": {**safe_service(), "read_only": False}}}))
            self.assertEqual(main([str(path), "--output", str(output)]), 0)
            self.assertEqual(main([str(path), "--fail-on", "medium", "--format", "sarif", "--output", str(output)]), 1)
            report = json.loads(output.read_text())
            self.assertEqual(report["version"], "2.1.0")
            self.assertEqual(report["runs"][0]["results"][0]["ruleId"], "IG003")
            path.write_text("invalid: [")
            with contextlib.redirect_stderr(io.StringIO()): self.assertEqual(main([str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
