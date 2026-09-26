"""Conservative checks against explicit Compose settings, not running containers."""
from dataclasses import asdict, dataclass, replace
from datetime import date
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
import json
import re
import yaml


class UniqueSafeLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            if key in result:
                raise ValueError("Duplicate mapping key; normalize the Compose configuration first.")
            result[key] = loader.construct_object(value_node, deep=deep)
        except TypeError as exc:
            raise ValueError("Mapping keys must be simple values.") from exc
    return result


UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_document(path):
    content = Path(path).read_text(encoding="utf-8")
    if len(content.encode("utf-8")) > 2_000_000:
        raise ValueError("Configuration exceeds the 2 MB input limit.")
    try:
        document = yaml.load(content, Loader=UniqueSafeLoader)
    except yaml.YAMLError as exc:
        # Parser snippets could contain credentials. Do not include them in reports.
        raise ValueError("Invalid YAML or unsupported YAML tag.") from exc
    if not isinstance(document, dict):
        raise ValueError("Expected a Compose mapping.")
    return document


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    service: str
    field: str
    message: str
    remediation: str
    fingerprint: str
    suppressed: bool = False
    exception: dict | None = None

    def to_dict(self):
        return asdict(self)


RULES = {
    "IG001": ("Privileged container", "Disable privileged mode; grant only the capabilities required."),
    "IG002": ("Non-root identity not explicit", "Set an explicit non-root user and verify filesystem permissions."),
    "IG003": ("Writable root filesystem", "Set read_only: true and mount only required writable paths."),
    "IG004": ("Health check not explicit", "Add a meaningful healthcheck with timeout and retry limits."),
    "IG005": ("Mutable image reference", "Pin the reviewed image with an immutable sha256 digest."),
    "IG006": ("Port published beyond loopback", "Bind to loopback or document an intentional ingress boundary."),
    "IG007": ("Host namespace shared", "Use isolated network and PID namespaces unless explicitly justified."),
    "IG008": ("Docker socket mounted", "Remove daemon socket access or isolate it behind a restricted service."),
    "IG009": ("Memory limit not explicit", "Set a positive mem_limit or deploy.resources.limits.memory value."),
    "IG010": ("Credential-like literal in environment", "Use a secret reference or environment substitution; rotate exposed credentials."),
}


def _object(value, field):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a mapping.")
    return value


def _loopback(host):
    try:
        return ip_address(str(host).strip("[]")).is_loopback
    except ValueError:
        return False


def _public_port(port):
    if isinstance(port, dict):
        return not _loopback(port.get("host_ip", "0.0.0.0"))
    if isinstance(port, (str, int)) and not isinstance(port, bool):
        parts = str(port).rsplit(":", 2)
        return len(parts) != 3 or not _loopback(parts[0])
    raise ValueError("Port entries must use short or long Compose syntax.")


def _positive_memory(value):
    return bool(re.fullmatch(r"(?:[1-9]\d*(?:\.\d+)?|0\.\d*[1-9]\d*)\s*(?:[kmgt]i?b?)?", str(value).lower()))


def scan(document, source="compose.yaml"):
    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise ValueError("Compose needs a nonempty services mapping.")
    findings = []
    for name, raw_service in services.items():
        if not isinstance(name, str) or not name:
            raise ValueError("Service names must be nonempty strings.")
        service = _object(raw_service, "Service")
        if not service:
            raise ValueError("Services must contain configuration.")

        def add(rule, severity, field, detail=None):
            message, remediation = RULES[rule]
            fingerprint = sha256(f"{source}|{name}|{rule}|{field}".encode()).hexdigest()[:24]
            findings.append(Finding(rule, severity, name, field, detail or message, remediation, fingerprint))

        if service.get("privileged") is True:
            add("IG001", "high", "privileged")
        user = str(service.get("user", "")).split(":")[0]
        if not user or user in {"0", "root"}:
            add("IG002", "high" if user else "medium", "user")
        if service.get("read_only") is not True:
            add("IG003", "medium", "read_only")
        health = _object(service.get("healthcheck"), "healthcheck")
        if not health or health.get("disable") is True or not health.get("test") or health.get("test") in ("NONE", ["NONE"]):
            add("IG004", "medium", "healthcheck")
        image = service.get("image", "")
        if not isinstance(image, str):
            raise ValueError("image must be a string.")
        if image and not re.search(r"@sha256:[0-9a-fA-F]{64}$", image):
            add("IG005", "medium", "image")
        ports = service.get("ports", [])
        if not isinstance(ports, list):
            raise ValueError("ports must be a list.")
        if any(_public_port(port) for port in ports):
            add("IG006", "high", "ports")
        for field in ("network_mode", "pid"):
            if service.get(field) == "host":
                add("IG007", "high", field)
        volumes = service.get("volumes", [])
        if not isinstance(volumes, list):
            raise ValueError("volumes must be a list.")
        for volume in volumes:
            if not isinstance(volume, (str, dict)):
                raise ValueError("Volume entries must use short or long syntax.")
        if any("docker.sock" in (str(volume.get("source", "")) + " " + str(volume.get("target", "")) if isinstance(volume, dict) else volume) for volume in volumes):
            add("IG008", "high", "volumes")
        deploy = _object(service.get("deploy"), "deploy")
        resources = _object(deploy.get("resources"), "resources")
        limits = _object(resources.get("limits"), "limits")
        if not _positive_memory(service.get("mem_limit", limits.get("memory", ""))):
            add("IG009", "medium", "memory")
        environment = service.get("environment", {})
        if isinstance(environment, list):
            if any(not isinstance(entry, str) for entry in environment):
                raise ValueError("Environment list entries must be strings.")
            environment = dict(entry.split("=", 1) if "=" in entry else (entry, None) for entry in environment)
        if not isinstance(environment, dict):
            raise ValueError("environment must be a mapping or list.")
        for key, value in environment.items():
            if re.search(r"(?:PASSWORD|TOKEN|SECRET|API_KEY|PRIVATE_KEY)", str(key), re.I) and not str(key).endswith("_FILE") and value not in (None, "") and "${" not in str(value):
                add("IG010", "high", f"environment.{key}", f"Credential-like environment key {key} has a literal value (redacted).")
    return sorted(findings, key=lambda f: (f.service, f.rule_id, f.field))


def apply_exceptions(findings, entries, today=None):
    today = today or date.today()
    if not isinstance(entries, list):
        raise ValueError("Exceptions must be a JSON list.")
    indexed = {}
    for entry in entries:
        if not isinstance(entry, dict) or any(not isinstance(entry.get(k), str) or not entry[k].strip() for k in ("fingerprint", "owner", "reason", "expires")):
            raise ValueError("Every exception requires fingerprint, owner, reason, and expires strings.")
        if not re.fullmatch(r"[0-9a-f]{24}", entry["fingerprint"]) or len(entry["reason"].strip()) < 10:
            raise ValueError("Exception fingerprint or justification is invalid.")
        try:
            expiry = date.fromisoformat(entry["expires"])
            if expiry.isoformat() != entry["expires"]:
                raise ValueError()
        except ValueError as exc:
            raise ValueError("Exception expiry must be YYYY-MM-DD.") from exc
        if entry["fingerprint"] in indexed:
            raise ValueError("Duplicate exception fingerprint.")
        indexed[entry["fingerprint"]] = (entry, expiry)
    result = []
    for finding in findings:
        if finding.fingerprint in indexed:
            entry, expiry = indexed[finding.fingerprint]
            result.append(replace(finding, suppressed=expiry >= today, exception={**entry, "expired": expiry < today}))
        else:
            result.append(finding)
    return result
