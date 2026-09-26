# Design and scope

The pipeline is parse, validate supported shapes, evaluate rules, apply dated exceptions, render, then compute the gate. Parsing uses a safe YAML loader with duplicate-key rejection. Rule evaluation operates only on explicit service fields. It never interpolates environment variables, reads env_file references, executes Compose, or contacts registries.

The finding model separates remediation from presentation. JSON supports automation, Markdown supports human review, and SARIF supports compatible code-scanning consumers. Findings use a source-path/service/rule/field fingerprint, not a hash of the entire input. Unrelated configuration edits therefore do not invalidate an exception.

High severity means potentially consequential access or exposure (privilege, root, broad ports, host namespaces, daemon socket, credential-like literal). Medium means a missing explicit hardening or reliability control. These severities are project policy, not vendor compliance scores. IG010 only matches key names and omits literal values from every renderer.

Expiry evaluation uses UTC at the CLI boundary; tests inject a date to cover exact expiry-day semantics. Expired exceptions remain attached to their findings for review but no longer suppress the gate. Unknown fingerprints have no effect. Exception authorization is a code-review responsibility; the tool does not authenticate an owner string.

Current limits: single-file Compose input under 2 MB, no image metadata, no YAML merge override semantics (normalize configuration first), no complete schema validation, no Kubernetes or Terraform checks. A clean result means the supported rules found nothing, not that an environment is safe. Memory and user checks deliberately favor explicit configuration over assumptions about images.

Potential next steps: schema-backed validation, source line mapping, custom policy bundles, and tests against real normalized Compose outputs. None are represented as implemented features.
