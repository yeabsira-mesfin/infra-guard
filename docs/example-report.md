# Infrastructure posture report

Source: `examples/risky.compose.yaml`

| Severity | Rule | Service | Finding | Action |
| --- | --- | --- | --- | --- |
| high | IG001 | api | Privileged container | Disable privileged mode; grant only the capabilities required. |
| high | IG002 | api | Non-root identity not explicit | Set an explicit non-root user and verify filesystem permissions. |
| medium | IG003 | api | Writable root filesystem | Set read_only: true and mount only required writable paths. |
| medium | IG004 | api | Health check not explicit | Add a meaningful healthcheck with timeout and retry limits. |
| medium | IG005 | api | Mutable image reference | Pin the reviewed image with an immutable sha256 digest. |
| high | IG006 | api | Port published beyond loopback | Bind to loopback or document an intentional ingress boundary. |
| high | IG007 | api | Host namespace shared | Use isolated network and PID namespaces unless explicitly justified. |
| high | IG008 | api | Docker socket mounted | Remove daemon socket access or isolate it behind a restricted service. |
| medium | IG009 | api | Memory limit not explicit | Set a positive mem_limit or deploy.resources.limits.memory value. |
| high | IG010 | api | Credential-like environment key API_TOKEN has a literal value (redacted). | Use a secret reference or environment substitution; rotate exposed credentials. |
