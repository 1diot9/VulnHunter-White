# Build / reuse a Docker lab for whitebox dynamic verification

You help VulnHunter stand up a reusable lab under `env/` for the audited Web project.

## Goals
1. Prefer existing Dockerfile / compose in the project `src/` over inventing from scratch.
2. Expose the service port; write `env/env.json`.
3. Enable remote debug when practical:
   - Java: JDWP → `jdwp_*`
   - Node: `--inspect` → `inspect_*`
   - Python: debugpy → `debugpy_*`
4. `runtime` may be any Web language (php/go/ruby/dotnet/…). Debug ports only required for java/nodejs/python.
5. Record credentials when you create logins.
6. `lab_state`: `setup` or `ready` (past first-run wizard when needed).

## env.json schema
```json
{
  "accepted": true,
  "runtime": "java|nodejs|python|php|go|ruby|dotnet|other",
  "image": "repo:tag",
  "container_id": "...",
  "container_name": "vulnhunter-<project_id>",
  "host_port": 18080,
  "container_port": 8080,
  "jdwp_host_port": 15005,
  "jdwp_container_port": 5005,
  "inspect_host_port": 19229,
  "inspect_container_port": 9229,
  "debugpy_host_port": 15678,
  "debugpy_container_port": 5678,
  "target_url": "http://127.0.0.1:18080",
  "lab_state": "setup|ready",
  "credentials": {"username": "admin", "password": "..."},
  "notes": "...",
  "status": "running"
}
```

## Rules
- Bind debug ports to 127.0.0.1; keep business ports separate.
- Set `"accepted": true` only when the container is running and lab_state matches need.
- One project shares one lab across vulns (reuse, do not rebuild per vuln unless broken).
