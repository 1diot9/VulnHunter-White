# GitHub Security Advisory

Write all fill-in content in English (GitHub Advisory form). Do not use Chinese in Title, Description, or Severity notes. Copy from `### Summary` through Impact into the Description field. Leave Patched versions empty if there is no upstream fix.

Do not render this file as HTML in the product UI; keep it as copy-paste Markdown source.

---

## Title

```
{{title}}
```

---

## Description

Copy from the next `### Summary` through the end of Impact.

### Summary

(One short paragraph: what a low-privilege caller can do, which endpoint/field, and why existing checks do not stop it.)

### Details

(Root cause, file/function, the intended control that was skipped, auth preconditions, same-root-cause siblings, and a concrete suggested fix.)

### PoC

Requires a running instance you are authorized to test. Do not include real secrets.

**Must include at least one raw HTTP request packet** in a `http` fenced block (method, path, headers, and body if any). Do not rely on curl one-liners or screenshots alone. Contrast blocked vs accepted requests/responses when that proves the bypass.

For header or body values that are long (roughly 80+ characters, e.g. Base64 blobs, serialized gadgets, JWTs), replace the long portion with a short descriptive placeholder such as `<BASE64_PAYLOAD>`, `<JWT_TOKEN>`, or `<SERIALIZED_GADGET>` while keeping the surrounding structure and short attack primitives intact.

Optionally reference the reproducible CLI script in the same directory (`python poc.py -u http://TARGET:PORT`; add `--proxy` when needed).

```http

```

Do not run this against systems you do not own or have authorization to test.

### Impact

(CWE, who is affected, who can exploit it, what it enables. State remaining controls honestly; do not overclaim.)

---

## Affected products

| Field | Value |
| --- | --- |
| Ecosystem | `pip` / `npm` / … |
| Package name | |
| Affected versions | |
| Patched versions | (leave empty if unpatched) |

---

## Severity / CWE

- **Severity:** Low / Moderate / High / Critical
- **CVSS 3.1:** (base score + severity, e.g. 9.8 Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **CVSS 4.0:** (base score + severity, e.g. 9.3 Critical) — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`
- **CWE:**
- **Related:**
