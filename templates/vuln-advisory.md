# GitHub Security Advisory

English fill-in for the GitHub Advisory form. Copy from `### Summary` through Impact into the Description field. Leave Patched versions empty if there is no upstream fix.

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

(HTTP request(s) and/or a minimal Python snippet. Contrast blocked vs accepted responses when that proves the bypass.)

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
- **CVSS 3.1:**
- **CWE:**
- **Related:**
