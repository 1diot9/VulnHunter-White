"""Reject harness scripts whose final output is canned success instead of runtime data."""

from __future__ import annotations

import ast
import re

HARNESS_OUTPUT_ERROR = (
    "harness 最终输出必须来自运行时的实际数据（调用抽出函数/sink 后的返回值、查询结果、"
    "命令回显、渲染 HTML、异常原文等）。"
    "禁止只打印固定字符串（如 VULNERABILITY CONFIRMED / SUCCESS），"
    "禁止写死成功字段（success=True、{\"success\": true}），"
    "禁止把预期回显写成字面量。判定标签可以有，但必须同时打印实际数据。"
)

_VERDICT_KEYS = frozenset(
    {
        "success",
        "ok",
        "confirmed",
        "vulnerable",
        "passed",
        "pass",
        "hit",
        "exploitable",
        "is_vuln",
        "vuln",
    }
)
_PURE_BUILTINS = frozenset(
    {
        "abs",
        "all",
        "any",
        "ascii",
        "bin",
        "bool",
        "bytes",
        "chr",
        "dict",
        "divmod",
        "enumerate",
        "float",
        "format",
        "frozenset",
        "getattr",
        "hasattr",
        "hash",
        "hex",
        "id",
        "int",
        "isinstance",
        "iter",
        "len",
        "list",
        "max",
        "min",
        "next",
        "object",
        "oct",
        "ord",
        "pow",
        "print",
        "property",
        "range",
        "repr",
        "reversed",
        "round",
        "set",
        "slice",
        "sorted",
        "staticmethod",
        "str",
        "sum",
        "super",
        "tuple",
        "type",
        "zip",
    }
)
_FAKE_EVIDENCE_RE = re.compile(
    r"(?i)uid=\d+\(|gid=\d+\(|root:x:0:0|root:[*$]|Pwned by "
)
_FIXED_VERDICT_STR_RE = re.compile(
    r"""(?ix)
    ["']?(?:success|ok|confirmed|vulnerable|passed|exploitable|is_vuln)["']?
    \s*[:=]\s*true
    """
)
_FIXED_JSON_TRUE_RE = re.compile(
    r'''(?i)["'](?:success|ok|confirmed|vulnerable|passed|exploitable|is_vuln)["']\s*:\s*true'''
)
_INTERP_RE = re.compile(
    r"""(?x)
    (?:
        \$\{?[A-Za-z_][\w]*\}?
        | \{[A-Za-z_][\w.]*\}
        | %[-+#0\s]?\d*[sdvfexqwt]
        | (?:print|println|printf|puts|echo|console\.log|System\.out\.print(?:ln)?
            | fmt\.Print[lf]?n? | var_dump | var_export)\s*\(\s*[A-Za-z_$]
        | echo\s+"?\$
        | puts\s+[A-Za-z_@$]
        | \+\s*[A-Za-z_$]
        | ,\s*[A-Za-z_$]
        | \.\s*\$[A-Za-z_]
        | \#\{[A-Za-z_]
    )
    """,
    re.I,
)


_OUTPUT_CALL_RE = re.compile(
    r"(?is)(?:console\.log|System\.out\.print(?:ln)?|fmt\.Print[lf]?n?|"
    r"var_dump|var_export|printf|println|print|echo|puts)\s*[\(\s]([^;\n]*)"
)


def harness_output_block_reason(code: str | None, *, language: str | None = None) -> str | None:
    """Return an error if the harness prints canned success instead of runtime evidence."""
    text = code or ""
    if not text.strip():
        return None
    lang = (language or "python").strip().lower()
    if lang in {"python", "python3", "py"}:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return _generic_block_reason(text)
        if _PythonHarnessOutput(tree).blocked():
            return HARNESS_OUTPUT_ERROR
        return None
    return _generic_block_reason(text)


def _generic_block_reason(text: str) -> str | None:
    calls = list(_OUTPUT_CALL_RE.finditer(text))
    if not calls:
        return HARNESS_OUTPUT_ERROR
    printed = " ".join(match.group(1) or "" for match in calls)
    if _FIXED_JSON_TRUE_RE.search(printed) or _FIXED_VERDICT_STR_RE.search(printed):
        return HARNESS_OUTPUT_ERROR
    if _FAKE_EVIDENCE_RE.search(printed):
        return HARNESS_OUTPUT_ERROR
    if not _INTERP_RE.search(printed):
        return HARNESS_OUTPUT_ERROR
    return None


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _const_bool(node: ast.AST | None) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


class _PythonHarnessOutput(ast.NodeVisitor):
    def __init__(self, tree: ast.AST) -> None:
        self.runtime: set[str] = set()
        self.assigned: dict[str, ast.AST] = {}
        self.evidence_prints = 0
        self.hardcoded_verdict = False
        self.fabricated = False
        self.visit(tree)

    def blocked(self) -> bool:
        return self.hardcoded_verdict or self.fabricated or self.evidence_prints <= 0

    def visit_Assign(self, node: ast.Assign) -> None:
        runtime = self._is_runtime(node.value)
        for target in node.targets:
            self._mark(target, runtime, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._mark(node.target, self._is_runtime(node.value), node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        runtime = self._is_runtime(node.target) or self._is_runtime(node.value)
        self._mark(node.target, runtime, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._mark(node.target, self._is_runtime(node.iter), node.iter)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._mark(
                    item.optional_vars,
                    self._is_runtime(item.context_expr),
                    item.context_expr,
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in {"append", "extend", "add"}
            and isinstance(func.value, ast.Name)
            and any(self._is_runtime(arg) for arg in node.args)
        ):
            self.runtime.add(func.value.id)
        if self._is_print_like(node):
            self._inspect_output(node)
        self.generic_visit(node)

    def _mark(self, target: ast.AST, runtime: bool, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.assigned[target.id] = value
            if runtime:
                self.runtime.add(target.id)
            else:
                self.runtime.discard(target.id)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            elts = list(target.elts)
            if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(elts):
                for sub, item in zip(elts, value.elts):
                    self._mark(sub, self._is_runtime(item), item)
                return
            for sub in elts:
                self._mark(sub, runtime, value)
            return
        if isinstance(target, ast.Starred):
            self._mark(target.value, runtime, value)

    def _is_print_like(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"print", "pprint"}:
            return True
        if isinstance(func, ast.Attribute) and func.attr in {"write", "writelines"}:
            owner = func.value
            if isinstance(owner, ast.Attribute) and owner.attr in {"stdout", "stderr"}:
                return True
        return False

    def _inspect_output(self, node: ast.Call) -> None:
        args = list(node.args)
        for kw in node.keywords:
            if kw.value is not None:
                args.append(kw.value)
        for arg in args:
            dumped = self._dumps_payload(arg)
            target = dumped if dumped is not None else arg
            if self._has_fixed_verdict(target):
                self.hardcoded_verdict = True
            if self._is_fabricated(target):
                self.fabricated = True
            if self._is_evidence(target):
                self.evidence_prints += 1

    def _dumps_payload(self, node: ast.AST) -> ast.AST | None:
        if not isinstance(node, ast.Call):
            return None
        func = node.func
        name = ""
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name not in {"dumps", "dump"} or not node.args:
            return None
        payload = node.args[0]
        if isinstance(payload, ast.Name):
            return self.assigned.get(payload.id, payload)
        return payload

    def _has_fixed_verdict(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            assigned = self.assigned.get(node.id)
            if assigned is not None and assigned is not node:
                return self._has_fixed_verdict(assigned)
            return False
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                label = (_const_str(key) or "").strip().lower()
                if label in _VERDICT_KEYS and _const_bool(value) is True:
                    return True
            return False
        text = _const_str(node)
        if text and _FIXED_VERDICT_STR_RE.search(text):
            return True
        if isinstance(node, ast.JoinedStr):
            return any(
                self._has_fixed_verdict(part.value)
                if isinstance(part, ast.FormattedValue)
                else self._has_fixed_verdict(part)
                for part in node.values
            )
        return False

    def _is_fabricated(self, node: ast.AST) -> bool:
        text = _const_str(node)
        if text and _FAKE_EVIDENCE_RE.search(text):
            return True
        if isinstance(node, ast.JoinedStr):
            return any(
                isinstance(part, ast.Constant)
                and isinstance(part.value, str)
                and _FAKE_EVIDENCE_RE.search(part.value)
                for part in node.values
            )
        return False

    def _is_verdict(self, node: ast.AST) -> bool:
        if _const_bool(node) is not None:
            return True
        if isinstance(node, (ast.Compare, ast.BoolOp)):
            return True
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "bool":
            return True
        if isinstance(node, ast.Name):
            assigned = self.assigned.get(node.id)
            if assigned is not None and assigned is not node:
                return self._is_verdict(assigned)
        return False

    def _is_evidence(self, node: ast.AST) -> bool:
        if self._is_verdict(node) or isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.JoinedStr):
            return any(
                self._is_evidence(part.value)
                for part in node.values
                if isinstance(part, ast.FormattedValue)
            )
        if isinstance(node, ast.Name):
            assigned = self.assigned.get(node.id)
            if assigned is not None and self._is_verdict(assigned):
                return False
            return node.id in self.runtime
        return self._is_runtime(node) and not self._is_verdict(node)

    def _is_runtime_call(self, node: ast.Call) -> bool:
        args_runtime = any(self._is_runtime(arg) for arg in node.args)
        args_runtime = args_runtime or any(
            kw.value is not None and self._is_runtime(kw.value) for kw in node.keywords
        )
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in _PURE_BUILTINS:
                return args_runtime
            return True
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Constant):
                return args_runtime
            return True
        return True

    def _is_runtime(self, node: ast.AST | None) -> bool:
        if node is None or isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.runtime
        if isinstance(node, ast.Call):
            return self._is_runtime_call(node)
        if isinstance(node, ast.Attribute):
            return self._is_runtime(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_runtime(node.value) or self._is_runtime(node.slice)
        if isinstance(node, ast.Slice):
            return any(self._is_runtime(part) for part in (node.lower, node.upper, node.step))
        if isinstance(node, ast.JoinedStr):
            return any(
                self._is_runtime(part.value)
                for part in node.values
                if isinstance(part, ast.FormattedValue)
            )
        if isinstance(node, ast.FormattedValue):
            return self._is_runtime(node.value)
        if isinstance(node, ast.Starred):
            return self._is_runtime(node.value)
        if isinstance(node, ast.NamedExpr):
            runtime = self._is_runtime(node.value)
            self._mark(node.target, runtime, node.value)
            return runtime
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._is_runtime(node.elt) or any(
                self._is_runtime(gen.iter) for gen in node.generators
            )
        if isinstance(node, ast.DictComp):
            return (
                self._is_runtime(node.key)
                or self._is_runtime(node.value)
                or any(self._is_runtime(gen.iter) for gen in node.generators)
            )
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_runtime(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._is_runtime(elt) for elt in (*node.keys, *node.values) if elt is not None)
        return any(self._is_runtime(child) for child in ast.iter_child_nodes(node))
