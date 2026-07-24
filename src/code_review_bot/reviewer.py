from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass
from pathlib import Path


SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password)\s*=\s*['\"]([^'\"]{8,})['\"]"
)
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    message: str
    path: str
    line: int
    column: int = 1
    suggestion: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ReviewVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[Finding] = []

    def add(self, node: ast.AST, rule: str, severity: str, message: str, suggestion: str) -> None:
        self.findings.append(Finding(
            rule=rule,
            severity=severity,
            message=message,
            path=self.path,
            line=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", 0) + 1,
            suggestion=suggestion,
        ))

    def visit_Call(self, node: ast.Call) -> None:
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name in {"eval", "exec"}:
            self.add(
                node, "CRB001", "high", f"Dynamic {name}() can execute untrusted code.",
                "Replace it with a parser or an explicit dispatch table.",
            )
        shell_true = any(
            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in node.keywords
        )
        if shell_true:
            self.add(
                node, "CRB002", "high", "Subprocess call enables shell command parsing.",
                "Pass an argument list and keep shell=False.",
            )
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.add(
                node, "CRB003", "medium", "Bare except also catches process-exit signals.",
                "Catch Exception or the narrow exception types you can handle.",
            )
        self.generic_visit(node)

    def _review_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        defaults = [*node.args.defaults, *node.args.kw_defaults]
        if any(isinstance(default, (ast.List, ast.Dict, ast.Set)) for default in defaults if default):
            self.add(
                node, "CRB004", "medium", "Mutable default argument is shared across calls.",
                "Use None as the default and create the value inside the function.",
            )
        end_line = getattr(node, "end_lineno", node.lineno)
        if end_line - node.lineno + 1 > 80:
            self.add(
                node, "CRB005", "low", "Function is longer than 80 lines.",
                "Extract named helpers around distinct responsibilities.",
            )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._review_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._review_function(node)


def review_source(source: str, path: str = "<memory>") -> list[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [Finding(
            rule="CRB000",
            severity="high",
            message=f"Python syntax error: {exc.msg}",
            path=path,
            line=exc.lineno or 1,
            column=exc.offset or 1,
            suggestion="Fix the syntax error before merging.",
        )]

    visitor = ReviewVisitor(path)
    visitor.visit(tree)
    for line_number, line in enumerate(source.splitlines(), 1):
        match = SECRET_RE.search(line)
        if match and not any(marker in line.lower() for marker in ("example", "dummy", "test", "<")):
            visitor.findings.append(Finding(
                rule="CRB006",
                severity="high",
                message=f"Possible hard-coded {match.group(1)}.",
                path=path,
                line=line_number,
                column=match.start(1) + 1,
                suggestion="Load secrets from a secret manager or environment variable.",
            ))
    return sorted(visitor.findings, key=lambda item: (-SEVERITY_ORDER[item.severity], item.line))


def review_path(path: Path) -> list[Finding]:
    files = [path] if path.is_file() else [
        item for item in path.rglob("*.py")
        if not any(part.startswith(".") or part in {"build", "dist"} for part in item.parts)
    ]
    findings: list[Finding] = []
    for file_path in sorted(files):
        try:
            source = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            findings.append(Finding(
                "CRB999", "low", f"Could not read file: {exc}", str(file_path), 1,
                suggestion="Save the file as UTF-8 and check permissions.",
            ))
            continue
        findings.extend(review_source(source, str(file_path)))
    return findings

