"""Static discovery and conservative vulnerability triage for authorized JS/TS source trees."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from tree_sitter import Language, Parser
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts
    TREE_SITTER_AVAILABLE = True
except ImportError:
    Language = None
    Parser = None
    tsjs = None
    tsts = None
    TREE_SITTER_AVAILABLE = False

EXCLUDED_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next", ".nuxt", "vendor"}
TEST_MARKERS = (".test.", ".spec.", "__tests__")
SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx"}
CALL_PATTERN = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
FALLBACK_FUNCTION_PATTERNS = (
    re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?[A-Za-z_$][\w$]*\s*=>\s*\{"),
)
RISK_RULES = [
    ("CWE-89", "critical", ("sequelize.query", "db.query", "SELECT ", "INSERT ", "UPDATE ", "DELETE "), "Raw database query construction may combine SQL with untrusted input."),
    ("CWE-78", "critical", ("child_process.exec", "execSync(", "spawn("), "A process execution sink is present and requires input-flow review."),
    ("CWE-79", "high", ("innerHTML", "dangerouslySetInnerHTML", "document.write"), "An HTML injection sink is present and requires encoding review."),
    ("CWE-95", "critical", ("eval(", "new Function("), "Dynamic code execution is present."),
    ("CWE-601", "high", ("res.redirect", "location.href"), "A redirect sink is present and requires destination validation review."),
    ("CWE-918", "high", ("fetch(", "axios.get", "http.get", "https.get"), "A server-side network request may consume a user-controlled destination."),
]


def source_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        relative = path.relative_to(root)
        relative_text = str(relative).lower()
        if any(part in EXCLUDED_DIRS for part in relative.parts) or any(marker in relative_text for marker in TEST_MARKERS):
            continue
        yield path, relative


def parser_for(suffix: str):
    language = Language(tsts.language_typescript() if suffix in {".ts", ".tsx"} else tsjs.language())
    return Parser(language)


def node_text(source: bytes, node) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def function_name(node, source: bytes, fallback: str) -> str:
    name = node.child_by_field_name("name")
    if name:
        return node_text(source, name)
    parent = node.parent
    if parent and parent.type in {"variable_declarator", "pair", "method_definition"}:
        candidate = parent.child_by_field_name("name") or parent.child_by_field_name("key")
        if candidate:
            return node_text(source, candidate)
    return fallback


def function_record(relative: Path, name: str, code: str, start_line: int, end_line: int) -> dict:
    identity = f"{relative}:{start_line}:{name}"
    calls = [match.group(1) for match in CALL_PATTERN.finditer(code)]
    return {
        "id": hashlib.sha1(identity.encode()).hexdigest()[:12],
        "name": name,
        "filePath": str(relative).replace("\\", "/"),
        "sourceCode": code,
        "startLine": start_line,
        "endLine": end_line,
        "calls": sorted(set(calls)),
    }


def walk_functions_tree_sitter(root: Path) -> list[dict]:
    functions: list[dict] = []
    function_types = {"function_declaration", "function_expression", "arrow_function", "method_definition"}
    for path, relative in source_files(root):
        source = path.read_bytes()
        tree = parser_for(path.suffix.lower()).parse(source)
        stack = [tree.root_node]
        index = 0
        while stack:
            node = stack.pop()
            if node.type in function_types:
                index += 1
                code = node_text(source, node)
                name = function_name(node, source, f"anonymous_{index}")
                calls: list[str] = []
                inner = [node]
                while inner:
                    child = inner.pop()
                    if child is not node and child.type in function_types:
                        continue
                    if child.type == "call_expression":
                        callee = child.child_by_field_name("function")
                        if callee:
                            calls.append(node_text(source, callee))
                    inner.extend(reversed(child.children))
                record = function_record(relative, name, code, node.start_point.row + 1, node.end_point.row + 1)
                record["calls"] = sorted(set(calls))
                functions.append(record)
                continue
            stack.extend(reversed(node.children))
    return functions


def matching_brace(source: str, opening: int) -> int:
    depth = 0
    quote = None
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {"'", '"', "`"}:
            quote = char
        elif char == "/" and next_char == "/":
            newline = source.find("\n", index + 2)
            index = len(source) if newline == -1 else newline
        elif char == "/" and next_char == "*":
            closing = source.find("*/", index + 2)
            index = len(source) if closing == -1 else closing + 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return len(source) - 1


def walk_functions_fallback(root: Path) -> list[dict]:
    functions: list[dict] = []
    for path, relative in source_files(root):
        source = path.read_text(encoding="utf-8", errors="replace")
        matches = []
        for pattern in FALLBACK_FUNCTION_PATTERNS:
            matches.extend(pattern.finditer(source))
        occupied_until = -1
        for match in sorted(matches, key=lambda item: item.start()):
            if match.start() < occupied_until:
                continue
            opening = source.find("{", match.start(), match.end() + 1)
            if opening == -1:
                continue
            closing = matching_brace(source, opening)
            code = source[match.start():closing + 1]
            start_line = source.count("\n", 0, match.start()) + 1
            end_line = source.count("\n", 0, closing) + 1
            functions.append(function_record(relative, match.group(1), code, start_line, end_line))
            occupied_until = closing + 1
    return functions


def triage(function: dict) -> dict | None:
    code = function["sourceCode"]
    lowered = code.lower()
    input_markers = ("req.body", "req.query", "req.params", "request.", "ctx.request", "process.env")
    has_input = any(marker.lower() in lowered for marker in input_markers)
    for cwe, confidence, patterns, reason in RISK_RULES:
        if any(pattern.lower() in lowered for pattern in patterns):
            verdict = "likely_vulnerable" if has_input and confidence == "critical" else "needs_review"
            return {
                "pass1_hypothesis": {"vulnerable": True, "cwe_guess": cwe, "reasoning": reason, "confidence": confidence},
                "pass2_triage": {
                    "verdict": verdict,
                    "explanation": "A risky sink was found. The second pass checked for nearby request-derived input; manual data-flow verification is still required.",
                    "recommendation": "Trace the value into this sink, verify validation or parameterization, and record the result through manual review. Do not execute payloads from this pipeline.",
                    "status": "pending",
                },
            }
    return None


def build_graph(functions: list[dict]) -> dict:
    edges: set[tuple[str, str]] = set()
    by_name = {item["name"]: item for item in functions}
    for item in functions:
        for call in item.pop("calls"):
            target = by_name.get(call.split(".")[-1])
            if target and target["id"] != item["id"]:
                edges.add((item["id"], target["id"]))
        finding = triage(item)
        if finding:
            item["vulnerability"] = finding
    return {
        "nodes": functions,
        "edges": [{"source": source, "target": target} for source, target in sorted(edges)],
    }


def materialize(target_type: str, source: str) -> tuple[Path, tempfile.TemporaryDirectory | None]:
    if target_type == "local":
        path = Path(source).expanduser().resolve()
        if not path.is_dir():
            raise ValueError("Local target must be an existing directory")
        return path, None
    temp = tempfile.TemporaryDirectory(prefix="aegis-target-")
    destination = Path(temp.name) / "source"
    subprocess.run(["git", "clone", "--depth", "1", "--", source, str(destination)], check=True, timeout=180, capture_output=True, text=True)
    return destination, temp


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-type", choices=("repository", "local"), required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    root, temp = materialize(args.target_type, args.source)
    try:
        parser_mode = "tree-sitter" if TREE_SITTER_AVAILABLE else "built-in fallback"
        functions = walk_functions_tree_sitter(root) if TREE_SITTER_AVAILABLE else walk_functions_fallback(root)
        result = build_graph(functions)
        result["summary"] = {
            "filesRoot": str(root),
            "functions": len(functions),
            "findings": sum(1 for item in functions if "vulnerability" in item),
            "parserMode": parser_mode,
            "warning": None if TREE_SITTER_AVAILABLE else "tree-sitter packages are unavailable; results were produced with the conservative built-in parser.",
        }
        print(json.dumps(result))
    finally:
        if temp:
            temp.cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        sys.exit(1)
