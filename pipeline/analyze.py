"""Static discovery and conservative vulnerability triage for authorized JS/TS source trees."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import networkx as nx
from tree_sitter import Language, Parser
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

EXCLUDED_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next", ".nuxt", "vendor"}
TEST_MARKERS = (".test.", ".spec.", "__tests__")
RISK_RULES = [
    ("CWE-89", "critical", ("sequelize.query", "db.query", "SELECT ", "INSERT ", "UPDATE ", "DELETE "), "Raw database query construction may combine SQL with untrusted input."),
    ("CWE-78", "critical", ("child_process.exec", "execSync(", "spawn("), "A process execution sink is present and requires input-flow review."),
    ("CWE-79", "high", ("innerHTML", "dangerouslySetInnerHTML", "document.write"), "An HTML injection sink is present and requires encoding review."),
    ("CWE-95", "critical", ("eval(", "new Function("), "Dynamic code execution is present."),
    ("CWE-601", "high", ("res.redirect", "location.href"), "A redirect sink is present and requires destination validation review."),
    ("CWE-918", "high", ("fetch(", "axios.get", "http.get", "https.get"), "A server-side network request may consume a user-controlled destination."),
]


def parser_for(suffix: str) -> Parser:
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


def walk_functions(root: Path) -> list[dict]:
    functions: list[dict] = []
    function_types = {"function_declaration", "function_expression", "arrow_function", "method_definition"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx"}:
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in relative.parts) or any(marker in str(relative).lower() for marker in TEST_MARKERS):
            continue
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
                identity = f"{relative}:{node.start_point.row + 1}:{name}"
                functions.append({
                    "id": hashlib.sha1(identity.encode()).hexdigest()[:12],
                    "name": name,
                    "filePath": str(relative).replace("\\", "/"),
                    "sourceCode": code,
                    "startLine": node.start_point.row + 1,
                    "endLine": node.end_point.row + 1,
                    "calls": sorted(set(calls)),
                })
                continue
            stack.extend(reversed(node.children))
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
    graph = nx.DiGraph()
    by_name = {item["name"]: item for item in functions}
    for item in functions:
        graph.add_node(item["id"])
    for item in functions:
        for call in item.pop("calls"):
            target_name = call.split(".")[-1]
            target = by_name.get(target_name)
            if target and target["id"] != item["id"]:
                graph.add_edge(item["id"], target["id"])
        finding = triage(item)
        if finding:
            item["vulnerability"] = finding
    return {"nodes": functions, "edges": [{"source": source, "target": target} for source, target in graph.edges()]}


def materialize(target_type: str, source: str) -> tuple[Path, tempfile.TemporaryDirectory | None]:
    if target_type == "local":
        path = Path(source).expanduser().resolve()
        if not path.is_dir():
            raise ValueError("Local target must be an existing directory")
        return path, None
    temp = tempfile.TemporaryDirectory(prefix="aegis-target-")
    destination = Path(temp.name) / "source"
    subprocess.run(["git", "clone", "--depth", "1", "--", source, str(destination)], check=True, timeout=180)
    return destination, temp


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-type", choices=("repository", "local"), required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    root, temp = materialize(args.target_type, args.source)
    try:
        functions = walk_functions(root)
        result = build_graph(functions)
        result["summary"] = {"filesRoot": str(root), "functions": len(functions), "findings": sum(1 for item in functions if "vulnerability" in item)}
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
