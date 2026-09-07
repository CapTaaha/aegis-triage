"""Authorized JS/TS source discovery with conservative OWASP-oriented taint analysis."""

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
    Language = Parser = tsjs = tsts = None
    TREE_SITTER_AVAILABLE = False

EXCLUDED_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next", ".nuxt", "vendor", "public"}
TEST_MARKERS = (".test.", ".spec.", "__tests__", "fixtures", "mocks")
SOURCE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
CALL_PATTERN = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
ASSIGNMENT_PATTERN = re.compile(r"\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)")
FALLBACK_FUNCTION_PATTERNS = (
    re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?[A-Za-z_$][\w$]*\s*=>\s*\{"),
)

SOURCES = {
    "HTTP request body": (r"\breq(?:uest)?\.body\b", r"\bevent\.body\b", r"\bctx\.request\.body\b"),
    "URL/query input": (r"\breq(?:uest)?\.(?:query|params)\b", r"URLSearchParams", r"useSearchParams\s*\(", r"location\.(?:search|hash)"),
    "HTTP headers/cookies": (r"\breq(?:uest)?\.(?:headers|cookies)\b", r"getCookie\s*\(", r"getRequestHeaders\s*\("),
    "Uploaded file metadata": (r"\breq(?:uest)?\.(?:file|files)\b", r"multer\s*\("),
    "Message/browser storage": (r"\.data\b", r"localStorage\.getItem", r"sessionStorage\.getItem"),
    "Environment/config input": (r"process\.env\b", r"useRuntimeConfig\s*\("),
}

SANITIZERS = {
    "HTML encoding": (r"DOMPurify\.sanitize", r"sanitizeHtml", r"escapeHtml", r"encodeForHTML"),
    "URL allowlist": (r"isAllowedUrl", r"isUrlToRedirect", r"allowedHosts?", r"new URL\s*\("),
    "Path normalization": (r"path\.(?:normalize|resolve|basename)", r"sanitizeFilename"),
    "SQL parameterization": (r"\breplacements\s*:", r"\bbind\s*:", r"\.prepare\s*\(", r"\$[1-9]\b", r"\?"),
    "Schema validation": (r"\.parse\s*\(", r"\.safeParse\s*\(", r"validate\s*\(", r"Joi\.", r"z\.object"),
}

RULES = [
    {"id": "AT-SQLI", "cwe": "CWE-89", "owasp": "A03:2021 Injection", "category": "SQL injection", "confidence": "critical", "taint": True, "sinks": (r"sequelize\.query\s*\(", r"(?:db|connection|client)\.(?:query|execute)\s*\(", r"\$queryRawUnsafe\s*\(", r"knex\.raw\s*\("), "reason": "Untrusted input may reach a raw SQL execution sink."},
    {"id": "AT-NOSQL", "cwe": "CWE-943", "owasp": "A03:2021 Injection", "category": "NoSQL injection", "confidence": "high", "taint": True, "sinks": (r"\.(?:find|findOne|update|remove|deleteMany)\s*\(", r"\$where\b"), "reason": "Untrusted input may be used as a NoSQL query object or operator."},
    {"id": "AT-CMD", "cwe": "CWE-78", "owasp": "A03:2021 Injection", "category": "OS command injection", "confidence": "critical", "taint": True, "sinks": (r"child_process\.(?:exec|execSync|spawn)\s*\(", r"\bexec(?:Sync)?\s*\(", r"shell\s*:\s*true"), "reason": "Untrusted input may reach an operating-system command sink."},
    {"id": "AT-XSS-DOM", "cwe": "CWE-79", "owasp": "A03:2021 Injection", "category": "Cross-site scripting", "confidence": "high", "taint": True, "sinks": (r"\.innerHTML\s*=", r"dangerouslySetInnerHTML", r"document\.write\s*\(", r"\.insertAdjacentHTML\s*\("), "reason": "Untrusted input may reach an HTML execution context without encoding."},
    {"id": "AT-XSS-RESP", "cwe": "CWE-79", "owasp": "A03:2021 Injection", "category": "Reflected cross-site scripting", "confidence": "high", "taint": True, "sinks": (r"res\.(?:send|write|end)\s*\(", r"reply\.send\s*\("), "reason": "Untrusted input may be written directly into an HTTP response."},
    {"id": "AT-SSRF", "cwe": "CWE-918", "owasp": "A10:2021 SSRF", "category": "Server-side request forgery", "confidence": "high", "taint": True, "sinks": (r"\bfetch\s*\(", r"axios\.(?:get|post|request)\s*\(", r"https?\.(?:get|request)\s*\(", r"got\s*\("), "reason": "A user-controlled destination may reach a server-side network request."},
    {"id": "AT-PATH", "cwe": "CWE-22", "owasp": "A01:2021 Broken Access Control", "category": "Path traversal", "confidence": "high", "taint": True, "sinks": (r"fs\.(?:readFile|writeFile|createReadStream|createWriteStream|unlink)\s*\(", r"sendFile\s*\(", r"res\.download\s*\("), "reason": "Untrusted input may control a filesystem path."},
    {"id": "AT-REDIRECT", "cwe": "CWE-601", "owasp": "A01:2021 Broken Access Control", "category": "Open redirect", "confidence": "high", "taint": True, "sinks": (r"res\.redirect\s*\(", r"location\.(?:href|assign|replace)\s*[=(]"), "reason": "Untrusted input may control a redirect destination."},
    {"id": "AT-TEMPLATE", "cwe": "CWE-1336", "owasp": "A03:2021 Injection", "category": "Template injection", "confidence": "high", "taint": True, "sinks": (r"renderString\s*\(", r"compile\s*\(", r"ejs\.render\s*\("), "reason": "Untrusted input may be interpreted as a server-side template."},
    {"id": "AT-DESERIALIZE", "cwe": "CWE-502", "owasp": "A08:2021 Software and Data Integrity Failures", "category": "Unsafe deserialization", "confidence": "high", "taint": True, "sinks": (r"serialize-javascript", r"node-serialize", r"yaml\.(?:load|parse)\s*\(", r"unserialize\s*\("), "reason": "Untrusted data may reach an unsafe deserialization operation."},
    {"id": "AT-POLLUTION", "cwe": "CWE-1321", "owasp": "A03:2021 Injection", "category": "Prototype pollution", "confidence": "high", "taint": True, "sinks": (r"Object\.assign\s*\(", r"lodash\.merge\s*\(", r"\.set\s*\([^,]+,"), "reason": "Untrusted object keys may reach a recursive merge or property assignment."},
    {"id": "AT-EVAL", "cwe": "CWE-95", "owasp": "A03:2021 Injection", "category": "Code injection", "confidence": "critical", "taint": True, "sinks": (r"\beval\s*\(", r"new Function\s*\(", r"vm\.runIn"), "reason": "Untrusted input may reach dynamic code evaluation."},
    {"id": "AT-WEAK-CRYPTO", "cwe": "CWE-327", "owasp": "A02:2021 Cryptographic Failures", "category": "Weak cryptography", "confidence": "medium", "taint": False, "sinks": (r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]", r"Math\.random\s*\(.*(?:token|secret|password)"), "reason": "A weak cryptographic primitive appears in a security-sensitive operation."},
    {"id": "AT-SECRET", "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures", "category": "Hard-coded secret", "confidence": "high", "taint": False, "sinks": (r"(?:api[_-]?key|secret|password|private[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",), "reason": "A credential-like value appears to be hard-coded in source."},
    {"id": "AT-JWT", "cwe": "CWE-347", "owasp": "A07:2021 Identification and Authentication Failures", "category": "JWT verification weakness", "confidence": "high", "taint": False, "sinks": (r"algorithms\s*:\s*\[?\s*['\"]none", r"jwt\.decode\s*\("), "reason": "JWT handling may accept unsigned data or decode without verification."},
    {"id": "AT-CORS", "cwe": "CWE-942", "owasp": "A05:2021 Security Misconfiguration", "category": "Permissive CORS", "confidence": "medium", "taint": False, "sinks": (r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*", r"cors\s*\(\s*\{[^}]*origin\s*:\s*true"), "reason": "Cross-origin access appears broadly permitted."},
    {"id": "AT-COOKIE", "cwe": "CWE-614", "owasp": "A05:2021 Security Misconfiguration", "category": "Insecure session cookie", "confidence": "medium", "taint": False, "sinks": (r"httpOnly\s*:\s*false", r"secure\s*:\s*false", r"sameSite\s*:\s*['\"]none['\"]"), "reason": "Cookie configuration may weaken session confidentiality or browser isolation."},
    {"id": "AT-UPLOAD", "cwe": "CWE-434", "owasp": "A04:2021 Insecure Design", "category": "Unrestricted file upload", "confidence": "high", "taint": True, "sinks": (r"\.mv\s*\(", r"writeFile\s*\(", r"diskStorage\s*\("), "reason": "Uploaded file data or names may reach persistent storage without clear restrictions."},
]


def source_files(root: Path):
    root = root.resolve()
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            resolved = path.resolve(strict=True)
            relative = resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        relative_text = str(relative).lower()
        if any(part in EXCLUDED_DIRS for part in relative.parts) or any(marker in relative_text for marker in TEST_MARKERS):
            continue
        yield resolved, relative


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
    route_pattern = re.compile(r"\.(?:get|post|put|patch|delete|use)\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
    routes = sorted(set(match.group(1) for match in route_pattern.finditer(code)))
    return {"id": hashlib.sha1(identity.encode()).hexdigest()[:12], "name": name, "filePath": str(relative).replace("\\", "/"), "sourceCode": code, "startLine": start_line, "endLine": end_line, "calls": sorted(set(match.group(1) for match in CALL_PATTERN.finditer(code))), "routes": routes}


def redact_secrets(text: str) -> str:
    redacted = re.sub(r"(?i)((?:api[_-]?key|secret|password|token|authorization)\s*[:=]\s*)['\"][^'\"]+['\"]", r'\1"[REDACTED]"', text)
    redacted = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1[REDACTED]", redacted)
    redacted = re.sub(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", "[REDACTED PRIVATE KEY]", redacted, flags=re.S)
    return redacted


def walk_functions_tree_sitter(root: Path) -> tuple[list[dict], int]:
    functions: list[dict] = []
    files = 0
    function_types = {"function_declaration", "function_expression", "arrow_function", "method_definition"}
    for path, relative in source_files(root):
        files += 1
        source = path.read_bytes()
        tree = parser_for(path.suffix.lower()).parse(source)
        stack = [tree.root_node]
        index = 0
        found = 0
        while stack:
            node = stack.pop()
            if node.type in function_types:
                index += 1
                found += 1
                code = node_text(source, node)
                name = function_name(node, source, f"anonymous_{index}")
                record = function_record(relative, name, code, node.start_point.row + 1, node.end_point.row + 1)
                inner = [node]
                calls = []
                while inner:
                    child = inner.pop()
                    if child is not node and child.type in function_types:
                        continue
                    if child.type == "call_expression":
                        callee = child.child_by_field_name("function")
                        if callee:
                            calls.append(node_text(source, callee))
                    inner.extend(reversed(child.children))
                record["calls"] = sorted(set(calls))
                functions.append(record)
                continue
            stack.extend(reversed(node.children))
        if found == 0 and source.strip():
            functions.append(function_record(relative, f"module::{relative.name}", source.decode("utf-8", errors="replace"), 1, source.count(b"\n") + 1))
    return functions, files


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


def walk_functions_fallback(root: Path) -> tuple[list[dict], int]:
    functions: list[dict] = []
    files = 0
    for path, relative in source_files(root):
        files += 1
        source = path.read_text(encoding="utf-8", errors="replace")
        matches = sorted([match for pattern in FALLBACK_FUNCTION_PATTERNS for match in pattern.finditer(source)], key=lambda item: item.start())
        occupied_until = -1
        found = 0
        for match in matches:
            if match.start() < occupied_until:
                continue
            opening = source.find("{", match.start(), match.end() + 1)
            if opening == -1:
                continue
            closing = matching_brace(source, opening)
            start_line = source.count("\n", 0, match.start()) + 1
            end_line = source.count("\n", 0, closing) + 1
            functions.append(function_record(relative, match.group(1), source[match.start():closing + 1], start_line, end_line))
            occupied_until = closing + 1
            found += 1
        if found == 0 and source.strip():
            functions.append(function_record(relative, f"module::{relative.name}", source, 1, source.count("\n") + 1))
    return functions, files


def matching_sources(code: str) -> list[str]:
    return [name for name, patterns in SOURCES.items() if any(re.search(pattern, code, re.I | re.S) for pattern in patterns)]


def tainted_identifiers(code: str) -> set[str]:
    tainted: set[str] = set()
    source_patterns = tuple(pattern for patterns in SOURCES.values() for pattern in patterns)
    assignments = list(ASSIGNMENT_PATTERN.finditer(code))
    for match in assignments:
        if any(re.search(pattern, match.group(2), re.I) for pattern in source_patterns):
            tainted.add(match.group(1))
    changed = True
    while changed:
        changed = False
        for match in assignments:
            if match.group(1) not in tainted and any(re.search(rf"\b{re.escape(name)}\b", match.group(2)) for name in tainted):
                tainted.add(match.group(1))
                changed = True
    return tainted


def analyze_function(function: dict) -> list[dict]:
    code = function["sourceCode"]
    sources = matching_sources(code)
    tainted = tainted_identifiers(code)
    sanitizer_names = [name for name, patterns in SANITIZERS.items() if any(re.search(pattern, code, re.I | re.S) for pattern in patterns)]
    findings = []
    for rule in RULES:
        sink_match = next((re.search(pattern, code, re.I | re.S) for pattern in rule["sinks"] if re.search(pattern, code, re.I | re.S)), None)
        if not sink_match:
            continue
        excerpt_start = max(0, code.rfind("\n", 0, sink_match.start()) + 1)
        excerpt_end = code.find("\n", sink_match.end())
        raw_excerpt = code[excerpt_start:excerpt_end if excerpt_end != -1 else len(code)].strip()[:280]
        directly_tainted = bool(sources) or any(re.search(rf"\b{re.escape(name)}\b", raw_excerpt) for name in tainted)
        if rule["taint"] and not directly_tainted:
            continue
        excerpt = redact_secrets(raw_excerpt)
        confidence = rule["confidence"]
        verdict = "likely_vulnerable" if directly_tainted and not sanitizer_names else "needs_review"
        if sanitizer_names:
            confidence = "medium"
        line = function["startLine"] + code.count("\n", 0, sink_match.start())
        findings.append({
            "pass1_hypothesis": {"vulnerable": True, "cwe_guess": rule["cwe"], "reasoning": rule["reason"], "confidence": confidence},
            "pass2_triage": {"verdict": verdict, "explanation": f"Static flow review found {', '.join(sources) if sources else 'a security-sensitive configuration'} near this sink. " + (f"Potential sanitizers were also observed: {', '.join(sanitizer_names)}." if sanitizer_names else "No recognized sanitizer was observed in the function."), "recommendation": "Review the reported source-to-sink path, framework behavior, validation, authorization, and encoding before manual confirmation. Do not execute payloads from this pipeline.", "status": "pending"},
            "evidence": {"ruleId": rule["id"], "owasp": rule["owasp"], "category": rule["category"], "source": ", ".join(sources) if sources else None, "sink": excerpt, "sanitizers": sanitizer_names, "taintedIdentifiers": sorted(tainted), "line": line, "excerpt": excerpt},
        })
    return findings


def build_graph(functions: list[dict]) -> dict:
    edges: set[tuple[str, str]] = set()
    by_name = {item["name"]: item for item in functions}
    finding_count = 0
    for item in functions:
        for call in item.pop("calls"):
            target = by_name.get(call.split(".")[-1])
            if target and target["id"] != item["id"]:
                edges.add((item["id"], target["id"]))
        findings = analyze_function(item)
        excerpts = list(dict.fromkeys(finding["evidence"]["excerpt"] for finding in findings if finding.get("evidence", {}).get("excerpt")))[:3]
        item["sourceExcerpt"] = "\n…\n".join(excerpts)
        del item["sourceCode"]
        if findings:
            item["vulnerabilities"] = findings
            item["vulnerability"] = findings[0]
            finding_count += len(findings)
    return {"nodes": functions, "edges": [{"source": source, "target": target} for source, target in sorted(edges)], "findingCount": finding_count}


def materialize(target_type: str, source: str, allowed_root: str | None) -> tuple[Path, tempfile.TemporaryDirectory | None]:
    if target_type == "local":
        if not allowed_root:
            raise ValueError("Local analysis requires a server-configured root")
        root = Path(allowed_root).expanduser().resolve(strict=True)
        path = Path(source).expanduser().resolve(strict=True)
        try:
            path.relative_to(root)
        except ValueError as error:
            raise ValueError("Local target is outside the server-configured root") from error
        if not path.is_dir():
            raise ValueError("Local target must be an existing directory")
        return path, None
    if not re.fullmatch(r"https://[^/?#]+/[^/?#]+/[^/?#]+(?:\.git)?/?", source, re.I):
        raise ValueError("Repository target must be an exact credential-free HTTPS repository URL")
    temp = tempfile.TemporaryDirectory(prefix="aegis-target-")
    destination = Path(temp.name) / "source"
    try:
        subprocess.run([
            "git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "-c", "http.followRedirects=false", "clone", "--depth", "1", "--no-tags", "--", source, str(destination)
        ], check=True, timeout=180, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "Repository clone failed").strip().splitlines()[-1]
        temp.cleanup()
        raise ValueError(f"Git clone failed: {detail}") from error
    return destination, temp


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-type", choices=("repository", "local"), required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--allowed-root")
    args = parser.parse_args()
    root, temp = materialize(args.target_type, args.source, args.allowed_root)
    try:
        parser_mode = "tree-sitter" if TREE_SITTER_AVAILABLE else "built-in fallback"
        functions, files = walk_functions_tree_sitter(root) if TREE_SITTER_AVAILABLE else walk_functions_fallback(root)
        result = build_graph(functions)
        result["summary"] = {"filesRoot": str(root), "files": files, "functions": len(functions), "findings": result.pop("findingCount"), "parserMode": parser_mode, "rulesEvaluated": len(RULES), "coverage": [rule["category"] for rule in RULES], "warning": None if TREE_SITTER_AVAILABLE else "tree-sitter packages are unavailable; results were produced with the conservative built-in parser."}
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
