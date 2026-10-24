"""Walks a project folder and applies the rules. Local files only, no network."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

from .models import Finding, ScanResult, SEVERITY_ORDER
from .rules import RULES, Rule, is_placeholder

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".tox", "site-packages", ".idea", ".vscode-test",
}
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock",
    "cargo.lock", "pipfile.lock", "composer.lock", "go.sum",
}
CONFIG_EXTS = {".json", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}
CODE_EXTS = {
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".zsh",
}
MAX_BYTES = 1_000_000
MAX_LINE = 2000
ENV_TEMPLATE_HINTS = ("example", "sample", "template", "dist")

DEFINITION_RE = re.compile(r"(?:async\s+)?(?:def|function|class)\s")
IGNORE_RE = re.compile(r"hardenagent:\s*ignore(?:\s+([A-Za-z0-9\-, ]+))?")
ENV_SECRET_RE = re.compile(
    r"^\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*=\s*[\"']?([^\s#\"']{8,})"
)


def mask(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "..." + value[-2:]


def classify(path: Path) -> Set[str]:
    name = path.name.lower()
    ext = path.suffix.lower()
    kinds = {"any"}
    if name == "dockerfile" or name.startswith("dockerfile.") or ext == ".dockerfile":
        kinds.add("docker")
    if "compose" in name and ext in (".yml", ".yaml"):
        kinds.update({"compose", "config"})
    if ext in CONFIG_EXTS or name.startswith(".env") or name.endswith(".env"):
        kinds.add("config")
    if name.startswith(".env") or name.endswith(".env"):
        kinds.add("env")
    if ext in CODE_EXTS:
        kinds.add("code")
    return kinds


def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in sorted(filenames):
            yield Path(dirpath) / filename


def read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def is_ignored(rule_id: str, line: str, previous: str) -> bool:
    for text in (line, previous):
        match = IGNORE_RE.search(text)
        if not match:
            continue
        listed = match.group(1)
        if not listed or not listed.strip():
            return True
        ids = {part.strip().upper() for part in re.split(r"[ ,]+", listed) if part.strip()}
        if rule_id.upper() in ids:
            return True
    return False


def _display(path: Path, root: Path) -> str:
    base = root if root.is_dir() else root.parent
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


# --------------------------------------------------------------------- line rules
def _scan_lines(text: str, rel: str, kinds: Set[str], rules: Iterable[Rule]) -> List[Finding]:
    applicable = [r for r in rules if "any" in r.kinds or kinds.intersection(r.kinds)]
    found: List[Finding] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if len(line) > MAX_LINE:
            continue
        previous = lines[index - 1] if index else ""
        stripped = line.lstrip()
        is_comment = stripped.startswith(("#", "//", "/*", "*"))
        is_definition = bool(DEFINITION_RE.match(stripped))
        for rule in applicable:
            if rule.kinds == ("code",) and (is_comment or is_definition):
                continue
            for match in rule.pattern.finditer(line):
                secret_value = match.groupdict().get("secret") or match.group(0)
                if rule.secret and is_placeholder(secret_value, generic=rule.rule_id == "HA-SEC-009"):
                    continue
                if is_ignored(rule.rule_id, line, previous):
                    continue
                evidence = line.strip()
                if rule.secret:
                    evidence = evidence.replace(secret_value, mask(secret_value))
                found.append(
                    Finding(rule.rule_id, rule.severity, rule.title, rel, index + 1,
                            evidence[:160], rule.fix)
                )
                break  # one hit per rule per line is enough
    return found


# --------------------------------------------------- multi-line wildcard lists
PERM_MULTILINE = re.compile(
    r"(?i)[\"']?(allow(?:ed)?[_-]?(?:tools|commands|paths|hosts|domains|actions|permissions|"
    r"scopes|dirs|directories)?|permissions?|scopes?|tools|capabilities)[\"']?[ \t]*:[ \t]*"
    r"(?:\[\s*|\n[ \t]*-[ \t]*)[\"']\*[\"']"
)


def _scan_multiline_wildcards(text: str, rel: str) -> List[Finding]:
    rule = next(r for r in RULES if r.rule_id == "HA-PERM-001")
    lines = text.splitlines()
    found: List[Finding] = []
    for match in PERM_MULTILINE.finditer(text):
        number = text.count("\n", 0, match.start(1)) + 1
        here = lines[number - 1] if number - 1 < len(lines) else ""
        previous = lines[number - 2] if number >= 2 else ""
        if is_ignored(rule.rule_id, here, previous):
            continue
        found.append(Finding(rule.rule_id, rule.severity, rule.title, rel, number,
                             here.strip()[:160], rule.fix))
    return found


# ------------------------------------------------------------------- .env checks
def _gitignore_covers_env(file_path: Path, stop: Path) -> bool:
    patterns = {".env", ".env*", "*.env", ".env.*", "/.env", "**/.env", ".env.local"}
    current = file_path.parent
    stop = stop if stop.is_dir() else stop.parent
    seen = 0
    while seen < 12:
        gitignore = current / ".gitignore"
        if gitignore.is_file():
            text = read_text(gitignore) or ""
            for raw in text.splitlines():
                entry = raw.strip()
                if entry and not entry.startswith("#") and entry in patterns:
                    return True
        if current == stop or current.parent == current or (current / ".git").exists():
            break
        current = current.parent
        seen += 1
    return False


def _scan_env_file(path: Path, text: str, rel: str, root: Path) -> List[Finding]:
    name = path.name.lower()
    if any(hint in name for hint in ENV_TEMPLATE_HINTS):
        return []
    found: List[Finding] = []
    secret_line = None
    for index, line in enumerate(text.splitlines()):
        match = ENV_SECRET_RE.match(line)
        if match and not is_placeholder(match.group(1), generic=True):
            secret_line = (index + 1, line, match.group(1))
            break
    if secret_line and not _gitignore_covers_env(path, root):
        number, line, value = secret_line
        found.append(Finding(
            "HA-ENV-001", "high", ".env file with secrets is not git-ignored", rel, number,
            line.strip().replace(value, mask(value))[:160],
            "Add '.env' to .gitignore, rotate any secret that was committed, and ship a .env.example instead.",
        ))
    if secret_line and os.name != "nt":
        try:
            mode = path.stat().st_mode
        except OSError:
            mode = 0
        if mode & 0o044:
            found.append(Finding(
                "HA-ENV-002", "medium", ".env file is readable by other users", rel, 1,
                f"file mode {oct(mode & 0o777)}",
                "Run: chmod 600 " + path.name,
            ))
    return found


# --------------------------------------------------------------------- MCP checks
def _iter_mcp_servers(data: object) -> Iterator[Tuple[str, Dict[str, object]]]:
    if isinstance(data, dict):
        for key in ("mcpServers", "mcp_servers", "mcp"):
            block = data.get(key)
            if isinstance(block, dict):
                for name, cfg in block.items():
                    if isinstance(cfg, dict):
                        yield str(name), cfg
        block = data.get("servers")
        if isinstance(block, dict):
            for name, cfg in block.items():
                if isinstance(cfg, dict) and ("command" in cfg or "url" in cfg):
                    yield str(name), cfg
        for value in data.values():
            if isinstance(value, (dict, list)):
                yield from _iter_mcp_servers(value)
    elif isinstance(data, list):
        for item in data:
            yield from _iter_mcp_servers(item)


def _line_of(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return index
    return 1


PINNED_NPM = re.compile(r"^(?:@[^/@]+/)?[^@/\s]+@(?!latest$)[\w.\-+^~]+$")
SHELLS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh", "powershell.exe"}
SECRET_KEY_RE = re.compile(r"(?i)key|token|secret|password|authorization")
BROAD_PATHS = {"/", "~", "$HOME", "${HOME}", "C:\\", "C:/", "c:\\", "c:/"}
HOME_DIR_RE = re.compile(r"^/(?:home|Users)/[^/]+/?$")


def _first_package_arg(args: List[str]) -> Optional[str]:
    for arg in args:
        if arg.startswith("-"):
            continue
        return arg
    return None


def _scan_mcp(text: str, rel: str) -> List[Finding]:
    lowered = text.lower()
    if "mcp" not in lowered and '"servers"' not in lowered:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    found: List[Finding] = []
    seen: Set[str] = set()
    lines = text.splitlines()
    for name, cfg in _iter_mcp_servers(data):
        key = name + json.dumps(cfg, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        number = _line_of(text, f'"{name}"')
        previous = lines[number - 2] if number >= 2 else ""
        here = lines[number - 1] if number - 1 < len(lines) else ""

        def add(rule_id: str, severity: str, title: str, evidence: str, fix: str) -> None:
            if not is_ignored(rule_id, here, previous):
                found.append(Finding(rule_id, severity, title, rel, number,
                                     f"server '{name}': {evidence}"[:160], fix))

        command = str(cfg.get("command") or "")
        raw_args = cfg.get("args") or []
        args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
        base = os.path.basename(command).lower()
        full = " ".join([command] + args)
        url = str(cfg.get("url") or cfg.get("serverUrl") or "")

        if base in {"npx", "bunx", "pnpx"}:
            package = _first_package_arg(args)
            if package and not PINNED_NPM.match(package):
                add("HA-MCP-001", "medium", "MCP server package is not pinned to a version",
                    f"{base} {package}",
                    "Pin an exact version (package@1.2.3) so a compromised update cannot run on your machine.")
        elif base in {"uvx", "pipx"}:
            package = _first_package_arg([a for a in args if a != "run"])
            if package and "==" not in package and "@" not in package:
                add("HA-MCP-001", "medium", "MCP server package is not pinned to a version",
                    f"{base} {package}",
                    "Pin an exact version (package==1.2.3) so a compromised update cannot run on your machine.")

        if url.lower().startswith("http://"):
            host = re.sub(r"^http://", "", url, flags=re.I).split("/")[0].split(":")[0].lower()
            if host not in {"localhost", "127.0.0.1", "::1", "[::1]"}:
                add("HA-MCP-002", "high", "MCP server reached over plain http", url,
                    "Use https so tool traffic and tokens cannot be read or altered on the network.")

        if base in SHELLS or "-c" in args:
            piped = re.search(r"(?i)\b(?:curl|wget)\b", full)
            severity = "high" if piped else "medium"
            add("HA-MCP-003", severity, "MCP server launched through a shell",
                full[:120],
                "Launch the server binary directly with an argument list instead of a shell string.")

        if "filesystem" in (name + " " + full).lower():
            for arg in args:
                if arg in BROAD_PATHS or HOME_DIR_RE.match(arg):
                    add("HA-MCP-004", "high", "MCP filesystem server can read the whole disk or home",
                        f"allowed path {arg}",
                        "Allow only the project folder the agent actually works in.")
                    break

        env = cfg.get("env")
        headers = cfg.get("headers")
        for block in (env, headers):
            if not isinstance(block, dict):
                continue
            for env_key, value in block.items():
                text_value = str(value)
                if (SECRET_KEY_RE.search(str(env_key)) and len(text_value) >= 8
                        and not text_value.startswith("$") and not is_placeholder(text_value)):
                    add("HA-MCP-005", "high", "MCP server config contains a literal secret",
                        f"{env_key} = {mask(text_value)}",
                        "Reference an environment variable (for example ${API_TOKEN}) and rotate this value.")
    return found


# ------------------------------------------------------------------- entry point
def scan(path: str, ignore: Optional[Iterable[str]] = None) -> ScanResult:
    root = Path(path).resolve()
    skip_rules = {r.upper() for r in (ignore or [])}
    result = ScanResult(root=str(root))
    findings: List[Finding] = []
    seen: Set[Tuple[str, str, int]] = set()

    for file_path in iter_files(root):
        if file_path.name.lower() in LOCKFILES:
            continue
        text = read_text(file_path)
        if text is None:
            continue
        result.files_scanned += 1
        rel = _display(file_path, root)
        kinds = classify(file_path)
        batch = _scan_lines(text, rel, kinds, RULES)
        if "config" in kinds:
            batch += _scan_multiline_wildcards(text, rel)
        if "env" in kinds:
            batch += _scan_env_file(file_path, text, rel, root)
        if file_path.suffix.lower() in {".json"}:
            batch += _scan_mcp(text, rel)
        for finding in batch:
            marker = (finding.rule_id, finding.file, finding.line)
            if marker in seen or finding.rule_id in skip_rules:
                continue
            seen.add(marker)
            findings.append(finding)

    exposed = [f for f in findings if f.rule_id == "HA-NET-001"]
    no_auth = [f for f in findings if f.rule_id == "HA-AUTH-001"]
    if exposed and no_auth and "HA-NET-900" not in skip_rules:
        first = exposed[0]
        findings.append(Finding(
            "HA-NET-900", "critical",
            "Unauthenticated service exposed on all interfaces (combined finding)",
            first.file, first.line,
            f"{first.evidence}  +  {no_auth[0].file}:{no_auth[0].line} {no_auth[0].evidence}"[:160],
            "Bind to 127.0.0.1 AND require authentication. Anyone on the network could drive this agent.",
        ))

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line, f.rule_id))
    result.findings = findings
    return result
