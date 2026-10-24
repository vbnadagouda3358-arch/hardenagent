"""Line-based rules. Each rule is a regex applied to files of certain kinds.

File kinds (see scanner.classify):
  any      every text file (used for secrets)
  config   .json .yaml .yml .toml .ini .cfg .conf .env files
  code     .py .js .ts .sh and similar
  docker   Dockerfiles
  compose  docker-compose files
  env      .env files
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern, Tuple


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    kinds: Tuple[str, ...]
    pattern: Pattern[str]
    fix: str
    secret: bool = False


def _r(expr: str, flags: int = 0) -> Pattern[str]:
    return re.compile(expr, flags)


# Matches that look like documentation placeholders rather than real secrets.
PLACEHOLDER = re.compile(
    r"(?i)x{4,}|example|your[_-]?|changeme|placeholder|dummy|<[^>]*>|\$\{|\.\.\.|redacted"
)
# Extra placeholder words only applied to the generic "name = value" secret rule.
GENERIC_PLACEHOLDER = re.compile(r"(?i)test|sample|fake|secret_here|todo|none|null|env")

RULES: Tuple[Rule, ...] = (
    # ------------------------------------------------------------------ secrets
    Rule(
        "HA-SEC-001", "Anthropic API key in file", "critical", ("any",),
        _r(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
        "Revoke this key now, then load it from an environment variable or a secrets manager.",
        secret=True,
    ),
    Rule(
        "HA-SEC-002", "OpenAI-style API key in file", "critical", ("any",),
        _r(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"),
        "Revoke this key now, then load it from an environment variable or a secrets manager.",
        secret=True,
    ),
    Rule(
        "HA-SEC-003", "AWS access key ID in file", "critical", ("any",),
        _r(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "Deactivate the key in IAM and use short-lived roles instead of static keys.",
        secret=True,
    ),
    Rule(
        "HA-SEC-004", "GitHub token in file", "critical", ("any",),
        _r(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
        "Revoke the token in GitHub settings and use a fine-grained token from the environment.",
        secret=True,
    ),
    Rule(
        "HA-SEC-005", "Slack token in file", "critical", ("any",),
        _r(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),
        "Revoke the token in Slack and store the replacement outside the repository.",
        secret=True,
    ),
    Rule(
        "HA-SEC-006", "Telegram bot token in file", "high", ("any",),
        _r(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
        "Regenerate the token with BotFather and load it from the environment.",
        secret=True,
    ),
    Rule(
        "HA-SEC-007", "Google API key in file", "high", ("any",),
        _r(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "Rotate the key in Google Cloud and restrict it by API and referrer or IP.",
        secret=True,
    ),
    Rule(
        "HA-SEC-008", "Private key block in file", "critical", ("any",),
        _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Remove the key from the repository, rotate it, and mount it as a runtime secret.",
        secret=True,
    ),
    Rule(
        "HA-SEC-009", "Hard-coded secret value", "medium", ("any",),
        _r(
            r"(?i)\b(?:api[_-]?key|apikey|secret|token|bot[_-]?token|gateway[_-]?token|passwd|password|auth[_-]?token|"
            r"access[_-]?key|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"'](?P<secret>[A-Za-z0-9_\-/+=.]{16,})[\"']"
        ),
        "Move the value to an environment variable or secrets manager and rotate it if it was real.",
        secret=True,
    ),
    Rule(
        "HA-SEC-010", "Groq API key in file", "high", ("any",),
        _r(r"\bgsk_[A-Za-z0-9]{30,}\b"),
        "Revoke the key in the Groq console and load the replacement from an environment variable.",
        secret=True,
    ),
    Rule(
        "HA-SEC-011", "Notion integration token in file", "high", ("any",),
        _r(r"\b(?:ntn_[A-Za-z0-9]{30,}|secret_[A-Za-z0-9]{30,})\b"),
        "Rotate the token in Notion's integration settings and load it from an environment variable.",
        secret=True,
    ),
    Rule(
        "HA-SEC-012", "Hugging Face token in file", "high", ("any",),
        _r(r"\bhf_[A-Za-z0-9]{30,}\b"),
        "Revoke the token in Hugging Face settings and load the replacement from the environment.",
        secret=True,
    ),
    # ------------------------------------------------------- network and access
    Rule(
        "HA-NET-001", "Service listens on all network interfaces", "high",
        ("config", "code", "docker"),
        _r(
            r"(?i)(?:host|bind|listen|address|interface)[\"']?\s*[:=]\s*[\"']?0\.0\.0\.0"
            r"|--host[= ]0\.0\.0\.0|listen\([^)]*[\"']0\.0\.0\.0[\"']"
        ),
        "Bind to 127.0.0.1 and put an authenticated reverse proxy or VPN in front of the agent.",
    ),
    Rule(
        "HA-NET-002", "Gateway bind mode exposes it to the local network ('lan')", "high",
        ("config", "code", "docker", "compose"),
        _r(r"(?i)\bbind[\"']?\s*[:=]\s*[\"']?lan\b|--bind[= ]lan\b"),
        "Use bind 'loopback' and reach the gateway through an SSH tunnel, VPN or HTTPS proxy with token auth.",
    ),
    Rule(
        "HA-AUTH-001", "Authentication is disabled", "high", ("config", "code"),
        _r(
            r"(?i)[\"']?(?:auth|authentication|require[_-]?auth|auth[_-]?required|enable[_-]?auth|authn)"
            r"[\"']?\s*[:=]\s*[\"']?(?:false|none|off|disabled|no)[\"']?(?:\s|,|$)"
        ),
        "Require authentication on every endpoint that can trigger tools or read agent data.",
    ),
    Rule(
        "HA-AUTH-002", "Weak or default credential", "high", ("config", "code"),
        _r(
            r"(?i)\b(?:password|passwd|token|admin[_-]?password)\b[\"']?\s*[:=]\s*[\"']"
            r"(?:admin|password|123456|changeme|default|root|letmein)[\"']"
        ),
        "Replace the default value with a long random secret loaded from the environment.",
    ),
    Rule(
        "HA-AUTH-002", "Weak or default credential", "high", ("config",),
        _r(
            r"(?i)^\s*[\"']?(?:password|passwd|token|admin[_-]?password)[\"']?\s*[:=]\s*"
            r"(?:admin|password|123456|changeme|default|root|letmein)\s*(?:#.*)?$"
        ),
        "Replace the default value with a long random secret loaded from the environment.",
    ),
    Rule(
        "HA-CORS-001", "Wildcard CORS origin", "medium", ("config", "code"),
        _r(
            r"(?i)access-control-allow-origin[\"']?\s*[:=,]\s*[\"']?\*"
            r"|(?:cors[_-]?origins?|allow(?:ed)?[_-]?origins?)[\"']?\s*[:=]\s*\[?\s*[\"']\*[\"']"
        ),
        "List the exact origins that need access instead of using '*'.",
    ),
    Rule(
        "HA-PERM-001", "Wildcard permission or tool allow-list", "high", ("config",),
        _r(
            r"(?i)[\"']?(?:allow(?:ed)?[_-]?(?:tools|commands|paths|hosts|domains|actions|"
            r"permissions|scopes|dirs|directories)?|permissions?|scopes?|tools|capabilities)"
            r"[\"']?\s*[:=]\s*\[?\s*[\"']\*[\"']"
        ),
        "Replace '*' with an explicit allow-list of the tools, paths or hosts the agent really needs.",
    ),
    # -------------------------------------------------- approval, sandbox, exec
    Rule(
        "HA-APPR-001", "Human approval for actions is switched off", "high",
        ("config", "code", "docker", "compose"),
        _r(
            r"(?i)(?:auto[_-]?approve|auto[_-]?approval|auto[_-]?run|auto[_-]?execute|"
            r"skip[_-]?(?:approval|confirm\w*|permissions?)|bypass[_-]?permissions?|dangerously\w*)"
            r"[\"']?\s*[:=]\s*[\"']?(?:true|yes|on|1)\b"
            r"|(?:require[_-]?approval|require[_-]?confirmation|confirm[_-]?before[_-]?\w+|"
            r"human[_-]?approval|ask[_-]?before[_-]?\w+)[\"']?\s*[:=]\s*[\"']?(?:false|no|off|0)\b"
            r"|--yolo\b|--dangerously-skip-permissions|--auto-approve|--no-confirm"
        ),
        "Require explicit approval for tool calls that write files, run commands or send messages.",
    ),
    Rule(
        "HA-SBX-001", "Sandbox or isolation is disabled", "high", ("config", "code"),
        _r(
            r"(?i)[\"']?(?:sandbox(?:ed|ing)?|isolation|container[_-]?isolation)[\"']?"
            r"\s*[:=]\s*[\"']?(?:false|none|off|disabled|no)\b"
        ),
        "Run tools inside a sandbox (container, VM or restricted user) and keep it enabled.",
    ),
    Rule(
        "HA-SBX-002", "Container runs in privileged mode", "critical",
        ("compose", "docker", "config"),
        _r(r"(?i)\bprivileged\s*:\s*true|--privileged\b"),
        "Remove privileged mode and grant only the specific capabilities that are required.",
    ),
    Rule(
        "HA-SBX-003", "Docker socket exposed to the agent", "critical",
        ("compose", "docker", "config", "code"),
        _r(r"/var/run/docker\.sock"),
        "Do not mount the Docker socket; it gives full control of the host.",
    ),
    Rule(
        "HA-SBX-004", "Container shares the host network", "high",
        ("compose", "docker", "config"),
        _r(r"(?i)network_mode\s*:\s*[\"']?host|--network[= ]host|--net[= ]host"),
        "Use a bridge network and publish only the ports you need on 127.0.0.1.",
    ),
    Rule(
        "HA-SBX-005", "Host root or home directory mounted into container", "high",
        ("compose",),
        _r(
            r"^\s*-\s*[\"']?(?:/|~|\$\{?HOME\}?|/home/[\w.\-]+|/Users/[\w.\-]+)/?:[^\s\"']+"
        ),
        "Mount only the specific project folder the agent needs, preferably read-only.",
    ),
    Rule(
        "HA-SBX-006", "Credential directory mounted into container", "high",
        ("compose",),
        _r(r"^\s*-\s*[\"']?[^:\n]*(?:\.ssh|\.aws|\.kube|\.gnupg|gcloud)[^:\n]*:"),
        "Do not mount SSH, cloud or Kubernetes credentials into an agent container.",
    ),
    Rule(
        "HA-PORT-001", "Published port is reachable on all interfaces", "medium",
        ("compose",),
        _r(r"^\s*-\s*[\"']?(?:0\.0\.0\.0:)?\d{2,5}:\d{2,5}(?:/(?:tcp|udp))?[\"']?\s*(?:#.*)?$"),
        "Prefix the mapping with 127.0.0.1 (for example 127.0.0.1:8080:8080) unless it must be public.",
    ),
    Rule(
        "HA-EXEC-001", "Shell or code-execution tool enabled", "medium", ("config",),
        _r(
            r"(?i)[\"']?(?:shell|bash|terminal|exec|code[_-]?(?:interpreter|execution)|"
            r"run[_-]?command|command[_-]?execution)[\"']?\s*[:=]\s*[\"']?(?:true|enabled|on|yes)\b"
        ),
        "Keep shell tools behind a sandbox and an approval step, with a command allow-list.",
    ),
    Rule(
        "HA-EXEC-002", "Agent runs with elevated privileges", "high", ("config",),
        _r(
            r"(?i)[\"']?(?:sudo|run[_-]?as[_-]?root|elevated)[\"']?\s*[:=]\s*[\"']?"
            r"(?:true|yes|on|enabled)\b"
        ),
        "Run the agent as an unprivileged user.",
    ),
    Rule(
        "HA-EXEC-003", "Container runs as root", "medium", ("docker",),
        _r(r"(?im)^\s*USER\s+root\b"),
        "Create and switch to a non-root user in the Dockerfile.",
    ),
    # ------------------------------------------------------------ supply chain
    Rule(
        "HA-SUPPLY-001", "Remote script piped into a shell", "high",
        ("config", "code", "docker", "compose"),
        _r(r"(?i)\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"),
        "Download, verify a checksum or signature, then run the script as a separate step.",
    ),
    Rule(
        "HA-SUPPLY-002", "Dockerfile ADD from a remote URL", "medium", ("docker",),
        _r(r"(?im)^\s*ADD\s+https?://"),
        "Use COPY with a verified local file or download with a pinned checksum.",
    ),
    Rule(
        "HA-TLS-001", "TLS certificate verification disabled", "medium", ("config", "code"),
        _r(
            r"(?i)verify\s*=\s*False|rejectUnauthorized\s*:\s*false"
            r"|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[\"']?0"
            r"|(?:ssl[_-]?verify|verify[_-]?ssl|tls[_-]?verify)[\"']?\s*[:=]\s*[\"']?(?:false|0|no|off)\b"
            r"|\binsecure[\"']?\s*[:=]\s*[\"']?(?:true|yes|1)\b"
        ),
        "Leave certificate verification on; add your CA bundle if you use a private CA.",
    ),
    # ----------------------------------------------------------------- code
    Rule(
        "HA-CODE-001", "Shell command execution in code", "medium", ("code",),
        _r(
            r"subprocess\.[A-Za-z_]+\([^)\n]*shell\s*=\s*True|\bos\.(?:system|popen)\s*\("
            r"|child_process\.(?:exec|execSync)\s*\(|\bexecSync\s*\("
        ),
        "Pass an argument list without a shell, allow-list commands, and never pass raw model output.",
    ),
    Rule(
        "HA-CODE-002", "Dynamic code evaluation", "high", ("code",),
        _r(r"(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|\bnew\s+Function\s*\("),
        "Avoid eval/exec on model output; parse structured data instead.",
    ),
    Rule(
        "HA-CODE-003", "Unsafe deserialization", "medium", ("code",),
        _r(r"\bpickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|\byaml\.load\s*\((?![^)\n]*Safe)"),
        "Use JSON or yaml.safe_load; never unpickle data from outside your trust boundary.",
    ),
    Rule(
        "HA-CODE-004", "Debug mode enabled", "medium", ("config", "code"),
        _r(r"(?i)\bdebug[\"']?\s*[:=]\s*[\"']?(?:true|1|yes)\b"),
        "Turn debug mode off in anything that is reachable by other people.",
    ),
    Rule(
        "HA-CODE-005", "AppleScript or osascript built from variables", "high", ("code",),
        _r(
            r"(?i)osascript[^\n]*\bf[\"'][^\n]*\{[^}\n]+\}"
            r"|osascript[^\n]*(?:\.format\(|%\s*\(|%s)"
            r"|\bf[\"'][^\n]*\btell application\b[^\n]*\{[^}\n]+\}"
        ),
        "AppleScript can run shell commands. Validate every inserted value (allow-list app names, "
        "force numbers with int()) and never insert raw model or voice text.",
    ),
    Rule(
        "HA-CODE-006", "Command passed to subprocess as a variable (review)", "low", ("code",),
        _r(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\(\s*[A-Za-z_][\w.]*\s*[,)]"),
        "Confirm this command is built only from fixed values. Never include model or voice text "
        "without validation, and prefer an argument list.",
    ),
)

# Rules that are produced by dedicated logic, listed so `hardenagent rules` shows them.
SPECIAL_RULES: Tuple[Tuple[str, str, str], ...] = (
    ("HA-NET-900", "Unauthenticated service exposed on all interfaces (combined finding)", "critical"),
    ("HA-ENV-001", ".env file with secrets is not git-ignored", "high"),
    ("HA-ENV-002", ".env file is readable by other users", "medium"),
    ("HA-MCP-001", "MCP server package is not pinned to a version", "medium"),
    ("HA-MCP-002", "MCP server reached over plain http", "high"),
    ("HA-MCP-003", "MCP server launched through a shell", "medium"),
    ("HA-MCP-004", "MCP filesystem server can read the whole disk or home", "high"),
    ("HA-MCP-005", "MCP server config contains a literal secret", "high"),
)


def rule_catalog() -> list:
    """(id, severity, title) for every rule, for `hardenagent rules`."""
    items = {r.rule_id: (r.rule_id, r.severity, r.title) for r in RULES}
    for rid, title, sev in SPECIAL_RULES:
        items[rid] = (rid, sev, title)
    return sorted(items.values())


def is_placeholder(value: str, generic: bool = False) -> bool:
    if PLACEHOLDER.search(value):
        return True
    if generic and GENERIC_PLACEHOLDER.search(value):
        return True
    return False


def optional(pattern: Optional[Pattern[str]]) -> bool:  # pragma: no cover - tiny helper
    return pattern is not None
