# hardenagent

![tests](https://github.com/vbnadagouda3358-arch/hardenagent/actions/workflows/ci.yml/badge.svg)

A local security auditor for **self-hosted AI agent projects**. Point it at a folder and it
reports risky settings in agent configs, MCP server definitions, Docker files, `.env` files and
agent code, with a plain-English fix for each one.

- Runs entirely on your machine. **No network calls, no telemetry, no dependencies** (standard library only).
- Fast: scans a typical agent project in well under a second.
- CI friendly: exit codes, JSON, Markdown and SARIF output (GitHub code scanning).
- Python 3.9 or newer.

> Only scan projects you own or are authorised to test.

## Quick start

```bash
pip install git+https://github.com/vbnadagouda3358-arch/hardenagent
hardenagent demo            # see it work on a deliberately insecure sample
hardenagent scan ./my-agent
```

Run from source without installing:

```bash
git clone https://github.com/vbnadagouda3358-arch/hardenagent
cd hardenagent
PYTHONPATH=src python3 -m hardenagent demo
```

## Example output

This is an excerpt from `hardenagent demo`, which scans a made-up, deliberately insecure project.

```
hardenagent 0.1.0 - scanned 6 files in /tmp/hardenagent-demo-xxxx
Hardening score: 0/100 (quick heuristic, not a certification)

CRITICAL HA-SEC-001  Anthropic API key in file
         agent.py:4
         > ANTHROPIC_KEY = "sk-a...J1"
         Fix: Revoke this key now, then load it from an environment variable or a secrets manager.

CRITICAL HA-NET-900  Unauthenticated service exposed on all interfaces (combined finding)
         config.yaml:2
         > host: 0.0.0.0  +  config.yaml:4 auth: false
         Fix: Bind to 127.0.0.1 AND require authentication. Anyone on the network could drive this agent.

Summary: 5 critical, 12 high, 7 medium, 0 low
```

Secret values are masked in every report.

## What it checks

| Area | Examples |
|---|---|
| Secrets | Anthropic, OpenAI-style, Groq, Notion, Hugging Face, AWS, GitHub, Slack, Telegram and Google keys, private keys, hard-coded passwords and tokens in code, YAML, JSON and INI files |
| Network and auth | Binding to `0.0.0.0` or a gateway bind mode of `lan`, authentication switched off, weak default credentials, wildcard CORS, and a combined **critical** finding when an unauthenticated service is exposed |
| Agent permissions | Auto-approve or "skip permissions" flags, disabled sandbox, `deno run -A`, wildcard tool allow-lists, shell or code-execution tools, running as root |
| MCP servers | Unpinned `npx` or `uvx` packages, plain `http` servers, shell-launched servers, filesystem servers allowed on `/` or the home folder, literal tokens in `env` or `headers` |
| Containers | Privileged mode, Docker socket mounted, host network, host root or `~/.ssh` mounted, ports published on all interfaces, `USER root`, remote scripts piped into a shell |
| Code | `eval` and `exec`, `shell=True`, `os.system`, unsafe pickle or yaml loading, disabled TLS verification, debug mode, debug or console routes, debugger ports open to the network (Node, Deno, Python, Java) |
| Hygiene | `.env` files with secrets that are not git-ignored or are readable by other users |

List every rule with `hardenagent rules`.

## Using it in CI

```yaml
- run: pip install git+https://github.com/vbnadagouda3358-arch/hardenagent
- run: hardenagent scan . --fail-on high
```

The exit code is `1` when a finding at or above `--fail-on` exists (`never`, `info`, `low`,
`medium`, `high`, `critical`) and `2` on usage errors.

```bash
hardenagent scan . --format sarif -o hardenagent.sarif   # upload to GitHub code scanning
hardenagent scan . --format markdown -o report.md
hardenagent scan . --format json
```

## Silencing a finding

Add a comment on the same line or the line above:

```yaml
host: 0.0.0.0   # hardenagent: ignore HA-NET-001
```

Or skip a rule everywhere: `hardenagent scan . --ignore HA-CODE-004`.

## Honest limitations

- It is a **static** scanner. It reads files and does not probe running services, so it cannot
  prove an agent is safe. A score of 100 is not a certification.
- Rules are pattern-based, so expect some false positives and some misses. Please open an issue
  with a sanitised example.
- The rules are generic. Presets for specific agent frameworks are on the roadmap, and I have
  not yet validated them against real installs.

## Roadmap

- Presets for popular self-hosted agent frameworks and MCP client config locations
- Baseline files (accept existing findings, fail only on new ones)
- Hosted continuous scanning, team reports and compliance mapping (paid layer)

## Feedback and contributing

Found a false positive or a missing check? Please
[open an issue](https://github.com/vbnadagouda3358-arch/hardenagent/issues) with a sanitised
example. Never paste real keys or tokens.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Test fixtures are built at runtime so the repository never contains token-shaped strings.

## License

MIT
