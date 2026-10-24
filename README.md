# hardenagent

A local security auditor for **self-hosted AI agent projects**. Point it at a folder and it
reports risky settings in agent configs, MCP server definitions, Docker files, `.env` files and
agent code, with a plain-English fix for each one.

- Runs entirely on your machine. **No network calls, no telemetry, no dependencies** (standard library only).
- Fast: scans a typical agent project in well under a second.
- CI friendly: exit codes, JSON, Markdown and SARIF output (GitHub code scanning).

> Only scan projects you own or are authorised to test.

## Quick start

```bash
pip install git+https://github.com/<your-github-username>/hardenagent
hardenagent demo            # see it work on a deliberately insecure sample
hardenagent scan ./my-agent
```

Run from source without installing:

```bash
git clone https://github.com/<your-github-username>/hardenagent
cd hardenagent
PYTHONPATH=src python3 -m hardenagent demo
```

## What it checks

| Area | Examples |
|---|---|
| Secrets | Anthropic, OpenAI-style, AWS, GitHub, Slack, Telegram, Google keys, private keys, hard-coded passwords (values are masked in reports) |
| Network and auth | Binding to `0.0.0.0`, authentication switched off, weak default credentials, wildcard CORS, and a combined **critical** finding when an unauthenticated service is exposed |
| Agent permissions | Auto-approve or "skip permissions" flags, disabled sandbox, wildcard tool allow-lists, shell/code-exec tools, running as root |
| MCP servers | Unpinned `npx`/`uvx` packages, plain `http` servers, shell-launched servers, filesystem servers allowed on `/` or home, literal tokens in `env` or `headers` |
| Containers | Privileged mode, Docker socket mounted, host network, host root/home or `~/.ssh` mounted, ports published on all interfaces, `USER root`, `curl | sh` |
| Code | `eval`/`exec`, `shell=True`, `os.system`, unsafe pickle/yaml loading, disabled TLS verification, debug mode |
| Hygiene | `.env` with secrets that is not git-ignored or is world-readable |

List every rule with `hardenagent rules`.

## Using it in CI

```yaml
- run: pip install git+https://github.com/<your-github-username>/hardenagent
- run: hardenagent scan . --fail-on high
```

Exit code is `1` when a finding at or above `--fail-on` exists (`never`, `info`, `low`, `medium`,
`high`, `critical`), `2` on usage errors.

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

Or skip a rule globally: `hardenagent scan . --ignore HA-CODE-004`.

## Honest limitations

- It is a **static** scanner. It reads files; it does not probe running services, so it cannot
  prove an agent is safe, and a score of 100 is not a certification.
- Rules are pattern-based, so expect some false positives and misses. Please open an issue with a
  sanitised example.
- The rules are generic. Presets for specific agent frameworks are on the roadmap.

## Roadmap

- Presets for popular self-hosted agent frameworks and MCP client config locations
- Baseline files (accept existing findings, fail only on new ones)
- Hosted continuous scanning, team reports and compliance mapping (paid layer)

## Development

```bash
pip install -e ".[dev]"
pytest
```

Test fixtures are built at runtime so the repository never contains token-shaped strings.

## License

MIT
