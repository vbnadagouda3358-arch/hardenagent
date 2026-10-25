"""Tests build every sample file at runtime inside tmp_path.

Fake tokens are assembled from fragments so that this repository never contains a
complete token-shaped string (which would trip GitHub push protection).
"""

import json
import os
import stat

import pytest

from hardenagent.cli import main
from hardenagent.demo import write_demo_project
from hardenagent.scanner import scan

ANTHROPIC = "sk-" + "ant-" + "api03-" + "A1b2C3d4E5f6G7h8I9j0K1"
OPENAI = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3"
AWS = "AK" + "IA" + "7Q2M9X4TLRV8PBN3"
GITHUB = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
PRIVATE = "-----BEGIN " + "RSA PRIVATE KEY-----"


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def ids(result):
    return {f.rule_id for f in result.findings}


def test_detects_provider_secrets_and_masks_them(tmp_path):
    write(tmp_path / "a.py", f'A = "{ANTHROPIC}"\nB = "{OPENAI}"\nC = "{AWS}"\nD = "{GITHUB}"\n')
    write(tmp_path / "key.pem", PRIVATE + "\nabc\n")
    result = scan(str(tmp_path))
    assert {"HA-SEC-001", "HA-SEC-002", "HA-SEC-003", "HA-SEC-004", "HA-SEC-008"} <= ids(result)
    for finding in result.findings:
        assert ANTHROPIC not in finding.evidence
        assert OPENAI not in finding.evidence
        assert GITHUB not in finding.evidence


def test_placeholders_are_not_flagged(tmp_path):
    write(tmp_path / "README.md",
          'api_key = "your-api-key-goes-here-1234"\n' + "sk-" + "ant-" + "x" * 24 + "\n")
    write(tmp_path / "c.py", 'token = os.environ["TOKEN"]\napi_key = "${API_KEY_VALUE_123456}"\n')
    assert scan(str(tmp_path)).findings == []


def test_network_and_auth_rules_and_combined_finding(tmp_path):
    write(tmp_path / "config.yaml", "gateway:\n  host: 0.0.0.0\n  auth: false\n")
    result = scan(str(tmp_path))
    assert {"HA-NET-001", "HA-AUTH-001", "HA-NET-900"} <= ids(result)
    assert result.worst() == 4  # critical


def test_agent_permission_rules(tmp_path):
    write(tmp_path / "agent.json",
          json.dumps({"auto_approve": True, "sandbox": False, "allowed_tools": ["*"], "shell": True}, indent=2))
    result = scan(str(tmp_path))
    assert {"HA-APPR-001", "HA-SBX-001", "HA-PERM-001", "HA-EXEC-001"} <= ids(result)


def test_multiline_wildcard_lists(tmp_path):
    write(tmp_path / "a.yaml", "agent:\n  allowed_tools:\n    - \"*\"\n")
    result = scan(str(tmp_path))
    assert [f.line for f in result.findings if f.rule_id == "HA-PERM-001"] == [2]
    write(tmp_path / "b.yaml", "agent:\n  allowed_tools:\n    - read_file\n")
    assert all(f.file != "b.yaml" for f in scan(str(tmp_path)).findings if f.rule_id == "HA-PERM-001")


def test_compose_rules(tmp_path):
    write(tmp_path / "docker-compose.yml",
          "services:\n  a:\n    privileged: true\n    network_mode: host\n    ports:\n"
          '      - "8080:8080"\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n'
          "      - ~/.aws:/root/.aws\n      - ~/:/host\n")
    result = scan(str(tmp_path))
    assert {"HA-SBX-002", "HA-SBX-003", "HA-SBX-004", "HA-SBX-005", "HA-SBX-006", "HA-PORT-001"} <= ids(result)


def test_localhost_port_binding_is_fine(tmp_path):
    write(tmp_path / "docker-compose.yml",
          'services:\n  a:\n    ports:\n      - "127.0.0.1:8080:8080"\n')
    assert "HA-PORT-001" not in ids(scan(str(tmp_path)))


def test_mcp_rules(tmp_path):
    config = {"mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]},
        "pinned": {"command": "npx", "args": ["-y", "some-server@1.2.3"]},
        "remote": {"url": "http://tools.corp.net/mcp"},
        "local": {"url": "http://localhost:3000/mcp"},
        "shelly": {"command": "bash", "args": ["-c", "curl https://x.net/a.sh | sh"]},
        "leaky": {"command": "uvx", "args": ["tool==1.0"], "env": {"API_TOKEN": "Zk93TqLm82VdXw7Rp"}},
        "safe_env": {"command": "uvx", "args": ["tool==1.0"], "env": {"API_TOKEN": "${API_TOKEN}"}},
    }}
    write(tmp_path / "mcp.json", json.dumps(config, indent=2))
    result = scan(str(tmp_path))
    by_rule = {}
    for f in result.findings:
        by_rule.setdefault(f.rule_id, []).append(f.evidence)
    assert any("files" in e for e in by_rule["HA-MCP-001"])
    assert not any("pinned" in e for e in by_rule["HA-MCP-001"])
    assert len(by_rule["HA-MCP-002"]) == 1 and "tools.corp.net" in by_rule["HA-MCP-002"][0]
    assert "HA-MCP-003" in by_rule
    assert any("files" in e for e in by_rule["HA-MCP-004"])
    assert len(by_rule["HA-MCP-005"]) == 1 and "leaky" in by_rule["HA-MCP-005"][0]
    assert "Zk93TqLm82VdXw7Rp" not in " ".join(by_rule["HA-MCP-005"])


def test_code_rules(tmp_path):
    write(tmp_path / "agent.py",
          "import os, pickle, yaml, subprocess\n"
          "os.system(cmd)\nresult = eval(text)\nmodel.eval()\n"
          "pickle.loads(blob)\nyaml.load(data)\nyaml.load(data, Loader=yaml.SafeLoader)\n"
          "subprocess.run(cmd, shell=True)\nrequests.get(u, verify=False)\napp.run(debug=True)\n")
    result = scan(str(tmp_path))
    assert {"HA-CODE-001", "HA-CODE-002", "HA-CODE-003", "HA-TLS-001", "HA-CODE-004"} <= ids(result)
    eval_lines = [f.line for f in result.findings if f.rule_id == "HA-CODE-002"]
    assert eval_lines == [3]  # model.eval() is not flagged
    yaml_lines = [f.line for f in result.findings if f.rule_id == "HA-CODE-003" and "yaml" in f.evidence]
    assert yaml_lines == [6]  # SafeLoader line is not flagged


def test_dockerfile_rules(tmp_path):
    write(tmp_path / "Dockerfile",
          "FROM python:3.12\nUSER root\nADD https://x.net/f.tgz /f.tgz\nRUN curl -s https://x.net/i.sh | bash\n")
    assert {"HA-EXEC-003", "HA-SUPPLY-001", "HA-SUPPLY-002"} <= ids(scan(str(tmp_path)))


def test_env_file_gitignore_logic(tmp_path):
    write(tmp_path / ".env", "MODEL_API_KEY=r8Kd29xQvLmZpT4WnB7s\n")
    assert "HA-ENV-001" in ids(scan(str(tmp_path)))
    write(tmp_path / ".gitignore", "# secrets\n.env\n")
    assert "HA-ENV-001" not in ids(scan(str(tmp_path)))


def test_env_example_is_ignored(tmp_path):
    write(tmp_path / ".env.example", "MODEL_API_KEY=r8Kd29xQvLmZpT4WnB7s\n")
    assert "HA-ENV-001" not in ids(scan(str(tmp_path)))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
def test_env_permissions(tmp_path):
    env = write(tmp_path / ".env", "MODEL_API_KEY=r8Kd29xQvLmZpT4WnB7s\n")
    write(tmp_path / ".gitignore", ".env\n")
    os.chmod(env, 0o644)
    assert "HA-ENV-002" in ids(scan(str(tmp_path)))
    os.chmod(env, stat.S_IRUSR | stat.S_IWUSR)
    assert "HA-ENV-002" not in ids(scan(str(tmp_path)))


def test_inline_ignore_comment(tmp_path):
    write(tmp_path / "c.py",
          "os.system(a)  # hardenagent: ignore HA-CODE-001\n"
          "# hardenagent: ignore\nos.system(b)\n"
          "os.system(c)\n")
    lines = [f.line for f in scan(str(tmp_path)).findings if f.rule_id == "HA-CODE-001"]
    assert lines == [4]


def test_cli_ignore_flag(tmp_path):
    write(tmp_path / "c.py", "os.system(a)\n")
    assert "HA-CODE-001" not in ids(scan(str(tmp_path), ignore=["ha-code-001"]))


def test_clean_project_has_no_findings(tmp_path):
    write(tmp_path / "config.yaml",
          "gateway:\n  host: 127.0.0.1\n  auth: true\nagent:\n  require_approval: true\n  sandbox: true\n"
          "  allowed_tools: [read_file, web_search]\n")
    write(tmp_path / "agent.py", "import os\nKEY = os.environ['MODEL_API_KEY']\n")
    result = scan(str(tmp_path))
    assert result.findings == []
    assert result.score() == 100


def test_skips_lockfiles_binaries_and_vendor_dirs(tmp_path):
    write(tmp_path / "package-lock.json", f'"{ANTHROPIC}"')
    write(tmp_path / "node_modules" / "x.js", f'k="{ANTHROPIC}"')
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + ANTHROPIC.encode())
    assert scan(str(tmp_path)).findings == []


def test_cli_exit_codes_and_formats(tmp_path, capsys):
    write(tmp_path / "config.yaml", "host: 0.0.0.0\nauth: false\n")
    assert main(["scan", str(tmp_path)]) == 1
    assert main(["scan", str(tmp_path), "--fail-on", "never"]) == 0
    assert main(["scan", str(tmp_path / "missing")]) == 2
    capsys.readouterr()

    assert main(["scan", str(tmp_path), "--format", "json", "--fail-on", "never"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["critical"] == 1 and data["score"] < 100

    assert main(["scan", str(tmp_path), "--format", "sarif", "--fail-on", "never"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]

    assert main(["scan", str(tmp_path), "--format", "markdown", "--fail-on", "never"]) == 0
    assert "| Severity |" in capsys.readouterr().out


def test_output_file(tmp_path):
    write(tmp_path / "config.yaml", "debug: true\n")
    out = tmp_path / "report.json"
    assert main(["scan", str(tmp_path), "--format", "json", "--fail-on", "never", "-o", str(out)]) == 0
    assert json.loads(out.read_text())["files_scanned"] >= 1


def test_rules_command_lists_everything(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "HA-SEC-001" in out and "HA-MCP-005" in out and "HA-NET-900" in out


def test_demo_project_triggers_every_severity(tmp_path):
    folder = write_demo_project(str(tmp_path / "demo"))
    result = scan(folder)
    counts = result.counts()
    assert counts["critical"] >= 4 and counts["high"] >= 8 and counts["medium"] >= 5
    assert result.score() == 0


def test_code_rules_skip_comments_and_definitions(tmp_path):
    write(tmp_path / "a.py",
          "# eval(x) is dangerous\ndef eval(self, code):\n    pass\nvalue = eval(code)\n")
    lines = [f.line for f in scan(str(tmp_path)).findings if f.rule_id == "HA-CODE-002"]
    assert lines == [4]


def test_weak_credentials(tmp_path):
    write(tmp_path / "a.py", "client = Client(password=password, token=token)\n")
    assert "HA-AUTH-002" not in ids(scan(str(tmp_path)))
    write(tmp_path / "b.yaml", "db:\n  password: admin\n")
    write(tmp_path / "c.json", '{"password": "changeme"}\n')
    result = scan(str(tmp_path))
    files = {f.file for f in result.findings if f.rule_id == "HA-AUTH-002"}
    assert files == {"b.yaml", "c.json"}


def test_openclaw_style_gateway_bind_and_bot_token(tmp_path):
    write(tmp_path / "openclaw.json",
          '{\n  "gateway": {"bind": "lan", "port": 18789},\n'
          '  "channels": {"telegram": {"bot_token": "' + "7391" + "20485" + ":" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3kL" + '"}}\n}\n')
    result = scan(str(tmp_path))
    assert "HA-NET-002" in ids(result)
    assert {"HA-SEC-006", "HA-SEC-009"} & ids(result)
    write(tmp_path / "ok.json", '{"gateway": {"bind": "loopback"}}')
    assert all(f.file != "ok.json" for f in scan(str(tmp_path)).findings)


def test_new_provider_keys(tmp_path):
    groq = "gs" + "k_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2"
    notion = "nt" + "n_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    hf = "h" + "f_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5"
    write(tmp_path / "a.py", f'A = "{groq}"\nB = "{notion}"\nC = "{hf}"\n')
    result = scan(str(tmp_path))
    assert {"HA-SEC-010", "HA-SEC-011", "HA-SEC-012"} <= ids(result)
    for finding in result.findings:
        assert groq not in finding.evidence and hf not in finding.evidence


def test_osascript_built_from_variables(tmp_path):
    write(tmp_path / "mac_tools.py",
          "import subprocess\n"
          "def quit_app(name):\n"
          "    ok, out = _run([\"osascript\", \"-e\", f'tell application \"{name}\" to quit'])\n"
          "def set_volume(level):\n"
          "    ok, out = _run([\"osascript\", \"-e\", f\"set volume output volume {level}\"])\n"
          "def fixed():\n"
          "    ok, out = _run([\"osascript\", \"-e\", 'tell application \"Finder\" to activate'])\n")
    lines = [f.line for f in scan(str(tmp_path)).findings if f.rule_id == "HA-CODE-005"]
    assert lines == [3, 5]  # the fixed string on line 7 is not flagged


def test_subprocess_variable_is_low_severity_review(tmp_path):
    write(tmp_path / "a.py",
          "import subprocess\n"
          "subprocess.run(cmd)\n"
          "subprocess.run(cmd, capture_output=True, text=True, timeout=20)\n"
          "subprocess.run([\"open\", str(path)], check=False)\n"
          "subprocess.run(cmd.split())\n")
    findings = [f for f in scan(str(tmp_path)).findings if f.rule_id == "HA-CODE-006"]
    assert [f.line for f in findings] == [2, 3]
    assert all(f.severity == "low" for f in findings)


def test_env_severity_depends_on_git_repo(tmp_path):
    project = tmp_path / "proj"
    write(project / ".env", "MODEL_API_KEY=r8Kd29xQvLmZpT4WnB7s\n")
    env = [f for f in scan(str(project)).findings if f.rule_id == "HA-ENV-001"]
    assert env and env[0].severity == "medium"
    (project / ".git").mkdir()
    env = [f for f in scan(str(project)).findings if f.rule_id == "HA-ENV-001"]
    assert env and env[0].severity == "high"


def test_veda_like_voice_assistant_project(tmp_path):
    write(tmp_path / "notion_tools.py",
          "import os\nHEADERS = {\n    \"Authorization\": f\"Bearer {os.environ['NOTION_TOKEN']}\",\n}\n")
    write(tmp_path / "voice_agent.py", "import subprocess\n\ndef speak(cmd):\n    subprocess.run(cmd)\n")
    write(tmp_path / ".env", "GROQ_API_KEY=" + "gs" + "k_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2\n")
    write(tmp_path / ".gitignore", ".env\n")
    result = scan(str(tmp_path))
    assert "HA-SEC-010" not in ids(result)  # a key in a git-ignored .env is the right place
    assert "HA-CODE-006" in ids(result)
    assert all(f.file != "notion_tools.py" for f in result.findings)  # env-var token is fine


def test_provider_keys_still_flagged_outside_real_env_files(tmp_path):
    groq = "gs" + "k_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2"
    write(tmp_path / ".env.example", f"GROQ_API_KEY={groq}\n")
    write(tmp_path / "agent.py", f'KEY = "{groq}"\n')
    flagged = {f.file for f in scan(str(tmp_path)).findings if f.rule_id == "HA-SEC-010"}
    assert flagged == {".env.example", "agent.py"}


def test_unquoted_yaml_and_ini_secrets(tmp_path):
    secret = "Zk93TqLm82VdXw7RpA1b2C3d"
    write(tmp_path / "a.yaml", f"llm:\n  provider: acme\n  api_key: {secret}\n  openai_api_key: {secret}\n")
    write(tmp_path / "b.ini", f"[auth]\naccess_token = {secret}\n")
    write(tmp_path / "c.yaml", f"services:\n  app:\n    environment:\n      - DB_PASSWORD={secret}\n")
    result = scan(str(tmp_path))
    flagged = {(f.file, f.line) for f in result.findings if f.rule_id == "HA-SEC-009"}
    assert flagged == {("a.yaml", 3), ("a.yaml", 4), ("b.ini", 2), ("c.yaml", 4)}
    for finding in result.findings:
        assert secret not in finding.evidence


def test_unquoted_secret_rule_ignores_references_and_placeholders(tmp_path):
    write(tmp_path / "ok.yaml",
          "a:\n"
          "  api_key: ${API_KEY}\n"
          "  token: ${{ secrets.GITHUB_TOKEN }}\n"
          "  api_key: your_api_key_goes_here_12345\n"
          "  password: \"\"\n"
          "  api_key_file: /etc/secrets/openai_api_key_file\n"
          "  token: short\n"
          "  token_url: https://auth.example.net/oauth/token\n"
          "  public_key: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n")
    assert scan(str(tmp_path)).findings == []


def test_quoted_secret_with_access_token_key(tmp_path):
    write(tmp_path / "a.json", '{"access_token": "Zk93TqLm82VdXw7RpA1b2C3d"}\n')
    assert "HA-SEC-009" in ids(scan(str(tmp_path)))


def test_unquoted_secret_in_a_real_env_file_is_left_to_env_rules(tmp_path):
    write(tmp_path / ".env", "SERVICE_TOKEN=Zk93TqLm82VdXw7RpA1b2C3d\n")
    write(tmp_path / ".gitignore", ".env\n")
    os.chmod(tmp_path / ".env", 0o600)
    assert scan(str(tmp_path)).findings == []


def test_exposed_debuggers(tmp_path):
    write(tmp_path / "start.sh",
          "node --inspect=0.0.0.0:9229 server.js\n"
          "node --inspect-brk=0.0.0.0:9230 server.js\n"
          "python -m debugpy --listen 0.0.0.0:5678 app.py\n"
          "node --inspect=127.0.0.1:9229 server.js\n"
          "node --inspect server.js\n"
          "node --inspect=[::1]:9229 server.js\n")
    write(tmp_path / "dbg.py", "import debugpy\ndebugpy.listen((\"0.0.0.0\", 5678))\n")
    write(tmp_path / "Dockerfile", "CMD java -agentlib:jdwp=transport=dt_socket,server=y,address=*:5005 -jar app.jar\n")
    result = scan(str(tmp_path))
    flagged = sorted((f.file, f.line) for f in result.findings if f.rule_id == "HA-NET-003")
    assert flagged == [("Dockerfile", 1), ("dbg.py", 2), ("start.sh", 1), ("start.sh", 2), ("start.sh", 3)]
    assert all(f.severity == "critical" for f in result.findings if f.rule_id == "HA-NET-003")


def test_deno_all_permissions(tmp_path):
    write(tmp_path / "run.sh",
          "deno run -A main.ts\n"
          "deno run --allow-all main.ts\n"
          "deno run --allow-net=api.example.com main.ts\n")
    write(tmp_path / "script.ts", "#!/usr/bin/env -S deno run -A\nconsole.log('hi');\n")
    result = scan(str(tmp_path))
    flagged = sorted((f.file, f.line) for f in result.findings if f.rule_id == "HA-SBX-007")
    assert flagged == [("run.sh", 1), ("run.sh", 2), ("script.ts", 1)]


def test_debug_and_console_routes(tmp_path):
    write(tmp_path / "server.js",
          "app.get('/debug', handler);\n"
          "router.use(\"/__debug__\", dbg);\n"
          "app.get('/debugging-guide', page);\n"
          "app.get('/api/users', users);\n")
    write(tmp_path / "app.py", "@app.route(\"/console\")\ndef c():\n    pass\n")
    write(tmp_path / "main.ts", "if (url.pathname === \"/debug\") { return dump(); }\n")
    result = scan(str(tmp_path))
    flagged = sorted((f.file, f.line) for f in result.findings if f.rule_id == "HA-CODE-007")
    assert flagged == [("app.py", 1), ("main.ts", 1), ("server.js", 1), ("server.js", 2)]
