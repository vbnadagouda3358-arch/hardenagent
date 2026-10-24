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
