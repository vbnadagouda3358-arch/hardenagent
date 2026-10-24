"""`hardenagent demo` writes a deliberately insecure sample agent project and scans it.

All keys below are fake and are assembled at runtime so this source file never
contains a complete token-shaped string.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

FAKE_ANTHROPIC = "sk-" + "ant-" + "api03-" + "Q7mZ4rT9vLk2WxP8aN5cB3dF6hJ1"
FAKE_AWS = "AK" + "IA" + "7Q2M9X4TLRV8PBN3"


def write_demo_project(base: str = "") -> str:
    root = Path(base or tempfile.mkdtemp(prefix="hardenagent-demo-"))
    root.mkdir(parents=True, exist_ok=True)
    (root / ".git").mkdir(exist_ok=True)  # marks the demo as a git repo

    (root / "config.yaml").write_text(
        "gateway:\n"
        "  host: 0.0.0.0\n"
        "  port: 18789\n"
        "  auth: false\n"
        "agent:\n"
        "  auto_approve: true\n"
        "  sandbox: false\n"
        "  allowed_tools: [\"*\"]\n"
        "  shell: true\n"
    )
    (root / "docker-compose.yml").write_text(
        "services:\n"
        "  agent:\n"
        "    image: my-agent:latest\n"
        "    privileged: true\n"
        "    ports:\n"
        "      - \"18789:18789\"\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n"
        "      - ~/.ssh:/root/.ssh\n"
    )
    (root / "mcp.json").write_text(
        "{\n"
        "  \"mcpServers\": {\n"
        "    \"files\": {\n"
        "      \"command\": \"npx\",\n"
        "      \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem\", \"/\"]\n"
        "    },\n"
        "    \"crm\": {\n"
        "      \"url\": \"http://crm.internal.example.net/mcp\",\n"
        "      \"headers\": {\"Authorization\": \"Bearer " + "Zk93" + "TqLm82VdXw7Rp" + "\"}\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    (root / "agent.py").write_text(
        "import os\nimport requests\n\n"
        f"ANTHROPIC_KEY = \"{FAKE_ANTHROPIC}\"\n"
        f"AWS_KEY = \"{FAKE_AWS}\"\n\n"
        "def run_tool(cmd):\n"
        "    os.system(cmd)\n"
        "    return eval(cmd)\n\n"
        "def fetch(url):\n"
        "    return requests.get(url, verify=False)\n"
    )
    (root / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "USER root\n"
        "RUN curl -fsSL https://get.example.net/install.sh | sh\n"
    )
    env_file = root / ".env"
    env_file.write_text("MODEL_API_KEY=" + "r8Kd" + "29xQvLmZpT4WnB7s" + "\n")
    try:
        os.chmod(env_file, 0o644)
    except OSError:
        pass
    return str(root)
