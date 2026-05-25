#!/usr/bin/env python3
"""
Pre-populate Open WebUI with Yashigani agent models.

Run inside the open-webui container:
  podman exec open-webui python3 /tmp/init-openwebui-agents.py

Inserts agent models directly into Open WebUI's SQLite DB.
Idempotent — skips agents that already exist.
"""
import json
import os
import sqlite3
import time

DB_PATH = os.getenv("OWUI_DB_PATH", "/app/backend/data/webui.db")

# Admin user ID — first user created in Open WebUI (auto-provisioned via trusted header)
ADMIN_USER_ID = os.getenv("OWUI_ADMIN_USER_ID", "")

AGENTS = [
    {
        "id": "@Langflow",
        "name": "Lala — Workflow Builder",
        "base_model_id": "qwen2.5:3b",
        "description": (
            "Visual multi-agent workflow builder by DataStax. "
            "Best for: building custom AI pipelines, chaining multiple steps, "
            "connecting to external APIs, and creating reusable automation workflows.\n\n"
            "Try these examples:\n"
            "• \"Summarise this document and then translate the summary to Portuguese\"\n"
            "• \"Check the weather API, then draft an email based on the forecast\"\n"
            "• \"Extract key points from this text, classify their sentiment, and create a report\""
        ),
    },
    {
        "id": "@Letta",
        "name": "Julietta — Memory Agent",
        "base_model_id": "qwen2.5:3b",
        "description": (
            "Stateful agent with persistent memory (formerly MemGPT). "
            "Best for: long-running projects where context matters across sessions, "
            "personal assistant tasks, research that builds over time, and remembering "
            "your preferences and past conversations.\n\n"
            "Try these examples:\n"
            "• \"Remember that our Q2 budget is £50K and the deadline is June 30th\"\n"
            "• \"What did we discuss about the security audit last time?\"\n"
            "• \"I prefer bullet points over paragraphs — remember that for all future responses\""
        ),
    },
    {
        "id": "@OpenClaw",
        "name": "Scout — Connected Agent",
        "base_model_id": "qwen2.5:3b",
        "description": (
            "AI agent with 30+ messaging channel integrations. "
            "Best for: tasks that need web access, code execution, file management, "
            "and connecting to external services like Slack, Teams, or email.\n\n"
            "Try these examples:\n"
            "• \"Search the web for the latest OWASP Top 10 changes and summarise them\"\n"
            "• \"Write a Python script that parses a CSV file and finds duplicates\"\n"
            "• \"Draft a Slack message announcing the new security policy\""
        ),
    },
]


def main():
    db = sqlite3.connect(DB_PATH)

    # Find the admin user ID if not provided
    admin_id = ADMIN_USER_ID
    if not admin_id:
        row = db.execute(
            "SELECT id FROM user WHERE role = 'admin' ORDER BY created_at LIMIT 1"
        ).fetchone()
        if row:
            admin_id = row[0]
        else:
            # No admin yet — use a placeholder (will be adopted by first admin login)
            admin_id = "00000000-0000-0000-0000-000000000000"

    now = int(time.time())

    for agent in AGENTS:
        # Check if exists
        existing = db.execute(
            "SELECT id FROM model WHERE id = ?", (agent["id"],)
        ).fetchone()
        if existing:
            print("EXISTS: " + agent["name"])
            continue

        meta = json.dumps({
            "description": agent["description"],
            "profile_image_url": "",
            "capabilities": {"usage": True},
        })

        db.execute(
            "INSERT INTO model (id, user_id, base_model_id, name, meta, params, created_at, updated_at, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (agent["id"], admin_id, agent["base_model_id"], agent["name"],
             meta, "{}", now, now, True),
        )
        print("OK: " + agent["name"])

    db.commit()
    db.close()
    print("Done")


if __name__ == "__main__":
    main()
