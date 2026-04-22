import json

from .common import run_command


def fetch_tasks():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-ScheduledTask | "
        "Select-Object TaskName, TaskPath, State, Author, Description, URI | "
        "ConvertTo-Json -Depth 3",
    ]
    code, stdout, stderr = run_command(cmd)
    if code != 0:
        return {"error": stderr or stdout}
    try:
        data = json.loads(stdout) if stdout else []
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError:
        return {"error": "Failed to parse scheduled tasks JSON output"}


def run():
    tasks = fetch_tasks()
    if isinstance(tasks, dict) and tasks.get("error"):
        return tasks

    findings = []
    for task in tasks:
        name = f"{task.get('TaskPath', '')}{task.get('TaskName', '')}"
        lowered = name.lower()
        if any(word in lowered for word in ("update", "backup", "sync", "comp", "system")):
            findings.append(
                {
                    "task": name,
                    "state": task.get("State"),
                    "author": task.get("Author"),
                    "description": task.get("Description"),
                }
            )
    return findings
