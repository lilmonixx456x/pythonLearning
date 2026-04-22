import json
import os
import re
import subprocess
from pathlib import Path


def run_command(args, timeout=60):
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except Exception as exc:
        return 1, "", str(exc)


def run_powershell(script, timeout=60):
    return run_command(["powershell", "-NoProfile", "-Command", script], timeout=timeout)


def powershell_json(script, timeout=60):
    code, stdout, stderr = run_powershell(script, timeout=timeout)
    if code != 0:
        return {"error": (stderr or stdout).strip()}
    stdout = stdout.strip()
    if not stdout:
        return []
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            return [data]
        return data
    except json.JSONDecodeError:
        return {"error": "json_parse_failed"}


def normalized_path(raw):
    if not raw:
        return ""
    value = raw.strip().strip('"').strip()
    value = re.sub(r"^[a-zA-Z]:", lambda match: match.group(0).upper(), value)
    return value


def expand_env_path(raw):
    return normalized_path(os.path.expandvars(raw))


def split_command_path(command_line):
    text = (command_line or "").strip()
    if not text:
        return "", ""
    if text.startswith('"'):
        end = text.find('"', 1)
        if end > 0:
            return normalized_path(text[1:end]), text[end + 1 :].strip()
    match = re.match(r"([A-Za-z]:\\[^ ]+?\.exe)\b(.*)", text, re.IGNORECASE)
    if match:
        return normalized_path(match.group(1)), match.group(2).strip()
    if " " in text:
        first, rest = text.split(" ", 1)
        return normalized_path(first), rest.strip()
    return normalized_path(text), ""


def first_existing_parent(path_text):
    if not path_text:
        return ""
    path = Path(path_text)
    while True:
        if path.exists():
            return str(path)
        if path.parent == path:
            return ""
        path = path.parent


def read_text_file(path, max_chars=100000):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except Exception:
        return ""


def existing_paths(paths):
    return [str(Path(path)) for path in paths if Path(path).exists()]


def write_json_file(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
