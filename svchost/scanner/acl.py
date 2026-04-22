import os
import re

from .system import run_command


WRITE_MARKERS = ("(F)", "(M)", "(W)", "(WD)", "(AD)", "(DC)", "(WDAC)", "(WO)")
GENERIC_PRINCIPALS = {
    "everyone",
    "everyone ",
    "builtin\\users",
    "users",
    "authenticated users",
    "nt authority\\authenticated users",
    "interactive",
}


def get_identity_context():
    user = os.environ.get("USERNAME", "").strip()
    domain = os.environ.get("USERDOMAIN", "").strip()
    full_user = f"{domain}\\{user}".lower() if user and domain else user.lower()
    principals = {user.lower(), full_user, *GENERIC_PRINCIPALS}

    code, stdout, _ = run_command(["whoami", "/groups", "/fo", "csv", "/nh"])
    if code == 0:
        for line in stdout.splitlines():
            cols = [part.strip().strip('"') for part in line.split('","')]
            if cols:
                principals.add(cols[0].strip('"').lower())
    return {"user": user, "domain": domain, "principals": principals}


def icacls_output(path):
    code, stdout, stderr = run_command(["icacls", path])
    if code != 0 and not stdout:
        return {"error": (stderr or stdout).strip()}
    return {"text": stdout}


def principal_matches(principal, identity):
    cleaned = principal.strip().lower()
    if cleaned in identity["principals"]:
        return True
    if cleaned.endswith("\\users") or cleaned.endswith("\\authenticated users"):
        return True
    return False


def is_path_writable(path, identity):
    result = icacls_output(path)
    if result.get("error"):
        return {"path": path, "writable": False, "reason": result["error"]}

    for raw_line in result["text"].splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        if line.startswith("Successfully processed") or line.startswith("processed file"):
            continue
        principal, rights = line.split(":", 1)
        if principal_matches(principal, identity) and any(marker in rights for marker in WRITE_MARKERS):
            return {"path": path, "writable": True, "reason": f"{principal} {rights.strip()}"}
    return {"path": path, "writable": False, "reason": "no_write_ace_match"}


def find_writable_parent(path, identity):
    current = path
    seen = set()
    while current and current not in seen:
        seen.add(current)
        if os.path.exists(current):
            return is_path_writable(current, identity)
        parent = os.path.dirname(current.rstrip("\\/"))
        if not parent or parent == current:
            break
        current = parent
    return {"path": path, "writable": False, "reason": "no_existing_parent"}


def has_unquoted_space_path(command_line):
    text = (command_line or "").strip()
    return bool(text and " " in text and ".exe" in text.lower() and not text.startswith('"'))


def extract_candidate_hijack_paths(command_line):
    text = (command_line or "").strip().strip('"')
    if not text or ".exe" not in text.lower():
        return []
    prefix = text[: text.lower().find(".exe") + 4]
    parts = prefix.split("\\")
    if len(parts) < 2:
        return []
    candidates = []
    current = parts[0]
    for part in parts[1:]:
        current = current + "\\" + part
        if " " in current and not current.lower().endswith(".exe"):
            candidates.append(current + ".exe")
    return candidates
