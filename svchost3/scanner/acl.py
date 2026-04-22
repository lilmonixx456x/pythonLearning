import os

from .system import powershell_json, run_command


GENERIC_PRINCIPALS = {
    "everyone",
    "builtin\\users",
    "users",
    "authenticated users",
    "nt authority\\authenticated users",
    "interactive",
}
WRITE_RIGHTS = {
    "write",
    "modify",
    "fullcontrol",
    "createfiles",
    "appenddata",
    "writedata",
    "writeattributes",
    "writeextendedattributes",
    "delete",
    "changedpermissions",
    "takeownership",
}
_ACL_CACHE = {}
_REGISTRY_ACL_CACHE = {}


def _normalize_principal(name):
    return (name or "").strip().lower()


def get_identity_context():
    user = os.environ.get("USERNAME", "").strip()
    domain = os.environ.get("USERDOMAIN", "").strip()
    full_user = f"{domain}\\{user}".lower() if user and domain else user.lower()
    principals = {user.lower(), full_user, *GENERIC_PRINCIPALS}

    code, stdout, _ = run_command(["whoami", "/groups", "/fo", "csv", "/nh"])
    if code == 0:
        for raw in stdout.splitlines():
            cols = [part.strip().strip('"') for part in raw.split('","')]
            if cols and cols[0]:
                principals.add(cols[0].strip('"').lower())
    return {"user": user, "domain": domain, "principals": principals}


def principal_matches(principal, identity):
    cleaned = _normalize_principal(principal)
    if cleaned in identity["principals"]:
        return True
    if cleaned.endswith("\\users") or cleaned.endswith("\\authenticated users"):
        return True
    return False


def _read_acl(path):
    if path in _ACL_CACHE:
        return _ACL_CACHE[path]
    safe_path = path.replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop';"
        f"$acl=Get-Acl -LiteralPath '{safe_path}';"
        "$acl.Access | Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited | ConvertTo-Json -Depth 4"
    )
    data = powershell_json(script, timeout=45)
    if isinstance(data, dict) and data.get("error"):
        _ACL_CACHE[path] = {"error": data["error"]}
    else:
        _ACL_CACHE[path] = data
    return _ACL_CACHE[path]


def is_path_writable(path, identity):
    data = _read_acl(path)
    if isinstance(data, dict) and data.get("error"):
        return {"path": path, "writable": False, "reason": data["error"], "matches": []}

    matches = []
    for ace in data:
        principal = ace.get("IdentityReference", "")
        rights = {part.strip().lower() for part in str(ace.get("FileSystemRights", "")).split(",")}
        access_type = str(ace.get("AccessControlType", "")).lower()
        if access_type != "allow":
            continue
        if not principal_matches(principal, identity):
            continue
        if rights & WRITE_RIGHTS:
            matches.append({"principal": principal, "rights": sorted(rights)})

    if matches:
        match_text = "; ".join(f"{item['principal']} => {','.join(item['rights'])}" for item in matches[:3])
        return {"path": path, "writable": True, "reason": match_text, "matches": matches}
    return {"path": path, "writable": False, "reason": "no_allow_write_match", "matches": []}


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
    return {"path": path, "writable": False, "reason": "no_existing_parent", "matches": []}


def _read_registry_acl(registry_path):
    if registry_path in _REGISTRY_ACL_CACHE:
        return _REGISTRY_ACL_CACHE[registry_path]
    safe_path = registry_path.replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop';"
        f"$acl=Get-Acl -Path '{safe_path}';"
        "$acl.Access | Select-Object IdentityReference, RegistryRights, AccessControlType, IsInherited | ConvertTo-Json -Depth 4"
    )
    data = powershell_json(script, timeout=45)
    if isinstance(data, dict) and data.get("error"):
        _REGISTRY_ACL_CACHE[registry_path] = {"error": data["error"]}
    else:
        _REGISTRY_ACL_CACHE[registry_path] = data
    return _REGISTRY_ACL_CACHE[registry_path]


def is_registry_path_writable(registry_path, identity):
    data = _read_registry_acl(registry_path)
    if isinstance(data, dict) and data.get("error"):
        return {"path": registry_path, "writable": False, "reason": data["error"], "matches": []}

    matches = []
    write_rights = {"setvalue", "createSubKey".lower(), "fullcontrol", "takeownership", "changepermissions", "writekey"}
    for ace in data:
        principal = ace.get("IdentityReference", "")
        rights = {part.strip().lower() for part in str(ace.get("RegistryRights", "")).split(",")}
        access_type = str(ace.get("AccessControlType", "")).lower()
        if access_type != "allow":
            continue
        if not principal_matches(principal, identity):
            continue
        if rights & write_rights:
            matches.append({"principal": principal, "rights": sorted(rights)})
    if matches:
        match_text = "; ".join(f"{item['principal']} => {','.join(item['rights'])}" for item in matches[:3])
        return {"path": registry_path, "writable": True, "reason": match_text, "matches": matches}
    return {"path": registry_path, "writable": False, "reason": "no_allow_write_match", "matches": []}


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
