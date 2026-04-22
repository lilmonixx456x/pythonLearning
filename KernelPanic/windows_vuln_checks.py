import sys

from checks import (
    run_admin_group_check,
    boot_animation,
    print_report_location,
    run_always_install_elevated_check,
    run_autologon_check,
    run_file_scan_check,
    run_check,
    run_hotfix_check,
    run_kaspersky_check,
    run_listener_check,
    run_local_users_check,
    run_path_write_check,
    run_service_check,
    run_service_unquoted_check,
    run_share_check,
    run_startup_check,
    start_section,
    run_task_check,
    run_uac_policy_check,
    run_unattend_check,
    write_report,
)
from checks.common import current_identity, is_windows


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Public"
    output = sys.argv[2] if len(sys.argv) > 2 else "windows_vuln_report.txt"

    if not is_windows():
        print("This script is intended to run on Windows.")
        sys.exit(1)

    boot_animation()
    start_section("scan", f"target path: {target}")

    hotfix_data = run_check("hotfix timeline", run_hotfix_check)
    data = {
        "identity": current_identity(),
        "latest_hotfix": hotfix_data["latest_hotfix"],
        "startup": run_check("startup paths", run_startup_check),
        "file_scan": run_check("suspicious file sweep", run_file_scan_check, target),
        "service_findings": run_check("service privilege review", run_service_check),
        "task_findings": run_check("scheduled task review", run_task_check),
        "listener_findings": run_check("network listener map", run_listener_check),
        "shares": run_check("smb share review", run_share_check),
        "always_install_elevated": run_check("alwaysinstallelevated policy", run_always_install_elevated_check),
        "autologon": run_check("autologon registry state", run_autologon_check),
        "unattend": run_check("unattend credential scan", run_unattend_check),
        "uac_policy": run_check("uac policy review", run_uac_policy_check),
        "path_writable": run_check("writable path directories", run_path_write_check),
        "service_unquoted": run_check("unquoted service paths", run_service_unquoted_check),
        "admin_group": run_check("local administrators group", run_admin_group_check),
        "local_users": run_check("local user weakness review", run_local_users_check),
        "kaspersky": run_check("kaspersky presence and state", run_kaspersky_check),
    }

    write_report(output, data)
    print_report_location(output)


if __name__ == "__main__":
    main()
