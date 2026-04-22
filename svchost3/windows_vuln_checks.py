import os
import sys

from scanner import boot_animation, build_report, print_report_location, pulse_line, run_all_checks


def main():
    if os.name != "nt":
        print("This script is intended for Windows.")
        raise SystemExit(1)

    target = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Public"
    output = sys.argv[2] if len(sys.argv) > 2 else "windows_vuln_report.txt"

    boot_animation(target)
    results = run_all_checks(target)
    pulse_line(results)
    build_report(results, output)
    print_report_location(output)


if __name__ == "__main__":
    main()
