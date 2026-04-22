import ctypes
import shutil
import sys
import time


RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
CYAN = "\033[36m"
GRAY = "\033[90m"


def enable_ansi():
    if sys.platform != "win32":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def width():
    return max(72, shutil.get_terminal_size((96, 24)).columns)


def center(text):
    return text.center(width())


def slow(text, color="", delay=0.005):
    for ch in text:
        sys.stdout.write(f"{color}{ch}{RESET}" if color else ch)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()


def boot_animation(target):
    enable_ansi()
    lines = [
        "binding to local console",
        "resolving command surface",
        "loading non-admin inspection chain",
        f"target path -> {target}",
    ]
    for line in lines:
        slow(center(line), color=GRAY, delay=0.0025)
    sys.stdout.write("\n")
    slow(center("KERNELPANIC // LOCAL AUDIT"), color=RED, delay=0.003)
    slow(center("quiet windows exposure mapping"), color=CYAN, delay=0.002)
    sys.stdout.write("\n")
    sys.stdout.flush()


def print_report_location(path):
    sys.stdout.write("\n")
    slow(center("report written"), color=GREEN, delay=0.002)
    slow(center(path), color=CYAN, delay=0.0015)


def pulse_line(results):
    total = max(48, min(width() - 10, 96))
    confirmed = len([item for item in results.get("findings", []) if item.get("confidence") == "confirmed"])
    critical = len([item for item in results.get("findings", []) if item.get("level") == "critical"])
    high = len([item for item in results.get("findings", []) if item.get("level") == "high"])
    step = max(6, total // 12)
    chars = []
    for index in range(total):
        if index % step == step - 2:
            spike = critical > 0 or (high > 0 and index % (step * 2) == step - 2)
            chars.append(f"{RED}#{RESET}" if spike else f"{GREEN}#{RESET}")
        elif index < min(total, confirmed * 2):
            chars.append(f"{GREEN}#{RESET}")
        else:
            chars.append(f"{GRAY}#{RESET}")
    sys.stdout.write("\n")
    sys.stdout.write(center("[" + "".join(chars) + "]") + "\n")
    sys.stdout.flush()
