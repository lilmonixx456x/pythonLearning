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


def clear_screen():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def terminal_width():
    return max(72, shutil.get_terminal_size((96, 24)).columns)


def center(text):
    width = terminal_width()
    return text.center(width)


def slow_print(text, delay=0.012, color=""):
    for char in text:
        sys.stdout.write(f"{color}{char}{RESET}" if color else char)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()


def glitch_line(text, flash=0.04):
    sys.stdout.write(f"{GRAY}{text}{RESET}\r")
    sys.stdout.flush()
    time.sleep(flash)
    sys.stdout.write(" " * len(text) + "\r")
    sys.stdout.flush()
    time.sleep(flash / 2)
    sys.stdout.write(f"{RED}{text}{RESET}\n")
    sys.stdout.flush()


def draw_frame(lines):
    width = terminal_width()
    border = f"{GRAY}+{'-' * (width - 4)}+{RESET}"
    sys.stdout.write(border + "\n")
    for line in lines:
        padded = line[: width - 4].ljust(width - 4)
        sys.stdout.write(f"{GRAY}| {RESET}{padded}{GRAY} |{RESET}\n")
    sys.stdout.write(border + "\n")
    sys.stdout.flush()


def boot_animation():
    enable_ansi()
    clear_screen()

    glitch_line("linking terminal...")
    time.sleep(0.08)
    glitch_line("loading local audit modules...")
    time.sleep(0.08)

    banner = [
        f"{DIM}silent local recon{RESET}",
        "",
        f"{BOLD}{RED}KERNELPANIC // WINDOWS RISK CHECK{RESET}",
        f"{GRAY}read-only audit surface map{RESET}",
    ]
    draw_frame([center(line) for line in banner])
    time.sleep(0.25)

    boot_lines = [
        "[ok] console mode prepared",
        "[ok] stdlib modules linked",
        "[ok] registry readers online",
        "[ok] share/service/task probes online",
        "[..] waiting for target path",
    ]
    for line in boot_lines:
        slow_print(center(line), delay=0.004, color=CYAN if "[ok]" in line else GRAY)
        time.sleep(0.05)
    sys.stdout.write("\n")
    sys.stdout.flush()


def start_section(title, subtitle=""):
    width = terminal_width()
    label = f" {title} "
    line = f"{GRAY}{'=' * max(0, (width - len(label)) // 2)}{RESET}{BOLD}{label}{RESET}"
    sys.stdout.write(line + "\n")
    if subtitle:
        sys.stdout.write(f"{DIM}{subtitle}{RESET}\n")
    sys.stdout.flush()


def run_check(label, func, *args):
    sys.stdout.write(f"{GRAY}[..]{RESET} {label}")
    sys.stdout.flush()
    started = time.time()
    try:
        result = func(*args)
    except Exception as exc:
        elapsed = time.time() - started
        sys.stdout.write(f"\r{RED}[!!]{RESET} {label} {DIM}({elapsed:.2f}s){RESET}\n")
        sys.stdout.flush()
        return {"error": str(exc)}
    elapsed = time.time() - started
    sys.stdout.write(f"\r{GREEN}[ok]{RESET} {label} {DIM}({elapsed:.2f}s){RESET}\n")
    sys.stdout.flush()
    return result


def print_report_location(path):
    sys.stdout.write("\n")
    slow_print(center("report committed to local disk"), delay=0.006, color=GRAY)
    slow_print(center(path), delay=0.004, color=CYAN)
