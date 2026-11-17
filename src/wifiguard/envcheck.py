"""Environment verification for the ``check`` subcommand.

Reports — honestly — whether this machine can actually do the job:
Linux, root, the aircrack-ng suite present, wireless interfaces
found, and whether any adapter advertises monitor mode. Monitor-mode
capability is reported as ``None`` ("unknown") when it cannot be
determined, never guessed.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class ToolInfo:
    name: str
    path: str | None
    required: bool
    install: str  # apt package that provides it
    needed_for: str = ""


@dataclass
class InterfaceInfo:
    name: str
    wireless: bool
    mode: str | None = None  # e.g. "managed", from `iw dev`


@dataclass
class EnvReport:
    os_name: str
    is_linux: bool
    is_root: bool
    tools: list[ToolInfo] = field(default_factory=list)
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    monitor_capable: bool | None = None

    @property
    def missing_required(self) -> list[ToolInfo]:
        return [t for t in self.tools if t.required and t.path is None]


_TOOLS = [
    # name, required, apt package, needed for
    ("airmon-ng", True, "aircrack-ng", "enabling monitor mode"),
    ("airodump-ng", True, "aircrack-ng", "scanning and capturing"),
    ("aircrack-ng", True, "aircrack-ng", "handshake checks and cracking"),
    ("aireplay-ng", True, "aircrack-ng", "the optional --deauth burst"),
    ("hashcat", False, "hashcat", "faster cracking (mode 22000)"),
    ("hcxpcapngtool", False, "hcxtools", "converting captures for hashcat"),
]


def parse_iw_dev(text: str) -> list[InterfaceInfo]:
    """Parse ``iw dev`` output into wireless interfaces (pure)."""
    interfaces: list[InterfaceInfo] = []
    current: InterfaceInfo | None = None
    for line in text.splitlines():
        m = re.search(r"Interface\s+(\S+)", line)
        if m:
            current = InterfaceInfo(name=m.group(1), wireless=True)
            interfaces.append(current)
            continue
        m = re.search(r"^\s+type\s+(\S+)", line)
        if m and current is not None:
            current.mode = m.group(1)
    return interfaces


def parse_ip_link_names(text: str) -> list[str]:
    """Parse interface names out of ``ip link`` output (pure)."""
    return re.findall(r"^\d+:\s+([^:@\s]+)", text, flags=re.MULTILINE)


def parse_iw_list_monitor(text: str) -> bool | None:
    """Does ``iw list`` advertise monitor mode? (pure)

    Returns True/False when the "Supported interface modes" section
    is found, None when it is not (capability unknown).
    """
    in_section = False
    found_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if "Supported interface modes:" in line:
            in_section = True
            found_section = True
            continue
        if in_section:
            if stripped.startswith("*"):
                if stripped == "* monitor":
                    return True
                continue
            in_section = False
    return False if found_section else None


def _run_text(run, argv: list[str]) -> str:
    try:
        proc = run(argv, capture_output=True, text=True, timeout=30)
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def check_environment(which=shutil.which, run=subprocess.run) -> EnvReport:
    """Probe the machine. ``which``/``run`` are injectable for tests."""
    tools = [
        ToolInfo(name=name, path=which(name), required=required,
                 install=pkg, needed_for=needed)
        for name, required, pkg, needed in _TOOLS
    ]

    interfaces: list[InterfaceInfo] = []
    monitor: bool | None = None
    if which("iw"):
        interfaces = parse_iw_dev(_run_text(run, ["iw", "dev"]))
        iw_list = _run_text(run, ["iw", "list"])
        if iw_list:
            monitor = parse_iw_list_monitor(iw_list)
    if not interfaces and which("ip"):
        names = parse_ip_link_names(_run_text(run, ["ip", "link"]))
        interfaces = [InterfaceInfo(name=n, wireless=False) for n in names]

    try:
        is_root = os.geteuid() == 0
    except AttributeError:
        is_root = False

    return EnvReport(
        os_name=sys.platform,
        is_linux=sys.platform.startswith("linux"),
        is_root=is_root,
        tools=tools,
        interfaces=interfaces,
        monitor_capable=monitor,
    )


def format_env_report(report: EnvReport) -> str:
    lines: list[str] = ["wifiguard environment check", "=" * 27]
    lines.append(f"OS: {report.os_name} "
                 f"({'Linux — OK' if report.is_linux else 'NOT Linux — capture/scan/crack need Linux'})")
    lines.append(f"Root: {'yes' if report.is_root else 'no — capture and scan need root (use sudo)'}")
    lines.append("")
    lines.append("Tools:")
    for tool in report.tools:
        if tool.path:
            status = f"OK ({tool.path})"
        elif tool.required:
            status = "MISSING (required)"
        else:
            status = "missing (optional)"
        lines.append(f"  {tool.name:<14} {status}")
    missing = report.missing_required
    if missing:
        packages = sorted({t.install for t in missing})
        lines.append("")
        lines.append("Install the missing required tools with:")
        lines.append(f"  sudo apt install {' '.join(packages)}")
    optional_missing = [t for t in report.tools
                        if not t.required and t.path is None]
    if optional_missing:
        packages = sorted({t.install for t in optional_missing})
        lines.append(f"  Optional (faster cracking): sudo apt install "
                     f"{' '.join(packages)}")
    lines.append("")
    lines.append("Interfaces:")
    if report.interfaces:
        for iface in report.interfaces:
            kind = "wireless" if iface.wireless else "unknown type"
            mode = f", mode {iface.mode}" if iface.mode else ""
            lines.append(f"  {iface.name} ({kind}{mode})")
    else:
        lines.append("  none found — is a WiFi adapter plugged in?")
    if report.monitor_capable is True:
        lines.append("Monitor mode: supported by at least one adapter.")
    elif report.monitor_capable is False:
        lines.append("Monitor mode: NOT advertised by any adapter — "
                     "capture will not work with this hardware.")
    else:
        lines.append("Monitor mode: unknown (could not determine — "
                     "install iw / check `iw list`).")
    return "\n".join(lines)
