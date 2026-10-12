"""Windows netstat parser and cautious triage heuristics. No network lookups here."""
from __future__ import annotations

import csv
import io
import ipaddress
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Tuple


NETSTAT_LINE = re.compile(r"^\s*TCP\s+(\S+)\s+(\S+)\s+ESTABLISHED\s+(\d+)\s*$", re.IGNORECASE)
REVIEW_PORTS = {23: "Telnet", 2323: "alternate Telnet", 4444: "frequently used by test tools", 5555: "uncommon service", 6667: "IRC", 31337: "unusual service", 3389: "RDP", 445: "SMB"}
COMMON_PORTS = {21, 22, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 636, 853, 993, 995, 8080, 8443, 5222, 5223, 8883}
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}
INBOUND_SERVICE_PORTS = {21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 5985, 5986}


@dataclass(frozen=True)
class Connection:
    local_host: str
    local_port: int
    remote_ip: str
    remote_port: int
    pid: int
    process: str = "Unknown"
    risk: str = "Routine"
    reason: str = ""

    @property
    def local_endpoint(self) -> str:
        return display_endpoint(self.local_host, self.local_port)

    @property
    def remote_endpoint(self) -> str:
        return display_endpoint(self.remote_ip, self.remote_port)

    @property
    def public(self) -> bool:
        return is_public_ip(self.remote_ip)


def split_endpoint(value: str) -> Tuple[str, int]:
    """Split Windows netstat IPv4 and [IPv6]:port endpoints."""
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or len(value) <= end + 2 or value[end + 1] != ":":
            raise ValueError("Malformed IPv6 endpoint")
        host, port_string = value[1:end], value[end + 2:]
    else:
        host, sep, port_string = value.rpartition(":")
        if not sep or not host:
            raise ValueError("Malformed TCP endpoint")
    # IPv6 interface zones from netstat (e.g., fe80::1%12) are fine for display.
    port = int(port_string)
    if not (0 <= port <= 65535):
        raise ValueError("Invalid TCP port")
    return host, port


def display_endpoint(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def clean_ip(host: str):
    host = host.split("%", 1)[0]
    addr = ipaddress.ip_address(host)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def is_public_ip(host: str) -> bool:
    try:
        return clean_ip(host).is_global
    except ValueError:
        return False


def parse_netstat(output: str) -> List[Connection]:
    connections = []
    for line in output.splitlines():
        match = NETSTAT_LINE.match(line)
        if not match:
            continue
        try:
            local_host, local_port = split_endpoint(match.group(1))
            remote_host, remote_port = split_endpoint(match.group(2))
            clean_ip(remote_host)  # do not accept hostname; netstat -n resolves none
            connections.append(Connection(local_host, local_port, remote_host, remote_port, int(match.group(3))))
        except (ValueError, OverflowError):
            continue
    return connections


def parse_tasklist(output: str) -> Dict[int, str]:
    pids = {}
    for row in csv.reader(io.StringIO(output)):
        if len(row) < 2:
            continue
        try:
            pid = int(row[1].replace(",", "").strip())
        except ValueError:
            continue
        pids[pid] = row[0].strip()
    return pids


def classify(conn: Connection) -> Tuple[str, str]:
    if not conn.public:
        return "Local", "Non-public address (loopback, LAN, link-local, or special-use)."
    findings = []
    if conn.local_port in INBOUND_SERVICE_PORTS and conn.remote_port >= 1024:
        findings.append(f"Public peer connected to local service port {conn.local_port}; review if unexpected (direction not confirmed).")
    elif conn.remote_port in REVIEW_PORTS:
        findings.append(f"Remote port {conn.remote_port} ({REVIEW_PORTS[conn.remote_port]}) merits context review.")
    elif conn.remote_port not in COMMON_PORTS:
        findings.append(f"Less-common remote TCP port {conn.remote_port}; may be legitimate application traffic.")
    if conn.process.lower() in SCRIPT_HOSTS:
        findings.append(f"{conn.process} has a public TCP connection; verify the script/process is expected.")
    if findings:
        return "Review", " ".join(findings)
    return "Routine", "Public IP using a commonly seen port; this alone does not establish safety."


def annotate(connections: Iterable[Connection], process_map: Dict[int, str]) -> List[Connection]:
    output = []
    for c in connections:
        with_process = Connection(c.local_host, c.local_port, c.remote_ip, c.remote_port, c.pid, process_map.get(c.pid, "Unknown"))
        risk, reason = classify(with_process)
        output.append(Connection(with_process.local_host, with_process.local_port,
                                 with_process.remote_ip, with_process.remote_port,
                                 with_process.pid, with_process.process, risk, reason))
    return sorted(output, key=lambda c: ({"Review": 0, "Routine": 1, "Local": 2}.get(c.risk, 3), c.remote_ip, c.remote_port))


def _run_win(cmd: List[str], timeout: int = 15) -> str:
    kwargs = {"capture_output": True, "text": True, "errors": "replace", "timeout": timeout, "check": False}
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    completed = subprocess.run(cmd, **kwargs)
    if completed.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed (exit code {completed.returncode}): {completed.stderr.strip()[:300]}")
    return completed.stdout


def get_live_connections() -> List[Connection]:
    import os
    if os.name != "nt":
        raise RuntimeError("Live netstat mode targets Windows. The offline tests work on other platforms.")
    raw = _run_win(["netstat", "-ano"])
    try:
        process_map = parse_tasklist(_run_win(["tasklist", "/FO", "CSV", "/NH"]))
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        process_map = {}
    return annotate(parse_netstat(raw), process_map)


def export_csv(path: str, connections: Iterable[Connection], reputation: Dict[str, dict] | None = None):
    reputation = reputation or {}
    snapshot = datetime.now().astimezone().isoformat(timespec="seconds")
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["captured_at", "risk", "local_endpoint", "remote_ip", "remote_port", "remote_endpoint", "pid", "process", "reason", "abuseipdb_confidence", "abuseipdb_reports_90d"])
        for c in connections:
            info = reputation.get(c.remote_ip, {})
            writer.writerow([snapshot, c.risk, c.local_endpoint, c.remote_ip, c.remote_port, c.remote_endpoint,
                             c.pid, c.process, c.reason, info.get("abuseConfidenceScore", ""), info.get("totalReports", "")])
