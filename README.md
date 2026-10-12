# Python Project 002 — Netstat IP Investigator

**Purpose:** Inspect your own or authorized Windows 10/11 machine's **ESTABLISHED** TCP connections using the Windows `netstat -ano` command, correlate each connection with its PID and running process via `tasklist`, and flag connections that deserve *human investigation*. This is a defensive SOC training project.

## Quick start (Windows 11)

1. Unzip the project, open the extracted folder in PowerShell.
2. Make sure Python 3.10+ is installed: `py --version`.
3. Launch the desktop UI:
   ```powershell
   py app.py
   ```
4. Click **Refresh connections**, click a row for its details, and use **Review only** to filter.
5. To export a snapshot, click **Export CSV**.

**No pip installation required.** All code uses the Python standard library. No administrator privileges are needed for most per-process enumeration, but some process names may be unavailable, especially without elevation.

## How it works

```text
netstat -ano (ESTABLISHED TCP, endpoints + PID)
   | parse IPv4/IPv6, local/remote endpoint, port and PID
   v
tasklist /FO CSV /NH (PID -> image name)
   | combine and apply cautious triage flags
   v
Tkinter table -> selected details -> optional manual AbuseIPDB check -> CSV export
```

### Triage flags

- **Local:** non-public IP (loopback, private LAN, special-use). Not checked against public IP reputation services.
- **Routine:** global IP on a commonly seen service port; **not** a claim of trust.
- **Review:** public connection on a less-common or noteworthy TCP port (e.g., 4444, 3389, 445), a public connection associated with a script host such as `powershell.exe`, or a public peer associated with an exposed local service port. These are only contextual prompts, **not evidence of malware**.

A TCP socket snapshot does **not** prove whether the host initiated the connection or whether the remote IP is malicious. Legitimate software commonly uses less-common ports, and malicious actors also use port 443. A no-hit reputation lookup does **not** prove safety.

## Optional reputation lookup: AbuseIPDB

- Create your *own* API key at https://www.abuseipdb.com/ .
- Paste it into the masked **AbuseIPDB API key** field (it stays in application memory and is not written to CSV or disk).
- Select a **public** IP, then click **Check selected IP reputation** and confirm the third-party disclosure prompt.
- The service returns `abuseConfidenceScore`, `totalReports`, ISP and country, using reports from the last 90 days. These scores reflect **community-supplied information**, not absolute truth.
- Never paste credentials into screenshots or chat. No IP reputation lookups happen automatically.

API: https://docs.abuseipdb.com/#check-endpoint

## Command-line usage

```powershell
py cli.py
py cli.py --review-only
py cli.py --export connections.csv
```

For a **synthetic demo**, which does not read your system's actual connections:

```powershell
py app.py --demo
py cli.py --demo --review-only
```

The synthetic examples include real public resolver IPs on hypothetical endpoints. They do **not** imply that those IPs are suspicious in real life.

## Unit tests

```powershell
py -m unittest discover -s tests -v
```

## Manual Windows validation

```powershell
netstat -ano | findstr /I ESTABLISHED
tasklist /FI "PID eq 1234"
Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
```

Replace `1234` with a PID shown by the program.

## Security / privacy

- Read-only network monitoring. **Does not** disable processes, kill connections, block IPs, or probe other systems.
- No automatic IP lookups: a selected public IP is sent to AbuseIPDB only after you confirm.
- Never shares the local process inventory with AbuseIPDB.
- CSV includes IP addresses, PIDs, and process names: treat exports as potentially sensitive.
- The API key is kept only in memory; it is not persisted, although the entry widget retains it while the app is open.
- The monitor shows a momentary snapshot, not continuous flow history. For reliable incident analysis, use supporting telemetry such as Windows Event Logs, Sysmon and endpoint security logs.

## Troubleshooting

- **`'py' is not recognized`:** Install Python with the launcher, or try `python app.py`.
- **`netstat` cannot run:** Confirm you are on Windows and can execute `netstat -ano` in PowerShell.
- **`Unknown` process:** PID exited between `netstat` and `tasklist`, or process visibility is restricted.
- **Empty table:** There may be no established TCP connections at that instant. Try using a browser, then click Refresh.
- **Lookup failed:** Check API key, connectivity, and AbuseIPDB quota; retry later.
- **Running on Linux/macOS:** Live mode is Windows-only. Run `python app.py --demo` and the unit tests for the offline exercise.

## Student learning outcomes

Learn TCP connection states, source/destination endpoints, process correlation, IPv4/IPv6 parsing, subprocess execution, basic network threat triage, safe threat-intelligence enrichment, Tkinter GUIs, CSV evidence preservation, and defensive coding.
