# network-scanner

A fast, multithreaded TCP port scanner written in Python. Scans a target host for open ports, identifies services by port number, and attempts to grab banners from live services. Results can be saved to a JSON file.

---

## Features

- **Multithreaded** — hundreds of ports scanned concurrently via a thread pool
- **Banner grabbing** — retrieves version/greeting banners from open ports (SSH, FTP, SMTP, HTTP, etc.)
- **Flexible port ranges** — supports single ports, ranges, and comma-separated lists
- **Clean terminal output** — formatted table with port, service name, and banner
- **JSON output** — full scan report saved to disk with timestamp and metadata
- **Pure stdlib** — no third-party dependencies required

---

## Requirements

- Python 3.10 or newer (uses the `X | Y` union type hint syntax)
- No pip installs needed — uses only the Python standard library

---

## Installation

```bash
git clone https://github.com/<your-username>/network-scanner.git
cd network-scanner
```

That's it. No virtual environment or package installation required.

---

## Usage

```
python scanner.py <target> -p <ports> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `target` | Hostname or IP address to scan |
| `-p, --ports` | Port specification (see formats below) |
| `-t, --threads` | Number of concurrent threads (default: 100) |
| `-o, --output` | Save results to a JSON file |
| `--timeout` | Per-port connection timeout in seconds (default: 1.0) |

### Port formats

| Format | Example | Description |
|---|---|---|
| Single port | `80` | Scan only port 80 |
| Range | `1-1024` | Scan ports 1 through 1024 |
| List | `22,80,443` | Scan specific ports |
| Combined | `1-100,443,8080` | Mix of range and individual ports |

---

## Examples

**Scan common ports on a local host:**
```bash
python scanner.py 192.168.1.1 -p 1-1024
```

**Scan specific ports on a named host:**
```bash
python scanner.py scanme.nmap.org -p 22,80,443
```

**Full scan with 500 threads, save to JSON:**
```bash
python scanner.py 10.0.0.1 -p 1-65535 -t 500 -o report.json
```

**Slower scan with longer timeout (useful on lossy networks):**
```bash
python scanner.py 192.168.1.50 -p 1-1024 --timeout 3
```

---

## Sample output

```
[*] Resolved scanme.nmap.org → 45.33.32.156

[*] Scanning 45.33.32.156 — 3 port(s) with 100 threads

    Progress: 3/3 ports scanned

────────────────────────────────────────────────────────────
  Scan results for: 45.33.32.156
  Completed in:     1.43s
  Open ports found: 2
────────────────────────────────────────────────────────────

  PORT       SERVICE         BANNER
  ──────── ───────────── ──────────────────────────────
  22/tcp     ssh             SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  80/tcp     http            HTTP/1.0 200 OK
```

---

## JSON output format

```json
{
  "scan_info": {
    "target": "45.33.32.156",
    "ports_scanned": 1024,
    "open_ports": 2,
    "scan_duration_seconds": 3.142,
    "timestamp": "2026-03-16T10:00:00Z"
  },
  "results": [
    {
      "port": 22,
      "state": "open",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    },
    {
      "port": 80,
      "state": "open",
      "service": "http",
      "banner": "HTTP/1.0 200 OK\r\nDate: ..."
    }
  ]
}
```

---

## Legal & ethical use

Only scan hosts you own or have explicit written permission to test. Unauthorised port scanning may violate computer misuse laws in your jurisdiction.

---

## License

MIT
