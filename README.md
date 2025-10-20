

# 🔍 Port Scanner & Banner Grabber — *Reconnaissance Tool*

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success)]()
[![Asura-Lord](https://img.shields.io/badge/author-Asura--Lord-black)]()

<!-- Decorative / "cool" badges (stylistic only) -->
[![Stealth Mode](https://img.shields.io/badge/Stealth-ON-black?logo=ghost&logoColor=white)]()
[![Recon Toolkit](https://img.shields.io/badge/Toolkit-Cyber--Recon-purple)]()
[![Speed](https://img.shields.io/badge/Speed-MultiThreaded-orange)]()
[![Mood](https://img.shields.io/badge/Mood-Stay%20Safe%2C%20Stay%20Dangerous-red)]()



A lightweight, fast, and beginner‑friendly **Nmap‑lite**: multi‑threaded port scanner with optional banner grabbing. Produces **clean CSV output** (by default, saves **only open ports**) and supports single hosts, IP ranges, and CIDR blocks.

---

## Overview

This tool helps you discover open ports and basic service banners on targets you own or have permission to test. It’s ideal for learning socket programming, reconnaissance basics, and quick sanity checks during pentesting labs.

**Key design goals:** simple, fast, safe, and actionable output.

---

## Features

- ✅ Multi‑threaded scanning (fast using `ThreadPoolExecutor`)  
- ✅ Banner grabbing with conservative probes (safe)  
- ✅ Target types: hostname/IP, IP range (`start-end`), or CIDR (`/24`)  
- ✅ Clean CSV outputs:
  - `--save-open` → **only open ports** (`host,port,banner`)  
  - `--save-all` → full results (`host,port,status,banner`)  
- ✅ Presets for common port lists (`--preset common|web`)  
- ✅ Optional colored console output if `colorama` is installed (no hard dependency)  
- ✅ Quiet/silent mode for scripting or CI (`--silent`)

---

## Screenshot (placeholder)

> Replace these with your screenshots in `/screenshots` for the repo.

```

![Scan example](screenshots/scan_example.png)
![CSV output](screenshots/csv_example.png)

````

---

## Quick Installation

```bash
git clone https://github.com/Asura-Lord/Port-Scanner.git
cd Port-Scanner

# Optional virtual environment
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

# colorama is optional (for nice terminal colors)
pip install colorama
````

> The scanner itself uses only Python standard library — `colorama` improves console aesthetics only.

---

## Usage & Examples

Show help / usage:

```bash
python port-scanner.py --help
```

Basic scan (default ports `1-1024`):

```bash
python port-scanner.py scanme.nmap.org
```

Examples

* Scan ports `1–200` with `200` threads (no save):

```bash
python port-scanner.py scanme.nmap.org -p 1-200 -t 200
```

* Scan and **save only open ports** (auto-named CSV):

```bash
python port-scanner.py scanme.nmap.org -p 1-200 --save-open
```

* Scan IP range and save opens:

```bash
python port-scanner.py 192.168.1.1-192.168.1.50 -p 1-1024 --save-open
```

* Scan CIDR block:

```bash
python port-scanner.py 192.168.1.0/28 -p 22,80 --save-open
```

* Save full results (all ports — large):

```bash
python port-scanner.py example.com -p 1-1000 --save-all full_scan.csv
```

* Use presets:

```bash
python port-scanner.py target.example --preset common
python port-scanner.py target.example --preset web
```

* Silent mode (summary only):

```bash
python port-scanner.py scanme.nmap.org --silent
```

---

## CSV Output Behavior (clean & practical)

* `--save-open` (recommended): creates a CSV containing **only open ports**. Columns: `host,port,banner`. Keeps files focused and human‑readable.
* `--save-all`: writes every scanned port with status. Columns: `host,port,status,banner`.
* If you pass `--save-open` or `--save-all` without a filename, the script auto‑generates a timestamped file like `open_ports_20251020_153000.csv`.

---

## Command Reference (options)

```
usage: port-scanner.py TARGET [-p PORTS] [-t THREADS] [-T TIMEOUT]
                             [--save-open [FILENAME]] [--save-all [FILENAME]]
                             [--save-auto] [--preset {common,web}] [--silent]

positional arguments:
  TARGET                hostname/IP, CIDR (x.x.x.x/28) or range (x.x.x.x-x.x.x.x)

optional arguments:
  -p, --ports           ports (e.g. 22,80,443 or 1-65535). Default: 1-1024
  -t, --threads         worker threads (default: 200)
  -T, --timeout         socket timeout seconds (default: 1.0)
  --save-open [FNAME]   save only OPEN ports to CSV (provide name or auto)
  --save-all [FNAME]    save full results (all ports) to CSV
  --save-auto           auto-save OPEN CSV if number of ports > threshold
  --preset              use preset port list: common or web
  --silent              quiet output (only summary)
```

---

## Safety & Legal

**Important:** Only scan networks and hosts you own or have explicit permission to test. Unauthorized scanning can be illegal and can trigger security alerts. For testing, use `scanme.nmap.org` (public test target by the Nmap project).

---

## Tips & Best Practices

* Increase `--threads` for faster scans on local networks; lower for remote/fragile hosts.
* Increase `--timeout` on slow/unstable networks to reduce false negatives.
* Prefer **`--save-open`** for actionable results — it avoids huge CSVs with `closed` rows.
* Install `colorama` if you want colored output:

  ```bash
  pip install colorama
  ```

---

## Roadmap (future enhancements)

* `--json` output option (structured output)
* Better HTTP fingerprinting for web services
* UDP scanning mode (special handling required)
* Rate limiting / polite delays for noisy networks
* Optional HTML report generator

---

## Contributing

Pull requests, issues and suggestions welcome. Keep changes small & focused. When contributing, include rationale and example runs.

---

## License

MIT License © 2025 Asura-Lord — see `LICENSE` file.

---

## Contact / Showcase

Find other tools in the Cybersecurity‑Toolkit. Want help integrating this into a CI or dashboard? Ping me on GitHub.

 *Stay Safe, Stay Dangerous* — **Asura‑Lord**

```


