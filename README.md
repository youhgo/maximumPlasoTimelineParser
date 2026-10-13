# MaximumPlasoParserJson ![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![License](https://img.shields.io/github/license/youhgo/maximumPlasoTimelineParser) ![Dependencies](https://img.shields.io/badge/dependencies-0%20(Standard%20Library)-brightgreen)

**MaximumPlasoParserJson** is a lightweight, fast, and dependency-free Python tool to parse and triage [Plaso – Log2Timeline](https://github.com/log2timeline/plaso) JSON_line (`json_line`) timelines for Windows forensic investigations.

MaximumPlasoParserJson categorizes forensic artifacts into dedicated, **human-readable CSV files** and generates a clean, deduplicated, and chronologically sorted unified **`timeline.csv`**, as well as a consolidated **`persistence.csv`** report.

---

## Features

- **Zero external dependencies**: Uses only the Python standard library (`xml.etree.ElementTree`, `csv`, `json`, `datetime`). No `pip install` or `requirements.txt` needed.
- **Strict UTC timestamps**: Accurate microsecond epoch conversion without local workstation timezone drift.
- **Date range filtering (`--start-date`, `--end-date`)**: Fast numeric epoch comparison to isolate attack windows and skip irrelevant events instantly.
- **Consolidated Persistence Report (`persistence.csv`)**: Groups and unifies services, scheduled tasks, Run keys, Startup folders, WMI event subscriptions, Sysmon ASEP registry modifications, account creations, and privileged group changes.
- **High-priority DFIR triage**:
  - **Sysmon** (Event IDs 1: Process, 3: Network, 7: DLLs, 8/10: Injection/LSASS Access, 11: FileCreate, 12-14: Registry ASEP, 22: DNS).
  - **Log Tampering / Anti-Forensics** (Security 1102 and System 104 log cleared).
  - **Account and Group privilege changes** (4720, 4728, 4732, 4756, 4738 with member names).
  - **Windows Defender** detections (1116-1119) and tampering/exclusions (5001, 5007).
  - **Services** (System 7045 and Security 4697 merged).
  - **PowerShell** (4104 ScriptBlock, 4103 Module Logging, 400/600).
  - **Execution artifacts**: Amcache, AppCompat ShimCache, Prefetch, UserAssist, SRUM, MRU, MUICache.
  - **File and Navigation**: MFT, USN Journal, FILESTAT, LNK shortcuts, Browser history.
- **Multi-line CSV integrity**: Uses `csv.reader` to prevent multi-line scripts (PowerShell, WMI) from being fragmented.
- **Forensic summary report**: Displays an executive findings summary directly in the terminal upon completion.

---

## Getting Started

### 1. Requirements

**None.** `MaximumPlasoParserJson.py` runs out-of-the-box on any Python 3.9+ installation without installing any third-party packages.

```bash
python3 --version
```

---

### 2. Prepare a Plaso Timeline

MaximumPlasoParserJson expects a **JSON_line formatted Plaso timeline**:

```bash
psteal.py --source /home/user/DFIR-Evidence -w timeline.json -o json_line
```

---

### 3. Run MaximumPlasoParserJson

#### Full Timeline Parse
```bash
python3 MaximumPlasoParserJson.py -t /path/to/timeline.json -o /path/to/output/ -m "WORKSTATION-01"
```

#### Fast Scoped Parse (Incident Response Window)
```bash
python3 MaximumPlasoParserJson.py -t /path/to/timeline.json -o /path/to/output/ -m "WORKSTATION-01" \
    --start-date "2023-10-01" --end-date "2023-10-15"
```

---

## Command-line Flags

| Flag | Variation | Required | Description |
|---|---|---|---|
| `-t` | `--timeline` | **Yes** | Path to the JSON_line Plaso timeline file |
| `-o` | `--output` | **Yes** | Destination directory for results |
| `-m` | `--machine_name` | No | Analyzed machine name (used in directory and report) |
| `-s` | `--separator` | No | CSV delimiter (default: `\|`) |
| | `--start-date` | No | Filter events on or after date (`YYYY-MM-DD` or `'YYYY-MM-DD HH:MM:SS'` UTC) |
| | `--end-date` | No | Filter events on or before date (`YYYY-MM-DD` or `'YYYY-MM-DD HH:MM:SS'` UTC) |

---

## Output Artifacts

All extracted CSVs and reports are stored inside `mpp_<machine_name>_<timestamp>/`:

```
├── summary_report.txt       <-- Forensic executive summary report
└── csv_results/
    ├── timeline.csv         <-- Unified, chronologically sorted timeline
    ├── persistence.csv      <-- [!] Consolidated Persistence: Services, Tasks, Run keys, WMI, Startup, ASEP
    ├── log_cleared.csv      <-- [!] Critical: Audit log cleared (1102 / 104)
    ├── sysmon_proc.csv      <-- Sysmon Event 1: Process Creation & hashes
    ├── sysmon_network.csv   <-- Sysmon Event 3: Network Connections
    ├── sysmon_dns.csv       <-- Sysmon Event 22: DNS Queries
    ├── sysmon_access.csv    <-- Sysmon Events 8 & 10: Injections & LSASS Access
    ├── sysmon_file.csv      <-- Sysmon Event 11: File Creation
    ├── sysmon_registry.csv  <-- Sysmon Events 12-14: Registry Persistence
    ├── sysmon_module.csv    <-- Sysmon Event 7: Loaded DLLs & signatures
    ├── 4624.csv             <-- Successful logons
    ├── 4625.csv             <-- Failed logons with failure reason
    ├── 4672.csv             <-- Special privilege logons
    ├── 4648.csv             <-- Explicit credential logons
    ├── 4688.csv             <-- Process creation
    ├── 7045.csv             <-- New service installations (7045 & 4697)
    ├── user_modification.csv<-- Account modifications & Group additions (4728, 4732, etc.)
    ├── windefender.csv      <-- Defender detections & exclusions/tampering (5001, 5007)
    ├── powershell.csv       <-- PowerShell host applications & Module logging (4103)
    ├── script_powershell.csv<-- PowerShell Script Block logging (4104)
    ├── tscheduler.csv       <-- Scheduled tasks executions & actions
    ├── bits.csv             <-- BITS transfers & URLs
    ├── remote_rdp.csv       <-- Remote RDP connections (1149)
    ├── local_rdp.csv        <-- Local RDP session events (21, 24, 25, 39, 40)
    ├── wmi.csv              <-- WMI activity & consumer queries
    ├── wmi_failure.csv      <-- WMI errors & failed operations
    ├── amcache.csv          <-- Amcache program executions & SHA256 hashes
    ├── appcompat.csv        <-- AppCompatCache (ShimCache) records
    ├── prefetch.csv         <-- Prefetch execution & run counts
    ├── userassist.csv       <-- UserAssist GUI executions
    ├── sam.csv              <-- SAM user login counts
    ├── srum.csv             <-- System Resource Usage Monitor
    ├── run.csv              <-- Run & RunOnce autostart entries
    ├── mui_cache.csv        <-- MUICache execution references
    ├── mru.csv              <-- Shell MRU & Recent files
    ├── browser_history.csv  <-- Chrome, Edge & Firefox navigation & autofill
    ├── lnk.csv              <-- Windows shortcut files & working directories
    ├── mft.csv              <-- MFT, USN Journal & FileStat records
    ├── start_stop.csv       <-- Windows startup & shutdown events
    └── windows_info.csv     <-- Windows version & OS metadata
```

### Forensic Summary Report (`summary_report.txt`)

Upon completion, an executive summary report is displayed in the terminal and automatically saved to `summary_report.txt` in the root output folder:

```
======================================================================
          MAXIMUM PLASO PARSER JSON - FORENSIC SUMMARY
======================================================================
  Analyzed Machine   : DC-01
  Timeline Source    : /cases/timeline.json
  Date Filter        : 2023-10-01 to 2023-10-15 (UTC)
  Output Directory   : /cases/output/mpp_DC-01_2026-10-13_09_15_00
----------------------------------------------------------------------
  CRITICAL FORENSIC ALERTS:
    Consolidated Persistence Found    : 18  <-- [!] PERSISTENCE IDENTIFIED
    Logs Cleared (1102 / 104)         : 2   <-- [!] ALERT: LOGS CLEARED
    Sysmon Access / Injection (8/10)  : 3   <-- [!] ALERT: INJECTION / LSASS ACCESS
    Windows Defender Detections/Tamper: 1   <-- [!] ALERT: THREAT / TAMPERING
    User & Group Account Changes      : 8
    Service Installations (7045/4697) : 12

  EXECUTION & PERSISTENCE ARTIFACTS:
    User Logons (4624/4625/4672/4648) : 14,230
    Process Creation (Security 4688)  : 8,412
    Sysmon Process Creation (ID 1)    : 7,890
    Sysmon Network Connections (ID 3) : 1,450
    Sysmon DNS Queries (ID 22)        : 2,120
    Sysmon File Create (ID 11)        : 450
    Sysmon Registry ASEP (12/13/14)   : 180
    Sysmon Modules / DLLs (ID 7)      : 3,400
    PowerShell Commands & Scripts     : 650
    Scheduled Tasks (TaskScheduler)   : 45
    BITS Jobs Transfers               : 12
    WMI Activities & Failures         : 28
    RDP Connections (Local & Remote)  : 16

  SYSTEM & EVIDENCE OF EXECUTION ARTIFACTS:
    Amcache Executables               : 540
    AppCompat ShimCache               : 1,230
    Prefetch Executions               : 890
    UserAssist Applications           : 110
    MFT & USN Journal File Events     : 84,200
    Browser History Records           : 1,820
    LNK Shortcut Files                : 95
    Registry Keys (Run/MRU/MUI/Common): 640
----------------------------------------------------------------------
  Total Events Scanned from Plaso     : 2,450,110
  Total Forensic Events Extracted     : 128,421
  Events in Merged timeline.csv       : 128,421
  Consolidated in persistence.csv     : 18
  Processing Speed                    : 38,450 events/sec
  Execution Time                      : 0:01:03
======================================================================
  [+] All CSV files saved in: /cases/output/mpp_DC-01_2026-10-13_09_15_00/csv_results
  [+] Summary report saved in: /cases/output/mpp_DC-01_2026-10-13_09_15_00/summary_report.txt
======================================================================
```

---

## License & Disclaimer
This project is open-source under Apache License 2.0.
