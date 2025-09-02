
# MaximumPlasoParser (MPP) ![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![License](https://img.shields.io/github/license/youhgo/maximumPlasoTimelineParser)

**MaximumPlasoParser (MPP)** is a Python script to parse [Plaso – Log2Timeline](https://github.com/log2timeline/plaso) JSON_line timelines. It only works with Windows artifacts.

MPP groups forensic artifacts by category and exports them in **human-readable CSV** or **JSON** for SIEM ingestion.


Need more forensic tools ? Checkout my awsome forensic artifcat parser project :) [Widown Forensic Artifact Parser Project](https://github.com/youhgo/wfapp),
MPP is included in !
---

## Features

- ✅ Group artifacts by category into separate files  
- ✅ Human-readable CSV output
- ✅ Fast: ~90 seconds to parse a 1.4 GB timeline  
- ✅ Easy to install: single Python script  

---

## Getting Started

### 1. Install Dependencies

```bash
pip3 install -r requirements.txt
```

**Only External dependency is**: [xmltodict](https://pypi.org/project/xmltodict/)  

---

### 2. Prepare a Timeline

MPP requires a **JSON_line formatted Plaso timeline**.  

```bash
psteal.py --source /home/user/DFIR-WorkStation -w timeline.json -o json_line
```

---

### 3. Run MPP

```bash
python3 MaximumPlasoParserJson.py -c "CaseName" --type "csv" -o /home/output/dir/ -t /home/path/to/json/timeline/timeline.json -m "MachineName"
```

---

## Example Outputs


```bash
cat 4624.csv
Date|time|event_code|subject_user_name|target_user_name|ip_address|ip_port|logon_type
[...]
2022-10-27|09:56:01|4624|DESKTOP-9I162HO$|System|-|-| 5
2022-10-27|09:56:06|4624|DESKTOP-9I162HO$|HRO|192.168.10.102|3389|10

cat App_compat_cache.csv
Date|Time| Name|FullPath|Hash 
[...]
2021-01-07|03:39:31|beacon.exe|C:\Users\Public\beacon.exe|e55e5b02ad40e9846a3cd83b00eec225fb987
2021-01-07|03:41:21|mimikatz.exe|C:\Users\Public\mimikatz.exe| e55e5b02ad40e9846a3cd83b00eec225fb987


cat windefender.csv
Date|time|EventCode|ThreatName|Severity|User|ProcessName|Path|Action 
[...]
2021-01-07|03:35:44|1116 - Detection|HackTool:Win64/Mikatz!dha|High|BROCELIANDE\arthur|C:\Users\Public\beacon.exe|Not Applicable
```

---

## Command-line Flags

| Flag     | Variation      | Required | Description                                             |
|----------|----------------|----------|---------------------------------------------------------|
| -t       | --timeline     | Yes      | Full path to JSON_line Plaso timeline                   |
| -o       | --output       | Yes      | Directory to save output files                          |
| -c       | --casename     | No       | Case name (used as JSON key for SIEM)                   |
| -s       | --separator    | No       | CSV separator (default: `\|`)                           |
| -m       | --machine_name | No       | Machine name (used in folder structure and JSON)        |
| --type   |                | No       | Output format: `csv`, `json`, or `all` (default: `csv`) |
| --config |                | No       | JSON config specifying which artifacts to parse         |

---

## Configuration

JSON config file controls which artifacts MPP will parse:

```json
{
  "4624usrLogon": 1,
  "4625usrFailLogon": 1,
  "4688newProc": 1,
  [...]
}
```

- `1` = parse  
- `0` = skip  

Default configuration enables all artifacts. 

A template is available : `mpp_config.json`.

---

## Supported Artifacts

```
├── 4624usrLogon.csv
├── 4625usrFailLogon.csv
├── 4648usrExpLogon.csv
├── 4672usrSpeLogon.csv
├── 4688newProc.csv
├── 7045newService.csv
├── amcache.csv
├── app_compat_cache.csv
├── applicationExperience.csv
├── bits.csv
├── chrome_History.csv
├── common_registry.csv
├── edge_History.csv
├── ff_history.csv
├── lnk.csv
├── mft.csv (+Usn)
├── mru.csv
├── mui_cache.csv
├── powershell.csv
├── powershellScript.csv
├── prefetch.csv
├── rdpLocal.csv
├── rdpRemote.csv
├── runKey.csv
├── sam.csv
├── srum.csv
├── taskScheduler.csv
├── timeline.csv
├── usrAssist.csv
├── windefender.csv
├── windows_general_info.csv
├── winStartStop.csv
└── wmi.csv
```

---

## License & Disclaimer
This project is made in my free time. I am **not a professional developer**.

Apache License 2.0

---
