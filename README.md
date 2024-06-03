# MaximumPlasoParser

MPP or MaximumPlasoParser is a python script that will parse a [plaso - Log2Timeline](https://github.com/log2timeline/plaso)  json timeline file.

The goal is to regroup artefacts by categories in some easily readable and straight forward files.

MPP : 
* Regroup Artefacts by categories;
* Provide Human Readable output;
* Provide Json output (for SIEM ingestion);
* Is Fast (Avg time to parse a 1.4 Go Timeline : 90 sec);
* Easy to use and install (only 1 file).


<ins>For example, Human readable (CSV) output looks like that :</ins>

```csv
4624.csv :
Date|time|event_code|subject_user_name|target_user_name|ip_address|ip_port|logon_type
2022-10-27|09:56:01|4624|DESKTOP-9I162HO$|Système|-|-|5
2022-10-27|09:56:06|4624|DESKTOP-9I162HO$|HRO|192.168.10.102|3389|10

Windefender.csv :
Date|time|EventCode|ThreatName|Severity|User|ProcessName|Path|Action
2021-01-07|03:35:44|1116 - Detection|HackTool:Win64/Mikatz!dha|High|BROCELIANDE\arthur|C:\Users\Public\beacon.exe|Not Applicable
2021-01-07|03:35:46|1116 - Detection|Behavior:Win32/Atosev.D!sms|Severe|-|C:\Users\Public\beacon.exe|Not Applicable
2021-01-07|03:35:46|1117 - Action|Behavior:Win32/Atosev.D!sms|Severe|-|C:\Users\Public\beacon.exe|Remove

App_Compat_cache.csv :
Date|Time|Name|FullPath|Hash
2021-01-07|03:39:31|beacon.exe|C:\Users\Public\beacon.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|03:41:21|mimikatz.exe|C:\Users\Public\mimikatz.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|03:56:55|Bytelocker.exe|C:\Users\Public\Bytelocker.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
2021-01-07|04:19:41|ActiveDirectorySync.exe|C:\Users\Administrator\Documents\ActiveDirectorySync.exe|e55e5b02ad40e9846a3cd83b00eec225fb98781c6f58a19697bf66a586f77672
```

## Notes : 
Mpp will only work on ***JSON_line*** formated plaso timeline, ***NOT CSV***.

<ins> Example of cmd to create a compatible timeline:</ins>

```bash
psteal.py --source /home/hro/DFIR-ORC-WorkStation-DESKTOP-9I162HO -w timeline.json -o json_line
```


Sometimes the results files contains duplicated line.
To remove them, I've provided a script "clean_duplicate.sh":
```bash
bash clean_duplicate.sh /home/path/to/MPP/output/mpp_MachineName_YYYY-MM-DDTHH:mm:SS
```

## Configuration

Install dependencies : `pip3 install -r requirements.txt`

The only external dependency is [xmltodict](https://pypi.org/project/xmltodict/).


## Usage

```bash
python3 MaximumPlasoParserJson.py -c "CaseName" --type "csv" -o /home/output/dir/ -t /home/path/to/json/timeline/timeline.json  -m "MachineName"
```

```bash
python3 MaximumPlasoParserJson.py --help                                                                                                                 
usage: MaximumPlasoParserJson.py [-h] -t TIMELINE -o OUTPUT_DIR [-c CASE_NAME] [-s SEPARATOR] [--type csv or json] [-m name of the machine] [--config CONFIG_FILE]

Solution to parse a json plaso timeline

options:
  -h, --help            show this help message and exit
  -t TIMELINE, --timeline TIMELINE
                        path to the timeline , must be json timeline
  -o OUTPUT_DIR, --output OUTPUT_DIR
                        dest where the result will be written
  -c CASE_NAME, --casename CASE_NAME
                        name of the case u working on
  -s SEPARATOR, --separator SEPARATOR
                        separator that will be used on csv files
  --type csv or json    type of the output file format : csv or json. Default is csv
  -m name of the machine, --machine_name name of the machine
                        name of the machine
  --config CONFIG_FILE  path to the json config file to be used

```


### Flag

| Flag     | Variation      | Mandatory | Note                                                                                                                                             |
|----------|----------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| -t       | --timeline     | Yes       | full path to the timeline. Must be a plaso timeline with json_line format                                                                        |
| -o       | --output       | Yes       | Path of the directory where all the file will be written                                                                                         |
| -c       | --casename     | No        | Name of your forensic case, will be used as a json key if json output format is choosen (will be used as an index for further Elastic ingestion) |
| -s       | --separator    | No        | Separator that will be used in csv output files if CSV output format is choosen. Default is \| (pipe)                                            |
| -m       | --machine_name | No        | Name of the machine, it will be use to create root folder and in json formated output                                                            |
| --type   |                | No        | Output format of results file, can be csv or json. Default is CSV. (Json format is for easy ELK ingestion.)                                      |
| --config |                | No        | Full path to a json config file. See details below                                                                                               |


### Config file

The config file specify which artefacts will be parsed.

Set the value to 1 to parse an artefact. 0 otherwise  The default config set every artefact to 1.

Feel free to use the template given with the project "mpp_config.json"

### Artefact parsed
Note : further artefact parser will be added over time.

The artefacts parsed by MPP are : 

``` bash
├── Security Evtx (4624, 4625, 4648, 4672, 4688)
├── System Evtx (7045)
├── amcache
├── app_compat_cache
├── application_experience
├── bits
├── ff_history
├── lnk
├── local_rdp
├── mft
├── mru
├── powershell
├── powershell_script
├── prefetch
├── remote_rdp
├── run_key
├── sam
├── srum
├── user_assist
├── windefender
└── wmi
```

## Disclamer

I'm not a professional dev and i'm doing this project on my free time.

There might be some issues on parsing Security logs. SomeTimes, multiple users are referenced on the log and for now
the script is taking the 1st One witch can be not relevant. I'm working on it.

