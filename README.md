# MaximumPlasoTimelineParser

Note : further artefact parser will be add over time.


MPP or MaximumPlasoParser is a python script that will parse a [plaso - Log2Timeline](https://github.com/log2timeline/plaso)  json timeline file.
The goal is to provide easily readable and straight forward files for the Forensic analyst.
MPP will create a file for each artefact.


<ins>For example :</ins>

'4624' windows security event log provide information about a successful user connexion.
MPP will parse them like so :

```csv
Date|time|event_code|subject_user_name|target_user_name|ip_address|ip_port|logon_type
2022-10-07|16:51:47|4624|DESKTOP-9I162HO$|DWM-1|-|-|2
2022-10-07|16:51:47|4624|DESKTOP-9I162HO$|SERVICE LOCAL|-|-|5
[...]
2022-10-27|09:56:01|4624|DESKTOP-9I162HO$|Système|-|-|5
2022-10-27|09:56:03|4624|DESKTOP-9I162HO$|Système|-|-|5
2022-10-27|09:56:06|4624|DESKTOP-9I162HO$|HRO|192.168.10.102|3389|10
```

Mpp will only work on ***JSON_line*** formated plaso timeline, ***NOT CSV***.

<ins> Example of cmd to create a compatible timeline:</ins>

```bash
psteal.py --source /home/hro/DFIR-ORC-WorkStation-DESKTOP-9I162HO -w timeline.json -o json_line
```

## Configuration

Install dependencies : `pip3 install -r requirements.txt`

The only external dependency is [xmltodict](https://pypi.org/project/xmltodict/).
Thank u for it bro !

## Usage

```bash
python3 MaMaximumPlasoParser.py --help

usage: MaximumPlasoParser.py [-h] -t TIMELINE -o OUTPUT_DIR [-c CASE_NAME]
                             [-s SEPARATOR] [--type csv or json]
                             [--config CONFIG_FILE]

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
  --type csv or json    type of the output file format : csv or json. Default
                        is csv
  --config CONFIG_FILE  path to the json config file to be used
```


### Flag

| Flag     | Variation   | Mandatory | Note                                                                                                                                             |
|----------|-------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| -t       | --timeline  | Yes       | full path to the timeline. Must be a plaso timeline with json_line format                                                                        |
| -o       | --output    | Yes       | Path of the directory where all the file will be written                                                                                         |
| -c       | --casename  | No        | Name of your forensic case, will be used as a json key if json output format is choosen (will be used as an index for further Elastic ingestion) |
| -s       | --separator | No        | Separator that will be used in csv output files if json output format is choosen. Default is \| (pipe)                                           |
| --type   |             | No        | Output format of results file, can be csv or json. Default is CSV. (Json format is for easy ELK ingestion.)                                      |
| --config |             | No        | Full path to a json config file. See details below                                                                                               |


### Config file

The config file specify which artefacts will be parsed.

Set the value to 1 to parse an artefact. 0 otherwise  The default config set every artefact to 1.

Feel free to use the template given with the project "mpp_config.json"

<ins>mpp_config.json content:</ins>
```json
{
  "4624": 1,
  "4625": 1,
  "4672": 1,
  "4648": 1,
  "4688": 1,
  "task_scheduler": 1,
  "remote_rdp": 1,
  "local_rdp": 1,
  "bits": 1,
  "service": 1,
  "powershell": 1,
  "powershell_script": 1,
  "wmi": 1,
  "app_exp": 1,
  "amcache": 1,
  "app_compat": 1,
  "sam": 1,
  "user_assist": 1,
  "mru": 1,
  "ff_history": 1,
  "prefetch": 1,
  "srum": 1,
  "run": 1,
  "lnk": 1
}
```

## Disclamer

I'm not a professional dev and i'm doing this project on my free time.
Please be indulgent, 'ill try to correct everything the best i can' :)

