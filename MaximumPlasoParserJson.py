#!/usr/bin/python3
import argparse
import csv
import xml.etree.ElementTree as ET
import os
import traceback
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import sys
import json
import re
import time
from pathlib import Path

class MaximumPlasoParser:
    """
    Class MaximumPlasoParser
    MPP or MaximumPlasoParser is a python script that will parse a plaso - Log2Timeline json timeline file.
    The goal is to provide easily readable and straight forward files for the Forensic analyst.
    MPP will create a CSV file for each artifact.
    """

    def __init__(self, path_to_timeline, output_directory, separator="|", machine_name="", start_date=None, end_date=None):
        """
        Constructor for the MaximumPlasoParser Class
        """
        self.path_to_timeline = path_to_timeline
        self.dir_out = output_directory
        self.separator = separator
        self.machine_name = machine_name if machine_name else "machine"

        self.start_date_str = start_date
        self.end_date_str = end_date
        self.start_ts = self._parse_date_to_epoch(start_date, is_end_date=False) if start_date else None
        self.end_ts = self._parse_date_to_epoch(end_date, is_end_date=True) if end_date else None

        self.artifact_counts = defaultdict(int)
        self.total_lines_read = 0
        self.total_events_extracted = 0
        self.total_timeline_events = 0

        self.current_date = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H_%M_%S")
        self.work_dir = os.path.join(os.path.abspath(self.dir_out), f"mpp_{self.machine_name}_{self.current_date}")
        self.csv_dir = os.path.join(self.work_dir, "csv_results")
        self.initialise_working_directories()

        # --- Dictionaries for Regex matching ---
        self.d_regex_type_artefact = {
            "evtx": re.compile(r'winevtx'),
            "hive": re.compile(r'winreg'),
            "db": re.compile(r'(sqlite)|(esedb)'),
            "winFile": re.compile(r'(lnk)|(text)|(prefetch)'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)')
        }
        self.d_regex_artefact_by_source_name = {
            "security": re.compile(r'Microsoft-Windows-Security-Auditing'),
            "system": re.compile(r'Service Control Manager'),
            "taskScheduler": re.compile(r'Microsoft-Windows-TaskScheduler'),
            "bits": re.compile(r'Microsoft-Windows-Bits-Client'),
            "rdp_local": re.compile(r'Microsoft-Windows-TerminalServices-LocalSessionManager'),
            "rdp_remote": re.compile(r'Microsoft-Windows-TerminalServices-RemoteConnectionManager'),
            "powershell": re.compile(r'(Microsoft-Windows-PowerShell)|(PowerShell)'),
            "wmi": re.compile(r'Microsoft-Windows-WMI-Activity'),
            "application_experience": re.compile(r'Microsoft-Windows-Application-Experience'),
            "windefender": re.compile(r'Microsoft-Windows-Windows Defender')
        }
        self.d_regex_artefact_by_parser_name = {
            "ff_history": re.compile(r'firefox'), "chrome_history": re.compile(r'chrome'),
            "edge_history": re.compile(r'edge'), "prefetch": re.compile(r'prefetch'),
            "lnk": re.compile(r'lnk'), "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)'),
            "winreg-srum": re.compile(r'srum'), "winreg-amcache": re.compile(r'amcache'),
            "winreg-appCompat": re.compile(r'appcompatcache'), "winreg-userassist": re.compile(r'userassist'),
            "winreg-mru": re.compile(r'winreg/(bagmru|mrulistex)'),
            "winreg_default": re.compile(r'winreg/winreg_default'),
            "winreg-networks": re.compile(r'winreg/networks'),
            "winreg-windows-run": re.compile(r'winreg/windows_run'),
            "winreg-windows_sam_users": re.compile(r'winreg/windows_sam_users'),
            "winreg-windows_usb_devices": re.compile(r'winreg/windows_usb_devices'),
            "winreg-windows_version": re.compile(r'winreg/windows_version'),
            "winreg-windows_boot_execute": re.compile(r'winreg/windows_boot_execute'),
            "winreg-windows_services": re.compile(r'winreg/windows_services'),
            "winreg-windows_shutdown": re.compile(r'winreg/windows_shutdown'),
            "winreg-windows_task_cache": re.compile(r'winreg/windows_task_cache'),
            "winreg-windows_timezone": re.compile(r'winreg/windows_timezone'),
            "winreg-winlogon": re.compile(r'winreg/winlogon')
        }

        self.common_reg_map = {
            "winreg-networks": "NETWORK", "winreg-windows_boot_execute": "BOOT_EXECUTE",
            "winreg-windows_services": "SERVICES", "winreg-windows_shutdown": "SHUTDOWN",
            "winreg-windows_usb_devices": "USB",
            "winreg-windows_timezone": "TIMEZONE", "winreg-winlogon": "WINLOGON"
        }

        # --- Centralized CSV Headers and File Handlers ---
        self.csv_headers = {
            "timeline": ["Date", "Time", "SourceArtefact", "Other"],
            "windows_info": ["Date", "Time", "Key", "Value"],
            "4624": ["Date", "Time", "event_code", "subject_user_name", "target_user_name", "ip_address", "ip_port",
                     "logon_type"],
            "4625": ["Date", "Time", "event_code", "subject_user_name", "target_user_name", "ip_address", "ip_port",
                     "logon_type", "failure_reason"],
            "4672": ["Date", "Time", "event_code", "logon_type", "subject_user_name", "target_user_name", "ip_address",
                     "ip_port"],
            "4648": ["Date", "Time", "event_code", "logon_type", "subject_user_name", "target_user_name", "ip_address",
                     "ip_port"],
            "4688": ["Date", "Time", "event_code", "subject_user_name", "target_user_name", "parent_process_name",
                     "new_process_name", "command_line"],
            "user_modification": ["Date", "Time", "event_code", "info", "TargetUserName", "SubjectUserName",
                                  "TargetDomainName", "TargetSid", "SamAccountName", "PasswordLastSet", "MemberName"],
            "tscheduler": ["Date", "Time", "event_code", "name", "task_name", "instance_id", "action_name",
                           "result_code", "user_name", "user_context"],
            "remote_rdp": ["Date", "Time", "event_code", "user_name", "ip_addr"],
            "local_rdp": ["Date", "Time", "event_code", "user_name", "ip_addr", "session_id", "source",
                          "target_session", "reason_n", "reason"],
            "bits": ["Date", "Time", "event_code", "id", "job_id", "job_title", "job_owner", "user", "bytes_total",
                     "bytes_transferred", "file_count", "file_length", "file_Time", "name", "url", "process_path"],
            "7045": ["Date", "Time", "event_code", "account_name", "img_path", "service_name", "start_type"],
            "script_powershell": ["Date", "Time", "event_code", "path_to_script", "script_block_text"],
            "powershell": ["Date", "Time", "event_code", "cmd"],
            "wmi": ["Date", "Time", "event_code", "operation_name", "user", "namespace", "consumer", "cause", "query"],
            "wmi_failure": ["Date", "Time", "event_code", "operation_name", "user", "namespace", "consumer", "cause",
                            "operation"],
            "app_exp": ["Date", "Time", "ExePath", "FixName", "event_code"],
            "amcache": ["Date", "Time", "Name", "FullPath", "id", "Hash"],
            "appcompat": ["Date", "Time", "Name", "FullPath", "Hash"],
            "sam": ["Date", "Time", "username", "login_count"],
            "userassist": ["Date", "Time", "valueName", "appFocus", "appDuration"],
            "mru": ["Date", "Time", "TYPE", "NAME", "entries"],
            "srum": ["Date", "Time", "description"],
            "run": ["Date", "Time", "entrie"],
            "common_reg": ["Date", "Time", "type", "key_path", "details"],
            "mui_cache": ["Date", "Time", "type", "name", "data"],
            "browser_history": ["Date", "Time", "browser", "type", "url", "visit_count", "visit_type", "isType",
                                "from_visit", "message"],
            "prefetch": ["Date", "Time", "name", "path", "nbExec"],
            "lnk": ["Date", "Time", "description", "working_dir"],
            "mft": ["Date", "Time", "source", "fileType", "action", "fileName"],
            "windefender": ["Date", "Time", "Event", "ThreatName", "Severity", "User", "ProcessName", "Path", "Action"],
            "start_stop": ["Date", "Time", "message"],
            "mru_run": ["Date", "Time", "cmd"],
            "sysmon_proc": ["Date", "Time", "event_code", "image", "command_line", "user", "parent_image",
                            "parent_command_line", "hashes", "original_file_name"],
            "sysmon_network": ["Date", "Time", "event_code", "image", "user", "protocol", "src_ip", "src_port",
                               "dst_ip", "dst_port", "dst_hostname"],
            "sysmon_module": ["Date", "Time", "event_code", "image", "image_loaded", "hashes", "signed",
                              "signature"],
            "sysmon_access": ["Date", "Time", "event_code", "source_image", "target_image", "granted_access",
                              "call_trace"],
            "sysmon_file": ["Date", "Time", "event_code", "image", "target_filename", "creation_time"],
            "sysmon_registry": ["Date", "Time", "event_code", "event_type", "image", "target_object", "details"],
            "sysmon_dns": ["Date", "Time", "event_code", "image", "query_name", "query_results", "query_status"],
            "log_cleared": ["Date", "Time", "event_code", "channel", "user_name", "domain", "details"],
            "persistence": ["Date", "Time", "mechanism_type", "name_or_key", "command_or_path", "user", "details"]
        }
        self.csv_writers = {}
        self.file_handlers = {}

    def initialise_working_directories(self):
        try:
            os.makedirs(self.work_dir, exist_ok=True)
            os.makedirs(self.csv_dir, exist_ok=True)
            print(f"Result directory is located at: {self.work_dir}")
        except OSError as e:
            sys.stderr.write(f"\nFailed to initialize directories: {e}\n")
            sys.exit(1)

    @staticmethod
    def convert_epoch_to_date(epoch_time):
        if not epoch_time or not isinstance(epoch_time, (int, float)):
            return "-", "-"
        try:
            dt = datetime.fromtimestamp(epoch_time / 1_000_000, tz=timezone.utc)
            return dt.strftime('%Y-%m-%d'), dt.strftime('%H:%M:%S')
        except (ValueError, TypeError, OSError, OverflowError):
            return "-", "-"

    @staticmethod
    def _parse_date_to_epoch(date_str, is_end_date=False):
        """
        Converts a date string (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS) to UTC microsecond timestamp.
        """
        if not date_str:
            return None
        date_str = date_str.strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(date_str, fmt)
                dt = dt.replace(tzinfo=timezone.utc)
                if fmt == "%Y-%m-%d" and is_end_date:
                    dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
                return int(dt.timestamp() * 1_000_000)
            except ValueError:
                continue
        raise ValueError(f"Invalid date format for '{date_str}'. Expected 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS'.")

    def get_csv_writer(self, artifact_type, delimiter='|'):
        if artifact_type not in self.csv_writers:
            try:
                filepath = os.path.join(self.csv_dir, f'{artifact_type}.csv')
                file_handler = open(filepath, 'a', newline='', encoding='utf-8')
                self.file_handlers[artifact_type] = file_handler
                writer = csv.writer(file_handler, delimiter=delimiter)

                if file_handler.tell() == 0:
                    headers = self.csv_headers.get(artifact_type, [])
                    if headers:
                        writer.writerow(headers)

                self.csv_writers[artifact_type] = writer
            except IOError as e:
                print(f"ERROR: Could not open file for artifact {artifact_type}: {e}", file=sys.stderr)
                return None

        return self.csv_writers[artifact_type]

    @staticmethod
    def _parse_xml(xml_string):
        """Safely parse an XML string into an ElementTree root without external dependencies."""
        if not xml_string or not isinstance(xml_string, (str, bytes)):
            return None
        try:
            return ET.fromstring(xml_string)
        except Exception:
            return None

    @staticmethod
    def _extract_event_data(root):
        """
        Extracts EventData from an EVTX XML element into a dictionary.
        Supports both <Data Name="key">value</Data> and unnamed <Data>value</Data>.
        """
        if root is None:
            return {}
        data = {}
        unnamed = []
        for elem in root.iter():
            if elem.tag.endswith('Data'):
                name = elem.get('Name')
                val = elem.text or '-'
                if name:
                    data[name] = val
                else:
                    unnamed.append(val)
        if unnamed:
            data['_unnamed'] = unnamed
        return data

    @staticmethod
    def _extract_user_data(root):
        """
        Extracts UserData from an EVTX XML element.
        Returns (operation_name, child_dict).
        """
        if root is None:
            return '', {}
        for elem in root.iter():
            if elem.tag.endswith('UserData'):
                for child in elem:
                    op_name = child.tag.split('}', 1)[-1]
                    child_data = {}
                    for sub in child:
                        sub_tag = sub.tag.split('}', 1)[-1]
                        child_data[sub_tag] = sub.text or '-'
                    return op_name, child_data
        return '', {}

    def close_files(self):
        print("Closing all open files...")
        for handler in self.file_handlers.values():
            try:
                handler.close()
            except Exception as e:
                print(f"Warning: could not close a file. Error: {e}")
        self.file_handlers.clear()
        self.csv_writers.clear()

    def parse_timeline(self):
        try:
            line_count = 0
            with open(self.path_to_timeline, 'r', encoding='utf-8') as timeline:
                for line in timeline:
                    line_count += 1
                    if line_count % 100000 == 0:
                        print(f"  [+] Read {line_count:,} events (extracted: {self.total_events_extracted:,})...")
                    try:
                        d_line = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Date filter
                    ts = d_line.get("timestamp")
                    if ts is not None and isinstance(ts, (int, float)):
                        if self.start_ts is not None and ts < self.start_ts:
                            continue
                        if self.end_ts is not None and ts > self.end_ts:
                            continue

                    type_artefact = self.identify_type_artefact_by_parser(d_line)
                    if type_artefact:
                        self.assign_parser(d_line, type_artefact)

            self.total_lines_read = line_count
            print(f"Total events scanned: {line_count:,} (extracted: {self.total_events_extracted:,})")
        except Exception:
            print(f"Critical error during parsing: {traceback.format_exc()}", file=sys.stderr)
        finally:
            self.close_files()

    def identify_type_artefact_by_parser(self, line):
        parser = line.get("parser", "")
        if not parser:
            return None
        if "winevtx" in parser:
            return "evtx"
        if "winreg" in parser:
            return "hive"
        if "sqlite" in parser or "esedb" in parser:
            return "db"
        if "lnk" in parser or "prefetch" in parser or "text" in parser:
            return "winFile"
        if "filestat" in parser or "usnjrnl" in parser or "mft" in parser:
            return "mft"
        return None

    def identify_artefact_by_parser_name(self, line):
        parser = line.get("parser", "")
        for key, value in self.d_regex_artefact_by_parser_name.items():
            if re.search(value, parser):
                return key
        return None

    def identify_artefact_by_source_name(self, line):
        source_name = line.get("source_name", "")
        if not source_name:
            return None
        if "Security-Auditing" in source_name:
            return "security"
        if "Service Control Manager" in source_name:
            return "system"
        if "TaskScheduler" in source_name:
            return "taskScheduler"
        if "Bits-Client" in source_name:
            return "bits"
        if "TerminalServices-LocalSessionManager" in source_name:
            return "rdp_local"
        if "TerminalServices-RemoteConnectionManager" in source_name:
            return "rdp_remote"
        if "PowerShell" in source_name:
            return "powershell"
        if "WMI-Activity" in source_name:
            return "wmi"
        if "Application-Experience" in source_name:
            return "application_experience"
        if "Windows Defender" in source_name:
            return "windefender"
        if "Sysmon" in source_name:
            return "sysmon"
        if "Eventlog" in source_name or "Event Log" in source_name:
            return "eventlog"
        return None

    def assign_parser(self, line, type_artefact):
        if type_artefact == "evtx":
            self.parse_logs(line)
        elif type_artefact == "hive":
            self.parse_hives(line)
        elif type_artefact == "db":
            self.parse_db(line)
        elif type_artefact == "winFile":
            self.parse_win_file(line)
        elif type_artefact == "mft":
            self.parse_mft(line)

    def parse_logs(self, line):
        log_type = self.identify_artefact_by_source_name(line)
        if not log_type: return

        parsers = {
            "security": self.parse_security_evtx, "taskScheduler": self.parse_task_scheduler,
            "bits": self.parse_bits, "system": self.parse_system_evtx,
            "rdp_local": self.parse_rdp_local, "rdp_remote": self.parse_rdp_remote,
            "powershell": self.parse_powershell, "wmi": self.parse_wmi,
            "application_experience": self.parse_app_experience, "windefender": self.parse_windows_defender,
            "sysmon": self.parse_sysmon, "eventlog": self.parse_eventlog,
        }

        parser_func = parsers.get(log_type)
        if parser_func:
            parser_func(line)

    # --- EVTX PARSERS ---
    def parse_security_evtx(self, event):
        event_code = event.get("event_identifier")
        if event_code == 4624:
            self.parse_logon_from_xml(event, "4624")
        elif event_code == 4625:
            self.parse_failed_logon_from_xml(event)
        elif event_code == 4672:
            self.parse_logon_from_xml(event, "4672")
        elif event_code == 4648:
            self.parse_logon_from_xml(event, "4648")
        elif event_code == 4688:
            self.parse_new_proc_from_xml(event)
        elif event_code == 4697:
            self.parse_service_installed_4697(event)
        elif event_code == 1102:
            self.parse_log_cleared(event, "Security")
        elif event_code in (4608, 4609):
            self.parse_windows_startup_shutdown(event)
        elif event_code in (4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4756, 4757):
            self.parse_user_modification(event, event_code)

    def parse_logon_from_xml(self, event, artifact_key):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "subject_user_name": data.get("SubjectUserName", "-"), "target_user_name": data.get("TargetUserName", "-"),
            "ip_address": data.get("IpAddress", "-"), "ip_port": data.get("IpPort", "-"),
            "logon_type": data.get("LogonType", "-")
        }
        self._write_csv_row(artifact_key, data_dict)

    def parse_failed_logon_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        data = self._extract_event_data(root)

        d_status = {"0XC000005E": "NoLogServAvailable", "0xC0000064": "BadUserAccount",
                    "0XC000006A": "BadUserNameOrPasswd", "0XC000006D": "BadUserNameOrPasswd",
                    "0XC000006F": "LogonOutSideHours", "0XC0000070": "LogonFromUnauthorizedWordstation",
                    "0XC0000072": "UserLogonDisabledByAdmin", "0XC000015B": "UserGotNotLogonRight",
                    "0XC0000192": "NetLogonWasNotStarted", "0xC0000193": "LogonWExpiredAccount",
                    "0XC0000413": "AccountNotauthorizedOnMachine", "-": "-"}
        status_code = str(data.get("Status", "-")).upper()

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "4625",
            "subject_user_name": data.get("SubjectUserName", "-"), "target_user_name": data.get("TargetUserName", "-"),
            "ip_address": data.get("IpAddress", "-"), "ip_port": data.get("IpPort", "-"),
            "logon_type": data.get("LogonType", "-"), "failure_reason": d_status.get(status_code, status_code)
        }
        self._write_csv_row("4625", data_dict)

    def parse_new_proc_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "4688",
            "subject_user_name": data.get("SubjectUserName", "-"), "target_user_name": data.get("TargetUserName", "-"),
            "parent_process_name": data.get("ParentProcessName", "-"),
            "new_process_name": data.get("NewProcessName", "-"),
            "command_line": data.get("CommandLine", "-")
        }
        self._write_csv_row("4688", data_dict)

    def parse_user_modification(self, event, event_code):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            eid = int(event_code)
        except (ValueError, TypeError):
            eid = event_code

        event_info_map = {
            4720: "UserCreation",
            4722: "UserAccountEnabled",
            4723: "PswdChangedByUser",
            4724: "PswdResetedByTiers",
            4725: "UserAccountDisabled",
            4726: "UserDeletion",
            4728: "MemberAddedToGlobalGroup",
            4729: "MemberRemovedFromGlobalGroup",
            4732: "MemberAddedToLocalGroup",
            4733: "MemberRemovedFromLocalGroup",
            4738: "UserAccountModified",
            4756: "MemberAddedToUniversalGroup",
            4757: "MemberRemovedFromUniversalGroup"
        }
        info = event_info_map.get(eid, f"UserMod_{event_code}")

        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        data = self._extract_event_data(root)

        member_name = data.get("MemberName", data.get("MemberSid", "-"))
        data_dict = {
            "Date": ts_date,
            "Time": ts_time,
            "event_code": event_code,
            "info": info,
            "TargetUserName": data.get("TargetUserName", "-"),
            "SubjectUserName": data.get("SubjectUserName", "-"),
            "TargetDomainName": data.get("TargetDomainName", "-"),
            "TargetSid": data.get("TargetSid", "-"),
            "SamAccountName": data.get("SamAccountName", "-"),
            "PasswordLastSet": data.get("PasswordLastSet", "-"),
            "MemberName": member_name
        }
        self._write_csv_row("user_modification", data_dict)

        # Persistence: Account creation (backdoor account) or privileged group membership
        if eid == 4720:
            self._write_persistence(
                ts_date, ts_time, "ACCOUNT_CREATION",
                data.get("TargetUserName", "-"),
                data.get("TargetSid", data.get("SamAccountName", "-")),
                data.get("SubjectUserName", "-"),
                "EventID: 4720 (User Account Created)"
            )
        elif eid in (4728, 4732, 4756):
            self._write_persistence(
                ts_date, ts_time, "GROUP_PRIVILEGE",
                data.get("TargetUserName", "-"),
                member_name,
                data.get("SubjectUserName", "-"),
                f"EventID: {eid} ({info})"
            )

    def parse_system_evtx(self, event):
        eid = event.get("event_identifier")
        if eid == 7045:
            self.parse_service_from_xml(event)
        elif eid == 104:
            self.parse_log_cleared(event, "System")

    def parse_service_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "7045", "account_name": data.get("AccountName", "-"),
            "img_path": data.get("ImagePath", "-"), "service_name": data.get("ServiceName", "-"),
            "start_type": data.get("StartType", "-")
        }
        self._write_csv_row("7045", data_dict)
        self._write_persistence(
            ts_date, ts_time, "SERVICE",
            data.get("ServiceName", "-"),
            data.get("ImagePath", "-"),
            data.get("AccountName", "-"),
            f"EventID: 7045, StartType: {data.get('StartType', '-')}"
        )

    def parse_service_installed_4697(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "4697",
            "account_name": data.get("ServiceAccount", "-"),
            "img_path": data.get("ServiceFileName", "-"),
            "service_name": data.get("ServiceName", "-"),
            "start_type": data.get("ServiceStartType", "-")
        }
        self._write_csv_row("7045", data_dict)
        self._write_persistence(
            ts_date, ts_time, "SERVICE",
            data.get("ServiceName", "-"),
            data.get("ServiceFileName", "-"),
            data.get("ServiceAccount", "-"),
            f"EventID: 4697, StartType: {data.get('ServiceStartType', '-')}"
        )

    def parse_log_cleared(self, event, default_channel="Security"):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        data = self._extract_event_data(root) if root is not None else {}
        event_code = event.get("event_identifier")

        channel = data.get("Channel", default_channel)
        user_name = data.get("SubjectUserName", event.get("username", "-"))
        domain = data.get("SubjectDomainName", "-")
        details = f"Log cleared: {channel}"

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event_code,
            "channel": channel, "user_name": user_name, "domain": domain,
            "details": details
        }
        self._write_csv_row("log_cleared", data_dict)

    def parse_eventlog(self, event):
        if str(event.get("event_identifier")) == "104":
            self.parse_log_cleared(event, "System")

    def parse_task_scheduler(self, event):
        if str(event.get("event_identifier")) in ["106", "107", "140", "141", "200", "201"]:
            self.parse_task_scheduler_from_xml_taskevt(event)

    def parse_task_scheduler_from_xml_taskevt(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "name": data.get("Name", "-"), "task_name": data.get("TaskName", "-"),
            "instance_id": data.get("InstanceId", "-"), "action_name": data.get("ActionName", "-"),
            "result_code": data.get("ResultCode", "-"), "user_name": data.get("UserName", "-"),
            "user_context": data.get("UserContext", "-")
        }
        self._write_csv_row("tscheduler", data_dict)

        eid_str = str(event.get("event_identifier", ""))
        if eid_str in ("106", "140"):
            action_desc = "Task Registered" if eid_str == "106" else "Task Updated"
            self._write_persistence(
                ts_date, ts_time, "SCHEDULED_TASK",
                data.get("TaskName", data.get("Name", "-")),
                data.get("ActionName", "-"),
                data.get("UserName", data.get("UserContext", "-")),
                f"EventID: {eid_str} ({action_desc}), Result: {data.get('ResultCode', '-')}"
            )

    def parse_bits(self, event):
        if str(event.get("event_identifier")) in ["3", "4", "59", "60", "61"]:
            self.parse_bits_evtx_from_xml(event)

    def parse_bits_evtx_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "id": data.get("Id", "-"), "job_id": data.get("jobId", "-"), "job_title": data.get("jobTitle", "-"),
            "job_owner": data.get("jobOwner", "-"), "user": data.get("User", "-"),
            "bytes_total": data.get("bytesTotal", "-"), "bytes_transferred": data.get("bytesTransferred", "-"),
            "file_count": data.get("fileCount", "-"), "file_length": data.get("fileLength", "-"),
            "file_Time": data.get("fileTime", "-"), "name": data.get("name", "-"), "url": data.get("url", "-"),
            "process_path": data.get("processPath", "-")
        }
        self._write_csv_row("bits", data_dict)

        url = data.get("url", "-")
        proc_path = data.get("process_path", "-")
        if (url and url != "-") or (proc_path and proc_path != "-"):
            self._write_persistence(
                ts_date, ts_time, "BITS_JOB",
                data.get("job_title", data.get("name", "-")),
                url if (url and url != "-") else proc_path,
                data.get("job_owner", data.get("user", "-")),
                f"EventID: {event.get('event_identifier')}, Process: {proc_path}"
            )

    def parse_windows_startup_shutdown(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        message = "WINDOWS STARTUP" if event.get("event_identifier") == 4608 else "WINDOWS SHUTDOWN"
        data_dict = {"Date": ts_date, "Time": ts_time, "message": message}
        self._write_csv_row("start_stop", data_dict)

    def parse_rdp_remote(self, event):
        if str(event.get("event_identifier")) == "1149":
            self.parse_remote_rdp_evtx_from_xml(event)

    def parse_remote_rdp_evtx_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "1149",
            "user_name": event.get("username", "-"), "ip_addr": event.get("ip_address", "-")
        }
        self._write_csv_row("remote_rdp", data_dict)

    def parse_rdp_local(self, event):
        if str(event.get("event_identifier")) in ["21", "24", "25", "39", "40"]:
            self.parse_rdp_local_evtx_from_xml(event)

    def parse_rdp_local_evtx_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        event_code = str(event.get("event_identifier", "-"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        _, data = self._extract_user_data(root)

        reason_map = {"21": "AuthSuccess", "24": "UserDisconnected", "25": "UserReconnected",
                      "39": "UserHasBeenDisconnected", "40": "UserHasBeenDisconnected"}

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event_code,
            "user_name": data.get("User", "-"), "ip_addr": data.get("Address", "-"),
            "session_id": data.get("SessionID", "-"), "source": data.get("Source", '-'),
            "target_session": data.get("Target", "-"), "reason_n": data.get("Reason", "-"),
            "reason": reason_map.get(event_code, "-")
        }
        self._write_csv_row("local_rdp", data_dict)

    def parse_wmi(self, event):
        event_code = str(event.get("event_identifier"))
        if event_code == "5861":
            self.parse_wmi_evtx_from_xml(event)
        elif event_code == "5858":
            self.parse_wmi_failure_from_xml(event)

    def parse_wmi_evtx_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        op_name, data = self._extract_user_data(root)
        if not op_name: return

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "operation_name": op_name, "user": data.get("User", "-"),
            "namespace": data.get("NamespaceName", "-"), "consumer": data.get("CONSUMER", "-"),
            "cause": str(data.get("PossibleCause", "-")).replace("\r\n", " ").replace("\n", " "),
            "query": str(data.get("Query", "-")).replace("\r\n", " ").replace("\n", " ")
        }
        self._write_csv_row("wmi", data_dict)
        self._write_persistence(
            ts_date, ts_time, "WMI_SUBSCRIPTION",
            data.get("CONSUMER", op_name),
            str(data.get("Query", "-")).replace("\r\n", " ").replace("\n", " "),
            data.get("User", "-"),
            f"Namespace: {data.get('NamespaceName', '-')}, Op: {op_name}"
        )

    def parse_wmi_failure_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        op_name, data = self._extract_user_data(root)
        if not op_name: return

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "operation_name": op_name, "user": data.get("User", "-"),
            "namespace": data.get("NamespaceName", "-"), "consumer": data.get("CONSUMER", "-"),
            "cause": str(data.get("PossibleCause", "-")).replace("\r\n", " ").replace("\n", " "),
            "operation": str(data.get("Operation", "-")).replace("\r\n", " ").replace("\n", " ")
        }
        self._write_csv_row("wmi_failure", data_dict)

    def parse_powershell(self, event):
        event_code = str(event.get("event_identifier"))
        if event_code in ["4104", "4105", "4106"]: self.parse_powershell_script_from_xml(event)
        if event_code in ["400", "600", "4103"]: self.parse_powershell_cmd_from_xml(event)

    def parse_powershell_script_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "path_to_script": data.get("Path", "-"), "script_block_text": data.get("ScriptBlockText", "-")
        }
        self._write_csv_row("script_powershell", data_dict)

    def parse_powershell_cmd_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        cmd = "-"
        event_code = str(event.get("event_identifier"))
        root = self._parse_xml(event.get("xml_string"))
        if root is not None:
            data = self._extract_event_data(root)
            if event_code == "4103":
                cmd = str(data.get("Payload", data.get("ContextInfo", "-"))).replace("\r\n", " ").replace("\n", " ")
            else:
                for line in data.get("_unnamed", []):
                    if "HostApplication=" in line:
                        for part in line.split("\n"):
                            if "HostApplication=" in part:
                                cmd = part.split("HostApplication=")[1].strip()
                                break
                        if cmd != "-":
                            break

        data_dict = {"Date": ts_date, "Time": ts_time, "event_code": event_code, "cmd": cmd}
        self._write_csv_row("powershell", data_dict)

    def parse_app_experience(self, event):
        if str(event.get("event_identifier")) in ["500", "505", "17"]:
            self.parse_app_experience_from_xml(event)

    def parse_app_experience_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        _, data = self._extract_user_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "FixName": data.get("FixName", "-"), "ExePath": data.get("ExePath", "-")
        }
        self._write_csv_row("app_exp", data_dict)

    def parse_windows_defender(self, event):
        event_code = str(event.get("event_identifier"))
        if event_code in ["1116", "1117", "1118", "1119", "5001", "5007"]:
            self.parse_windef_from_xml(event)

    def parse_windef_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None:
            return
        data = self._extract_event_data(root)

        eid = str(event.get('event_identifier'))
        if eid == "1116":
            event_type = "Detection"
        elif eid == "5001":
            event_type = "RealTimeDisabled"
        elif eid == "5007":
            event_type = "ConfigOrExclusionChanged"
        else:
            event_type = "Action"

        data_dict = {
            "Date": ts_date, "Time": ts_time, "Event": f"{eid} - {event_type}",
            "ThreatName": data.get("Threat Name", data.get("Old Value", "-")),
            "Severity": data.get("Severity Name", "-"),
            "User": data.get("Detection User", data.get("User", "-")),
            "ProcessName": data.get("Process Name", "-"),
            "Path": data.get("Path", data.get("New Value", "-")),
            "Action": data.get("Action Name", event_type)
        }
        self._write_csv_row("windefender", data_dict)

    # --- SYSMON PARSERS ---
    def parse_sysmon(self, event):
        eid = str(event.get("event_identifier", ""))
        if eid == "1":
            self.parse_sysmon_process(event)
        elif eid == "3":
            self.parse_sysmon_network(event)
        elif eid in ("7",):
            self.parse_sysmon_module(event)
        elif eid in ("8", "10"):
            self.parse_sysmon_access(event)
        elif eid == "11":
            self.parse_sysmon_file(event)
        elif eid in ("12", "13", "14"):
            self.parse_sysmon_registry(event)
        elif eid == "22":
            self.parse_sysmon_dns(event)

    def parse_sysmon_process(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None: return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "1",
            "image": data.get("Image", "-"),
            "command_line": str(data.get("CommandLine", "-")).replace("\r\n", " ").replace("\n", " "),
            "user": data.get("User", "-"),
            "parent_image": data.get("ParentImage", "-"),
            "parent_command_line": str(data.get("ParentCommandLine", "-")).replace("\r\n", " ").replace("\n", " "),
            "hashes": data.get("Hashes", "-"),
            "original_file_name": data.get("OriginalFileName", "-")
        }
        self._write_csv_row("sysmon_proc", data_dict)

    def parse_sysmon_network(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None: return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "3",
            "image": data.get("Image", "-"), "user": data.get("User", "-"),
            "protocol": data.get("Protocol", "-"),
            "src_ip": data.get("SourceIp", "-"), "src_port": data.get("SourcePort", "-"),
            "dst_ip": data.get("DestinationIp", "-"), "dst_port": data.get("DestinationPort", "-"),
            "dst_hostname": data.get("DestinationHostname", "-")
        }
        self._write_csv_row("sysmon_network", data_dict)

    def parse_sysmon_module(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None: return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "7",
            "image": data.get("Image", "-"), "image_loaded": data.get("ImageLoaded", "-"),
            "hashes": data.get("Hashes", "-"), "signed": data.get("Signed", "-"),
            "signature": data.get("Signature", "-")
        }
        self._write_csv_row("sysmon_module", data_dict)

    def parse_sysmon_access(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        eid = str(event.get("event_identifier", "-"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None: return
        data = self._extract_event_data(root)

        call_trace = str(data.get("CallTrace", data.get("StartAddress", "-"))).replace("\r\n", " ").replace("\n", " ")
        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": eid,
            "source_image": data.get("SourceImage", "-"),
            "target_image": data.get("TargetImage", "-"),
            "granted_access": data.get("GrantedAccess", "-"),
            "call_trace": call_trace
        }
        self._write_csv_row("sysmon_access", data_dict)

    def parse_sysmon_file(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None: return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "11",
            "image": data.get("Image", "-"),
            "target_filename": data.get("TargetFilename", "-"),
            "creation_time": data.get("CreationUtcTime", "-")
        }
        self._write_csv_row("sysmon_file", data_dict)

    def parse_sysmon_registry(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        eid = str(event.get("event_identifier", "-"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None: return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": eid,
            "event_type": data.get("EventType", "-"),
            "image": data.get("Image", "-"),
            "target_object": data.get("TargetObject", "-"),
            "details": str(data.get("Details", "-")).replace("\r\n", " ").replace("\n", " ")
        }
        self._write_csv_row("sysmon_registry", data_dict)

        target_obj = data.get("TargetObject", "")
        t_lower = target_obj.lower()
        asep_keywords = (
            "\\run", "\\runonce", "\\services\\", "\\winlogon",
            "\\image file execution options", "\\explorer\\shell folders",
            "\\explorer\\user shell folders", "\\startupapproved",
            "userinitmprlogonscript", "\\bootexecute", "appinit_dlls",
            "\\cmd processor\\autorun"
        )
        if any(kw in t_lower for kw in asep_keywords):
            self._write_persistence(
                ts_date, ts_time, "SYSMON_REG_ASEP",
                target_obj,
                data.get("Details", "-"),
                "-",
                f"EventID: {eid}, Process: {data.get('Image', '-')}, Type: {data.get('EventType', '-')}"
            )

    def parse_sysmon_dns(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        root = self._parse_xml(event.get("xml_string"))
        if root is None: return
        data = self._extract_event_data(root)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "22",
            "image": data.get("Image", "-"),
            "query_name": data.get("QueryName", "-"),
            "query_results": data.get("QueryResults", "-"),
            "query_status": data.get("QueryStatus", "-")
        }
        self._write_csv_row("sysmon_dns", data_dict)

    # --- HIVE PARSERS ---
    def parse_hives(self, line):
        hive_type = self.identify_artefact_by_parser_name(line)
        if not hive_type: return

        # Specific, high-volume artifacts
        if hive_type == "winreg-amcache":
            self.parse_amcache(line)
        elif hive_type == "winreg-appCompat":
            self.parse_app_compat_cache(line)
        elif hive_type == "winreg-windows_sam_users":
            self.parse_sam(line)
        elif hive_type == "winreg-userassist":
            self.parse_user_assist(line)
        elif hive_type == "winreg-mru":
            self.parse_mru(line)
        elif hive_type == "winreg-windows-run":
            self.parse_run(line)
        elif hive_type == "winreg-windows_version":
            self.parse_windows_version(line)
        elif hive_type == "winreg-windows_task_cache":
            self.parse_reg_task_cache(line)
        # Generic registry key parsing
        elif hive_type in self.common_reg_map:
            self.parse_common_reg_key(line, self.common_reg_map[hive_type])
        elif 'winreg_default' in hive_type:
            if 'MuiCache' in line.get("key_path", ""):
                self.parse_mui_cache(line)
            # Add other winreg_default conditions here if necessary

    def parse_common_reg_key(self, event, reg_type):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        key_path = event.get("key_path", "-")
        values = event.get("values", [])

        if isinstance(values, list) and values:
            for value in values:
                details = f"{value.get('name', '')}: {value.get('data', '')}"
                data_dict = {"Date": ts_date, "Time": ts_time, "type": reg_type, "key_path": key_path,
                             "details": details}
                self._write_csv_row("common_reg", data_dict)
                if reg_type in ("BOOT_EXECUTE", "WINLOGON", "SERVICES"):
                    self._write_persistence(
                        ts_date, ts_time, f"REG_{reg_type}",
                        key_path,
                        details,
                        "-",
                        f"Registry Hive Artifact: {reg_type}"
                    )
        else:
            details = event.get("message", "-").split("]")[-1].strip()
            data_dict = {"Date": ts_date, "Time": ts_time, "type": reg_type, "key_path": key_path, "details": details}
            self._write_csv_row("common_reg", data_dict)
            if reg_type in ("BOOT_EXECUTE", "WINLOGON", "SERVICES"):
                self._write_persistence(
                    ts_date, ts_time, f"REG_{reg_type}",
                    key_path,
                    details,
                    "-",
                    f"Registry Hive Artifact: {reg_type}"
                )

    def parse_reg_task_cache(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        key_path = event.get("key_path", "-")
        values = event.get("values", [])

        details_list = []
        if isinstance(values, list):
            for value in values:
                details_list.append(f"{value.get('name', '')}: {value.get('data', '')}")

        details_str = ", ".join(details_list) if details_list else "-"

        if details_str == "-":
            message = event.get("message", "-")
            prefix_to_remove = "[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache]"
            details_str = message.replace(prefix_to_remove, "").strip() if prefix_to_remove in message else message

        data_dict = {"Date": ts_date, "Time": ts_time, "type": "TASKCACHE", "key_path": key_path,
                     "details": details_str}
        self._write_csv_row("common_reg", data_dict)
        self._write_persistence(
            ts_date, ts_time, "REG_TASK_CACHE",
            key_path,
            details_str,
            "-",
            "Registry Task Cache"
        )

    def parse_windows_version(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        values = event.get("values", [])
        if isinstance(values, list):
            for value in values:
                data_dict = {
                    "Date": ts_date, "Time": ts_time,
                    "Key": value.get("name", "-"),
                    "Value": value.get("data", "-")
                }
                self._write_csv_row("windows_info", data_dict)

    def parse_amcache(self, event):
        full_path = event.get("full_path", "-")
        if full_path == "-": return

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        data_dict = {
            "Date": ts_date, "Time": ts_time, "Name": os.path.basename(full_path),
            "FullPath": full_path, "id": event.get("program_identifier", "-"),
            "Hash": event.get("sha256_hash", "-")
        }
        self._write_csv_row("amcache", data_dict)

    def parse_app_compat_cache(self, event):
        full_path = event.get("path", "-")
        if full_path == "-": return

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        data_dict = {
            "Date": ts_date, "Time": ts_time, "Name": os.path.basename(full_path),
            "FullPath": full_path, "Hash": event.get("sha256_hash", "-")
        }
        self._write_csv_row("appcompat", data_dict)

    def parse_sam(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        data_dict = {
            "Date": ts_date, "Time": ts_time, "username": event.get("username", "-"),
            "login_count": event.get("login_count", "-")
        }
        self._write_csv_row("sam", data_dict)

    def parse_user_assist(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        data_dict = {
            "Date": ts_date, "Time": ts_time, "valueName": event.get("value_name", "-"),
            "appFocus": event.get("application_focus_count", "-"),
            "appDuration": event.get("application_focus_duration", "-")
        }
        self._write_csv_row("userassist", data_dict)

    def parse_mru(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        entries = event.get("entries", event.get("shell_item_path", "-"))
        if not isinstance(entries, list):
            entries = [str(entries)]

        for entry in entries:
            data_dict = {
                "Date": ts_date, "Time": ts_time, "TYPE": event.get("parser", "N/A"),
                "NAME": event.get("name", "-"), "entries": entry
            }
            self._write_csv_row("mru", data_dict)

    def parse_mui_cache(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        entries = event.get("values", [])
        if isinstance(entries, list):
            for entry in entries:
                data_dict = {
                    "Date": ts_date, "Time": ts_time, "type": "MUICACHE",
                    "name": entry.get("name", "-"), "data": entry.get("data", "-")
                }
                self._write_csv_row("mui_cache", data_dict)

    def parse_run(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        entries = event.get("entries", [])
        key_path = event.get("key_path", "Run")
        if entries:
            for entrie in entries:
                data_dict = {"Date": ts_date, "Time": ts_time, "entrie": entrie}
                self._write_csv_row("run", data_dict)
                self._write_persistence(
                    ts_date, ts_time, "RUN_KEY",
                    key_path,
                    entrie,
                    "-",
                    "Registry Run Key"
                )

    # --- DB PARSERS ---
    def parse_db(self, line):
        db_type = self.identify_artefact_by_parser_name(line)
        if not db_type:
            return
        if db_type == "srum":
            self.parse_srum(line)
        elif "history" in db_type:
            browser = db_type.split('_')[0]
            self.parse_browser_history(line, browser)

    def parse_srum(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        data_dict = {"Date": ts_date, "Time": ts_time, "description": event.get("message", "-")}
        self._write_csv_row("srum", data_dict)

    def parse_browser_history(self, event, browser_name):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        data_dict = {
            "Date": ts_date, "Time": ts_time, "browser": browser_name,
            "type": event.get("data_type", "-"), "url": event.get("url", "-"),
            "visit_count": event.get("visit_count", "-"), "visit_type": event.get("visit_type", "-"),
            "isType": event.get("typed", "-"), "from_visit": event.get("from_visit", "-"),
            "message": event.get("message", "-") if "autofill" in event.get("data_type", "") else "-"
        }
        self._write_csv_row("browser_history", data_dict)

    # --- FILE PARSERS ---
    def parse_win_file(self, line):
        file_type = self.identify_artefact_by_parser_name(line)
        if file_type == "prefetch":
            self.parse_prefetch(line)
        elif file_type == "lnk":
            self.parse_lnk(line)

    def parse_prefetch(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        data_dict = {
            "Date": ts_date, "Time": ts_time, "name": event.get("executable", "-"),
            "path": ", ".join(event.get("path_hints", [])), "nbExec": event.get("run_count", "-")
        }
        self._write_csv_row("prefetch", data_dict)

    def parse_lnk(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        desc = event.get("description", "-")
        working_dir = event.get("working_directory", "-")
        display_name = event.get("display_name", event.get("filename", "-"))
        link_target = event.get("link_target", "-")

        if desc != "-" or working_dir != "-":
            data_dict = {
                "Date": ts_date, "Time": ts_time, "description": desc,
                "working_dir": working_dir
            }
            self._write_csv_row("lnk", data_dict)

        # Check if LNK is placed in a Startup directory or targets Startup
        full_context = f"{desc} {working_dir} {display_name} {link_target}".lower()
        if "startup" in full_context or "start menu\\programs\\startup" in full_context:
            self._write_persistence(
                ts_date, ts_time, "STARTUP_LNK",
                display_name if display_name != "-" else desc,
                link_target if link_target != "-" else working_dir,
                "-",
                f"Startup Shortcut: {desc}"
            )

    # --- MFT PARSERS ---
    def parse_mft(self, line):
        parser = line.get("parser", "")
        if parser == "usnjrnl":
            self.parse_usnjrl(line)
        elif parser == "mft":
            self.parse_file_mft(line)
        elif parser == "filestat":
            if ("NTFS" in line.get("source_long", "") or 
                "NTFS" in line.get("display_name", "") or 
                line.get("file_system_type") == "NTFS" or 
                "NTFS" in line.get("message", "")):
                self.parse_filestat(line)

    def parse_usnjrl(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        msg = event.get("message", "")

        file_name_match = re.search(r'^([^\s:\r\n]+\.[a-zA-Z0-9]{1,5})', msg)
        reason_match = re.search(r'Update reason:\s*([^,\r\n]+)', msg)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "source": "USNJRNL", "fileType": "N/A",
            "action": reason_match.group(1).strip() if reason_match else "noReason",
            "fileName": file_name_match.group(1) if file_name_match else (msg.split()[0] if msg else "-")
        }
        self._write_csv_row("mft", data_dict)

    def parse_filestat(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        fn = event.get("filename", "-")
        data_dict = {
            "Date": ts_date, "Time": ts_time, "source": 'FILESTAT',
            "fileType": event.get("file_entry_type", "-"), "action": event.get("timestamp_desc", "-"),
            "fileName": fn
        }
        self._write_csv_row("mft", data_dict)
        if "\\programs\\startup" in fn.lower() or "\\start menu\\programs\\startup" in fn.lower():
            self._write_persistence(
                ts_date, ts_time, "STARTUP_FILE",
                os.path.basename(fn),
                fn,
                "-",
                f"Action: {event.get('timestamp_desc', '-')}, Source: FILESTAT"
            )

    def parse_file_mft(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        action = event.get("timestamp_desc", "-")
        path_hints = event.get("path_hints", [])
        if isinstance(path_hints, list):
            for path in path_hints:
                data_dict = {
                    "Date": ts_date, "Time": ts_time, "source": "MFT",
                    "fileType": "N/A", "action": action, "fileName": path
                }
                self._write_csv_row("mft", data_dict)
                if "\\programs\\startup" in path.lower() or "\\start menu\\programs\\startup" in path.lower():
                    self._write_persistence(
                        ts_date, ts_time, "STARTUP_FILE",
                        os.path.basename(path),
                        path,
                        "-",
                        f"Action: {action}, Source: MFT"
                    )

    def _write_csv_row(self, artifact_key, data_dict):
        """A helper function to write a data dictionary to the correct CSV file."""
        headers = self.csv_headers.get(artifact_key, [])
        row_data = [data_dict.get(h, "-") for h in headers]
        writer = self.get_csv_writer(artifact_key, delimiter=self.separator)
        if writer:
            writer.writerow(row_data)
            self.artifact_counts[artifact_key] += 1
            if artifact_key != "persistence":
                self.total_events_extracted += 1

    def _write_persistence(self, ts_date, ts_time, mechanism_type, name_or_key, command_or_path, user="-", details="-"):
        """Centralized writer for consolidated persistence mechanisms (persistence.csv)."""
        data_dict = {
            "Date": ts_date,
            "Time": ts_time,
            "mechanism_type": str(mechanism_type),
            "name_or_key": str(name_or_key).replace('\r\n', ' ').replace('\n', ' ') if name_or_key else "-",
            "command_or_path": str(command_or_path).replace('\r\n', ' ').replace('\n', ' ') if command_or_path else "-",
            "user": str(user).replace('\r\n', ' ').replace('\n', ' ') if user else "-",
            "details": str(details).replace('\r\n', ' ').replace('\n', ' ') if details else "-"
        }
        self._write_csv_row("persistence", data_dict)

    def create_timeline(self):
        """
        Merges all generated CSV files into a single, sorted timeline.
        """
        print("Creating final timeline...")
        timeline_filepath = os.path.join(self.csv_dir, 'timeline.csv')
        timeline_data = []

        for root, _, files in os.walk(self.csv_dir):
            for file in files:
                # Skip timeline.csv and persistence.csv to avoid self-merging and duplicate entries
                if file.endswith('.csv') and file not in ('timeline.csv', 'persistence.csv'):
                    filepath = os.path.join(root, file)
                    artifact_name = Path(filepath).stem
                    try:
                        with open(filepath, 'r', encoding='utf-8', newline='') as f:
                            reader = csv.reader(f, delimiter=self.separator)
                            header = next(reader, None)
                            if not header:
                                continue
                            for row in reader:
                                if len(row) >= 2:
                                    # Exclude or truncate large script block text from timeline
                                    if artifact_name == 'script_powershell' and 'script_block_text' in header:
                                        try:
                                            temp_row = list(row)
                                            script_block_index = header.index('script_block_text')
                                            temp_row[script_block_index] = "[Script Block Omitted]"
                                            other_info = self.separator.join(temp_row[2:])
                                        except (ValueError, IndexError):
                                            other_info = self.separator.join(row[2:])
                                    else:
                                        other_info = self.separator.join(row[2:])

                                    # Sanitize internal newlines in other_info for single-line timeline viewing
                                    other_info = other_info.replace('\r\n', ' ').replace('\n', ' ')
                                    timeline_row = [row[0], row[1], artifact_name, other_info]
                                    timeline_data.append(timeline_row)
                    except Exception as e:
                        print(f"Warning: Could not process {file} for timeline. Error: {e}", file=sys.stderr)

        # Sort by Date (column 0) then Time (column 1)
        timeline_data.sort(key=lambda x: (x[0], x[1]))
        self.total_timeline_events = len(timeline_data)

        print(f"Writing {len(timeline_data)} events to timeline.csv...")
        try:
            with open(timeline_filepath, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f, delimiter=self.separator)
                headers = self.csv_headers.get('timeline', ["Date", "Time", "SourceArtefact", "Other"])
                writer.writerow(headers)
                writer.writerows(timeline_data)
        except IOError as e:
            print(f"ERROR: Could not write timeline.csv: {e}", file=sys.stderr)

    def clean_duplicates(self):
        """
        Removes duplicate lines from all generated CSV files using csv.reader,
        preserving multi-line fields and maintaining chronological order.
        """
        print("Cleaning duplicate entries from result files...")
        for root, _, files in os.walk(self.csv_dir):
            for file in files:
                if file.endswith('.csv'):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8', newline='') as f:
                            reader = csv.reader(f, delimiter=self.separator)
                            header = next(reader, None)
                            if not header:
                                continue
                            seen = set()
                            unique_rows = []
                            for row in reader:
                                row_tuple = tuple(row)
                                if row_tuple not in seen:
                                    seen.add(row_tuple)
                                    unique_rows.append(row)

                        # Sort rows chronologically by Date (col 0) and Time (col 1) if available
                        unique_rows.sort(key=lambda r: (r[0] if len(r) > 0 else '', r[1] if len(r) > 1 else ''))

                        with open(filepath, 'w', encoding='utf-8', newline='') as f:
                            writer = csv.writer(f, delimiter=self.separator)
                            writer.writerow(header)
                            writer.writerows(unique_rows)

                    except Exception as e:
                        print(f"Warning: Could not clean duplicates from {file}. Error: {e}", file=sys.stderr)

    def print_summary(self, elapsed_seconds):
        """
        Prints a structured forensic summary report of all extracted artifacts.
        """
        filter_info = "None (Full Timeline)"
        if self.start_date_str and self.end_date_str:
            filter_info = f"{self.start_date_str} to {self.end_date_str} (UTC)"
        elif self.start_date_str:
            filter_info = f">= {self.start_date_str} (UTC)"
        elif self.end_date_str:
            filter_info = f"<= {self.end_date_str} (UTC)"

        speed = (self.total_lines_read / elapsed_seconds) if elapsed_seconds > 0 else 0
        c = self.artifact_counts

        cleared_count = c.get("log_cleared", 0)
        injection_count = c.get("sysmon_access", 0)
        defender_count = c.get("windefender", 0)
        user_mod_count = c.get("user_modification", 0)
        services_count = c.get("7045", 0)
        persistence_count = c.get("persistence", 0)

        cleared_flag = "  <-- [!] ALERT: LOGS CLEARED" if cleared_count > 0 else ""
        injection_flag = "  <-- [!] ALERT: INJECTION / LSASS ACCESS" if injection_count > 0 else ""
        defender_flag = "  <-- [!] ALERT: THREAT / TAMPERING" if defender_count > 0 else ""
        persistence_flag = "  <-- [!] PERSISTENCE IDENTIFIED" if persistence_count > 0 else ""

        print("\n" + "=" * 70)
        print("          MAXIMUM PLASO PARSER JSON - FORENSIC SUMMARY")
        print("=" * 70)
        print(f"  Analyzed Machine   : {self.machine_name}")
        print(f"  Timeline Source    : {self.path_to_timeline}")
        print(f"  Date Filter        : {filter_info}")
        print(f"  Output Directory   : {self.work_dir}")
        print("-" * 70)
        print("  CRITICAL FORENSIC ALERTS:")
        print(f"    Consolidated Persistence Found    : {persistence_count:,}{persistence_flag}")
        print(f"    Logs Cleared (1102 / 104)         : {cleared_count:,}{cleared_flag}")
        print(f"    Sysmon Access / Injection (8/10)  : {injection_count:,}{injection_flag}")
        print(f"    Windows Defender Detections/Tamper: {defender_count:,}{defender_flag}")
        print(f"    User & Group Account Changes      : {user_mod_count:,}")
        print(f"    Service Installations (7045/4697) : {services_count:,}")
        print("\n  EXECUTION & PERSISTENCE ARTIFACTS:")
        total_logons = c.get('4624', 0) + c.get('4625', 0) + c.get('4672', 0) + c.get('4648', 0)
        reg_total = c.get('run', 0) + c.get('mru', 0) + c.get('mui_cache', 0) + c.get('common_reg', 0)

        report_lines = [
            "=" * 70,
            "          MAXIMUM PLASO PARSER JSON - FORENSIC SUMMARY",
            "=" * 70,
            f"  Analyzed Machine   : {self.machine_name}",
            f"  Timeline Source    : {self.path_to_timeline}",
            f"  Date Filter        : {filter_info}",
            f"  Output Directory   : {self.work_dir}",
            "-" * 70,
            "  CRITICAL FORENSIC ALERTS:",
            f"    Consolidated Persistence Found    : {persistence_count:,}{persistence_flag}",
            f"    Logs Cleared (1102 / 104)         : {cleared_count:,}{cleared_flag}",
            f"    Sysmon Access / Injection (8/10)  : {injection_count:,}{injection_flag}",
            f"    Windows Defender Detections/Tamper: {defender_count:,}{defender_flag}",
            f"    User & Group Account Changes      : {user_mod_count:,}",
            f"    Service Installations (7045/4697) : {services_count:,}",
            "",
            "  EXECUTION & PERSISTENCE ARTIFACTS:",
            f"    User Logons (4624/4625/4672/4648) : {total_logons:,}",
            f"    Process Creation (Security 4688)  : {c.get('4688', 0):,}",
            f"    Sysmon Process Creation (ID 1)    : {c.get('sysmon_proc', 0):,}",
            f"    Sysmon Network Connections (ID 3) : {c.get('sysmon_network', 0):,}",
            f"    Sysmon DNS Queries (ID 22)        : {c.get('sysmon_dns', 0):,}",
            f"    Sysmon File Create (ID 11)        : {c.get('sysmon_file', 0):,}",
            f"    Sysmon Registry ASEP (12/13/14)   : {c.get('sysmon_registry', 0):,}",
            f"    Sysmon Modules / DLLs (ID 7)      : {c.get('sysmon_module', 0):,}",
            f"    PowerShell Commands & Scripts     : {c.get('powershell', 0) + c.get('script_powershell', 0):,}",
            f"    Scheduled Tasks (TaskScheduler)   : {c.get('tscheduler', 0):,}",
            f"    BITS Jobs Transfers               : {c.get('bits', 0):,}",
            f"    WMI Activities & Failures         : {c.get('wmi', 0) + c.get('wmi_failure', 0):,}",
            f"    RDP Connections (Local & Remote)  : {c.get('local_rdp', 0) + c.get('remote_rdp', 0):,}",
            "",
            "  SYSTEM & EVIDENCE OF EXECUTION ARTIFACTS:",
            f"    Amcache Executables               : {c.get('amcache', 0):,}",
            f"    AppCompat ShimCache               : {c.get('appcompat', 0):,}",
            f"    Prefetch Executions               : {c.get('prefetch', 0):,}",
            f"    UserAssist Applications           : {c.get('userassist', 0):,}",
            f"    MFT & USN Journal File Events     : {c.get('mft', 0):,}",
            f"    Browser History Records           : {c.get('browser_history', 0):,}",
            f"    LNK Shortcut Files                : {c.get('lnk', 0):,}",
            f"    Registry Keys (Run/MRU/MUI/Common): {reg_total:,}",
            "-" * 70,
            f"  Total Events Scanned from Plaso     : {self.total_lines_read:,}",
            f"  Total Forensic Events Extracted     : {self.total_events_extracted:,}",
            f"  Events in Merged timeline.csv       : {self.total_timeline_events:,}",
            f"  Consolidated in persistence.csv     : {persistence_count:,}",
            f"  Processing Speed                    : {speed:,.0f} events/sec",
            f"  Execution Time                      : {timedelta(seconds=int(elapsed_seconds))}",
            "=" * 70,
            f"  [+] All CSV files saved in: {self.csv_dir}",
        ]

        report_filepath = os.path.join(self.work_dir, "summary_report.txt")
        try:
            with open(report_filepath, 'w', encoding='utf-8') as f:
                f.write("\n".join(report_lines) + "\n")
            report_lines.append(f"  [+] Summary report saved in: {report_filepath}")
        except IOError as e:
            print(f"Warning: Could not save summary report file: {e}", file=sys.stderr)

        report_lines.append("=" * 70)
        report_text = "\n" + "\n".join(report_lines) + "\n"
        print(report_text)

def parse_args():
    """
    Parses command line arguments.
    """
    parser = argparse.ArgumentParser(
        description='MaximumPlasoParserJson: Fast Forensic Timeline Classifier for Plaso JSON-L timelines.'
    )
    parser.add_argument('-t', '--timeline', required=True, dest="timeline",
                        help="Path to the JSON_line Plaso timeline file.")
    parser.add_argument("-o", "--output", required=True, dest="output_dir",
                        help="Destination directory for CSV results.")
    parser.add_argument("-s", "--separator", default="|", dest="separator",
                        help="Separator for CSV files (default: '|').")
    parser.add_argument("-m", "--machine_name", default="", dest="machine_name",
                        help="Name of the analyzed machine (used in folder structure).")
    parser.add_argument("--start-date", default=None, dest="start_date",
                        help="Filter events on or after date (format: 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS' in UTC).")
    parser.add_argument("--end-date", default=None, dest="end_date",
                        help="Filter events on or before date (format: 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS' in UTC).")
    return parser.parse_args()


def is_valid_json_line(filepath):
    """
    Checks if the first line of the file is valid JSON.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            first_line = f.readline()
            if not first_line:
                return False
            json.loads(first_line)
        return True
    except (IOError, json.JSONDecodeError, UnicodeDecodeError):
        return False


if __name__ == '__main__':
    args = parse_args()

    if not is_valid_json_line(args.timeline):
        print("ERROR: Timeline file is not a valid JSON-L file or is unreadable.", file=sys.stderr)
        sys.exit(1)

    start_time = time.time()
    print(f"Parser started at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    try:
        mpp = MaximumPlasoParser(
            path_to_timeline=args.timeline,
            output_directory=args.output_dir,
            separator=args.separator,
            machine_name=args.machine_name,
            start_date=args.start_date,
            end_date=args.end_date
        )
    except ValueError as ve:
        print(f"ERROR: {ve}", file=sys.stderr)
        sys.exit(1)

    mpp.parse_timeline()
    mpp.clean_duplicates()
    mpp.create_timeline()

    time_in_sec = time.time() - start_time
    mpp.print_summary(time_in_sec)

