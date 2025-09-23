#!/usr/bin/python3
import argparse
import csv
import xmltodict
import os
import traceback
from datetime import datetime, timedelta
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

    def __init__(self, path_to_timeline, output_directory, separator="|", machine_name=""):
        """
        Constructor for the MaximumPlasoParser Class
        """
        self.path_to_timeline = path_to_timeline
        self.dir_out = output_directory
        self.separator = separator
        self.machine_name = machine_name if machine_name else "no_name"

        self.current_date = datetime.utcnow().strftime("%Y-%m-%d_%H_%M_%S")
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
                                  "TargetDomainName", "TargetSid", "SamAccountName", "PasswordLastSet"],
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
            "mru_run": ["Date", "Time", "cmd"]
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
        try:
            dt = datetime.fromtimestamp(epoch_time / 1000000)
            return dt.strftime('%Y-%m-%d'), dt.strftime('%H:%M:%S')
        except (ValueError, TypeError):
            return "-", "-"

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

    def _xml_data_to_dict(self, event_data_list):
        if not isinstance(event_data_list, list):
            return {}
        return {item.get('@Name'): item.get('#text', '-') for item in event_data_list}

    def close_files(self):
        print("Closing all open files...")
        for handler in self.file_handlers.values():
            try:
                handler.close()
            except Exception as e:
                print(f"Warning: could not close a file. Error: {e}")

    def parse_timeline(self):
        try:
            with open(self.path_to_timeline, 'r', encoding='utf-8') as timeline:
                for line in timeline:
                    try:
                        d_line = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    type_artefact = self.identify_type_artefact_by_parser(d_line)
                    if type_artefact:
                        self.assign_parser(d_line, type_artefact)
        except Exception:
            print(f"Critical error during parsing: {traceback.format_exc()}", file=sys.stderr)
        finally:
            self.close_files()

    def identify_type_artefact_by_parser(self, line):
        parser = line.get("parser", "")
        for key, value in self.d_regex_type_artefact.items():
            if re.search(value, parser):
                return key
        return None

    def identify_artefact_by_parser_name(self, line):
        parser = line.get("parser", "")
        for key, value in self.d_regex_artefact_by_parser_name.items():
            if re.search(value, parser):
                return key
        return None

    def identify_artefact_by_source_name(self, line):
        source_name = line.get("source_name", "")
        for key, value in self.d_regex_artefact_by_source_name.items():
            if re.search(value, source_name):
                return key
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
        elif event_code in (4608, 4609):
            self.parse_windows_startup_shutdown(event)
        elif event_code in (4720, 4723, 4724, 4726):
            self.parse_user_modification(event, event_code)

    def parse_logon_from_xml(self, event, artifact_key):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = self._xml_data_to_dict(evt_as_json.get("Event", {}).get("EventData", {}).get("Data"))
        except (xmltodict.expat.ExpatError, IndexError):
            return

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "subject_user_name": data.get("SubjectUserName", "-"), "target_user_name": data.get("TargetUserName", "-"),
            "ip_address": data.get("IpAddress", "-"), "ip_port": data.get("IpPort", "-"),
            "logon_type": data.get("LogonType", "-")
        }
        self._write_csv_row(artifact_key, data_dict)

    def parse_failed_logon_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = self._xml_data_to_dict(evt_as_json.get("Event", {}).get("EventData", {}).get("Data"))
        except (xmltodict.expat.ExpatError, IndexError):
            return

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
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = self._xml_data_to_dict(evt_as_json.get("Event", {}).get("EventData", {}).get("Data"))
        except (xmltodict.expat.ExpatError, IndexError):
            return

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
        if event_code == 4720:
            info = "UserCreation"
        elif event_code == 4726:
            info = "userDeletion"
        elif event_code == 4723:
            info = "PswdChangedByUser"
        elif event_code == 4724:
            info = "PswdResetedByTiers"
        else:
            info = "UnknownUserModification"

        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = self._xml_data_to_dict(evt_as_json.get("Event", {}).get("EventData", {}).get("Data"))
        except (xmltodict.expat.ExpatError, IndexError):
            return

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
        }
        self._write_csv_row("user_modification", data_dict)

    def parse_system_evtx(self, event):
        if event.get("event_identifier") == 7045: self.parse_service_from_xml(event)

    def parse_service_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = self._xml_data_to_dict(evt_as_json.get("Event", {}).get("EventData", {}).get("Data"))
        except (xmltodict.expat.ExpatError, IndexError):
            return

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": "7045", "account_name": data.get("AccountName", "-"),
            "img_path": data.get("ImagePath", "-"), "service_name": data.get("ServiceName", "-"),
            "start_type": data.get("StartType", "-")
        }
        self._write_csv_row("7045", data_dict)

    def parse_task_scheduler(self, event):
        if str(event.get("event_identifier")) in ["106", "107", "140", "141", "200", "201"]:
            self.parse_task_scheduler_from_xml_taskevt(event)

    def parse_task_scheduler_from_xml_taskevt(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = self._xml_data_to_dict(evt_as_json.get("Event", {}).get("EventData", {}).get("Data"))
        except (xmltodict.expat.ExpatError, IndexError):
            return

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "name": data.get("Name", "-"), "task_name": data.get("TaskName", "-"),
            "instance_id": data.get("InstanceId", "-"), "action_name": data.get("ActionName", "-"),
            "result_code": data.get("ResultCode", "-"), "user_name": data.get("UserName", "-"),
            "user_context": data.get("UserContext", "-")
        }
        self._write_csv_row("tscheduler", data_dict)

    def parse_bits(self, event):
        if str(event.get("event_identifier")) in ["3", "4", "59", "60", "61"]:
            self.parse_bits_evtx_from_xml(event)

    def parse_bits_evtx_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = self._xml_data_to_dict(evt_as_json.get("Event", {}).get("EventData", {}).get("Data"))
        except (xmltodict.expat.ExpatError, IndexError):
            return

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
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = evt_as_json.get("Event", {}).get("UserData", {}).get("EventXML", {})
        except (xmltodict.expat.ExpatError, IndexError):
            return

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
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            event_data = evt_as_json.get("Event", {}).get("UserData", {})
            op_name = next(iter(event_data), None)
            if not op_name: return
            op_dict = event_data.get(op_name, {})
        except (xmltodict.expat.ExpatError, IndexError):
            return

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "operation_name": op_name, "user": op_dict.get("User", "-"),
            "namespace": op_dict.get("NamespaceName", "-"), "consumer": op_dict.get("CONSUMER", "-"),
            "cause": op_dict.get("PossibleCause", "-").replace("\n", " "),
            "query": op_dict.get("Query", "-").replace("\n", " ")
        }
        self._write_csv_row("wmi", data_dict)

    def parse_wmi_failure_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            event_data = evt_as_json.get("Event", {}).get("UserData", {})
            op_name = next(iter(event_data), None)
            if not op_name: return
            op_dict = event_data.get(op_name, {})
        except (xmltodict.expat.ExpatError, IndexError):
            return

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "operation_name": op_name, "user": op_dict.get("User", "-"),
            "namespace": op_dict.get("NamespaceName", "-"), "consumer": op_dict.get("CONSUMER", "-"),
            "cause": op_dict.get("PossibleCause", "-").replace("\n", " "),
            "operation": op_dict.get("Operation", "-").replace("\n", " ")
        }
        self._write_csv_row("wmi_failure", data_dict)

    def parse_powershell(self, event):
        event_code = str(event.get("event_identifier"))
        if event_code in ["4104", "4105", "4106"]: self.parse_powershell_script_from_xml(event)
        if event_code in ["400", "600"]: self.parse_powershell_cmd_from_xml(event)

    def parse_powershell_script_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = self._xml_data_to_dict(evt_as_json.get("Event", {}).get("EventData", {}).get("Data"))
        except (xmltodict.expat.ExpatError, IndexError):
            return

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "path_to_script": data.get("Path", "-"), "script_block_text": data.get("ScriptBlockText", "-")
        }
        self._write_csv_row("script_powershell", data_dict)

    def parse_powershell_cmd_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        cmd = "-"
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])
            for line in event_data:
                if "HostApplication=" in line:
                    for part in line.split("\n"):
                        if "HostApplication" in part:
                            cmd = part.split("HostApplication=")[1].strip()
                            break
        except (xmltodict.expat.ExpatError, IndexError):
            pass

        data_dict = {"Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"), "cmd": cmd}
        self._write_csv_row("powershell", data_dict)

    def parse_app_experience(self, event):
        if str(event.get("event_identifier")) in ["500", "505", "17"]:
            self.parse_app_experience_from_xml(event)

    def parse_app_experience_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = evt_as_json.get("Event", {}).get("UserData", {}).get("CompatibilityFixEvent", {})
        except (xmltodict.expat.ExpatError, IndexError):
            return

        data_dict = {
            "Date": ts_date, "Time": ts_time, "event_code": event.get("event_identifier"),
            "FixName": data.get("FixName", "-"), "ExePath": data.get("ExePath", "-")
        }
        self._write_csv_row("app_exp", data_dict)

    def parse_windows_defender(self, event):
        event_code = str(event.get("event_identifier"))
        if event_code in ["1116", "1117", "1118", "1119"]:
            self.parse_windef_from_xml(event)

    def parse_windef_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            evt_as_json = xmltodict.parse(event.get("xml_string", "<_/>"))
            data = self._xml_data_to_dict(evt_as_json.get("Event", {}).get("EventData", {}).get("Data"))
        except (xmltodict.expat.ExpatError, IndexError):
            return

        event_type = "Detection" if str(event.get("event_identifier")) == "1116" else "Action"
        data_dict = {
            "Date": ts_date, "Time": ts_time, "Event": f"{event.get('event_identifier')} - {event_type}",
            "ThreatName": data.get("Threat Name", "-"), "Severity": data.get("Severity Name", "-"),
            "User": data.get("Detection User", "-"), "ProcessName": data.get("Process Name", "-"),
            "Path": data.get("Path", "-"), "Action": data.get("Action Name", "-")
        }
        self._write_csv_row("windefender", data_dict)

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
        else:
            details = event.get("message", "-").split("]")[-1].strip()
            data_dict = {"Date": ts_date, "Time": ts_time, "type": reg_type, "key_path": key_path, "details": details}
            self._write_csv_row("common_reg", data_dict)

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
        if entries:
            for entrie in entries:
                data_dict = {"Date": ts_date, "Time": ts_time, "entrie": entrie}
                self._write_csv_row("run", data_dict)

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
        if event.get("description", "-") != "-" and event.get("working_directory", "-") != "-":
            data_dict = {
                "Date": ts_date, "Time": ts_time, "description": event.get("description", "-"),
                "working_dir": event.get("working_directory", "-")
            }
            self._write_csv_row("lnk", data_dict)

    # --- MFT PARSERS ---
    def parse_mft(self, line):
        parser = line.get("parser")
        if parser == "usnjrnl":
            self.parse_usnjrl(line)
        elif parser == "mft":
            self.parse_file_mft(line)
        elif parser == "filestat" and "NTFS" in str(line):
            self.parse_filestat(line)

    def parse_usnjrl(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        msg = event.get("message", "")

        file_name_match = re.search(r'^(.{1,}\.){1,}(\w){1,3}', msg)
        reason_match = re.search(r'Update reason: (.*)', msg)

        data_dict = {
            "Date": ts_date, "Time": ts_time, "source": "USNJRNL", "fileType": "N/A",
            "action": reason_match.group(1).replace(',', '') if reason_match else "noReason",
            "fileName": file_name_match.group() if file_name_match else msg
        }
        self._write_csv_row("mft", data_dict)

    def parse_filestat(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        data_dict = {
            "Date": ts_date, "Time": ts_time, "source": 'FILESTAT',
            "fileType": event.get("file_entry_type", "-"), "action": event.get("timestamp_desc", "-"),
            "fileName": event.get("filename", "-")
        }
        self._write_csv_row("mft", data_dict)

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

    def _write_csv_row(self, artifact_key, data_dict):
        """A helper function to write a data dictionary to the correct CSV file."""
        headers = self.csv_headers.get(artifact_key, [])
        row_data = [data_dict.get(h, "-") for h in headers]
        writer = self.get_csv_writer(artifact_key, delimiter=self.separator)
        if writer:
            writer.writerow(row_data)

    def create_timeline(self):
        """
        Merges all generated CSV files into a single, sorted timeline.
        """
        print("Creating final timeline...")
        timeline_data = []
        for root, _, files in os.walk(self.csv_dir):
            for file in files:
                if file.endswith('.csv'):
                    filepath = os.path.join(root, file)
                    artifact_name = Path(filepath).stem
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            reader = csv.reader(f, delimiter=self.separator)
                            header = next(reader)  # Read header
                            for row in reader:
                                # Ensure row has at least date and time
                                if len(row) >= 2:

                                    # Exclude large script block text from timeline
                                    if artifact_name == 'script_powershell':
                                        try:
                                            # Create a copy to modify
                                            temp_row = list(row)
                                            script_block_index = header.index('script_block_text')
                                            temp_row[script_block_index] = "[Script Block Omitted]"
                                            other_info = self.separator.join(temp_row[2:])
                                        except (ValueError, IndexError):
                                            other_info = self.separator.join(row[2:])  # Fallback
                                    else:
                                        other_info = self.separator.join(row[2:])

                                    timeline_row = [row[0], row[1], artifact_name, other_info]
                                    timeline_data.append(timeline_row)
                    except Exception as e:
                        print(f"Warning: Could not process {file} for timeline. Error: {e}")

        # Sort by Date (column 0) then Time (column 1)
        timeline_data.sort(key=lambda x: (x[0], x[1]))

        print(f"Writing {len(timeline_data)} events to timeline.csv...")
        writer = self.get_csv_writer('timeline', delimiter=self.separator)
        if writer:
            writer.writerows(timeline_data)

    def clean_duplicates(self):
        """
        Removes duplicate lines from all generated CSV files, preserving the header.
        """
        print("Cleaning duplicate entries from result files...")
        for root, _, files in os.walk(self.csv_dir):
            for file in files:
                if file.endswith('.csv'):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            lines = f.readlines()

                        if len(lines) > 1:
                            header = lines[0]
                            # Use a set for the body to automatically handle duplicates
                            unique_body_lines = set(lines[1:])

                            # Reconstruct the file with header and sorted unique body
                            final_lines = [header] + sorted(list(unique_body_lines))

                            if len(final_lines) < len(lines):
                                print(f"  - Removed {len(lines) - len(final_lines)} duplicates from {file}")
                                with open(filepath, 'w', encoding='utf-8') as f:
                                    f.writelines(final_lines)

                    except Exception as e:
                        print(f"Warning: Could not clean duplicates from {file}. Error: {e}")


def parse_args():
    """
    Parses command line arguments.
    """
    parser = argparse.ArgumentParser(description='A robust parser for Plaso JSON timelines.')
    parser.add_argument('-t', '--timeline', required=True, dest="timeline",
                        help="Path to the JSON plaso timeline file.")
    parser.add_argument("-o", "--output", required=True, dest="output_dir",
                        help="Destination directory for CSV results.")
    parser.add_argument("-s", "--separator", default="|", dest="separator",
                        help="Separator for CSV files (default: '|').")
    parser.add_argument("-m", "--machine_name", default="", dest="machine_name", help="Name of the analyzed machine.")
    return parser.parse_args()


def is_valid_json_line(filepath):
    """
    Checks if the first line of the file is valid JSON.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            json.loads(f.readline())
        return True
    except (IOError, json.JSONDecodeError, UnicodeDecodeError):
        return False


if __name__ == '__main__':
    args = parse_args()

    if not is_valid_json_line(args.timeline):
        print("ERROR: Timeline file is not a valid JSON-L file or is unreadable.", file=sys.stderr)
        sys.exit(1)

    start_time = time.time()
    print(f"Parser started at: {datetime.now().strftime('%Y-%m-%d, %H:%M:%S')}")

    mpp = MaximumPlasoParser(
        path_to_timeline=args.timeline,
        output_directory=args.output_dir,
        separator=args.separator,
        machine_name=args.machine_name
    )
    mpp.parse_timeline()
    mpp.clean_duplicates()  # Clean duplicates before creating timeline
    mpp.create_timeline()  # Create the final merged timeline

    time_in_sec = time.time() - start_time
    print(f"Finished in {timedelta(seconds=time_in_sec)}")

