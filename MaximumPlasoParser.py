#!/usr/bin/python3
import json
import os
import traceback
import argparse
import re
from datetime import datetime
import xmltodict
import time


class MaximumPlasoParser:
    """
       Class to manage cache
       Attributes :
    """

    def __init__(self, dir_out, output_type="csv", separator="|", case_name=None, config_file=None) -> None:
        """
        The constructor for ManageCache class.
        Parameters:
        """
        self.dir_out = dir_out
        self.output_type = output_type
        self.separator = separator
        self.case_name = case_name

        if config_file:
            self.config = self.read_json_config(config_file)
        else:
            self.config = {
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

        self.d_regex_type_artefact = {
            "evtx": re.compile(r'winevtx'),
            "hive": re.compile(r'winreg'),
            "db": re.compile(r'(sqlite)|(esedb)'),
            "winFile": re.compile(r'(lnk)|(text)|(prefetch)')
        }
        self.d_regex_aterfact_by_file_name = {
            "security": re.compile(r'((s|S)ecurity\.evtx|(s|S)ecurity\.evt)'),
            "system": re.compile(r'((s|S)ystem\.evtx|(s|S)ystem\.evt)'),
            "taskScheduler": re.compile(r'.*TaskScheduler%4Operational\.evtx'),
            "bits": re.compile(r'.*Bits-Client%4Operational\.evtx'),
            "rdp_local": re.compile(r'.*TerminalServices-LocalSessionManager%4Operational\.evtx'),
            "powershell": re.compile(r'(.*Microsoft-Windows-PowerShell%4Operational\.evtx)|(.*Windows_PowerShell\.evtx)'),
            "wmi": re.compile(r'.*Microsoft-Windows-WMI-Activity%4Operational\.evtx'),
            "application_experience": re.compile(r'.*Microsoft-Windows-Application-Experience%4Program-Telemetry\.evtx'),
            "amcache": re.compile(r'.*(A|a)mcache\.hve'),
            "appCompat": re.compile(r'.*(A|a)mcache\.hve')
        }
        self.d_regex_artefact_by_source_name = {
            "security": re.compile(r'Microsoft-Windows-Security-Auditing'),
            "system": re.compile(r'Service Control Manager'),
            "taskScheduler": re.compile(r'.*TaskScheduler%4Operational\.evtx'),
            "bits": re.compile(r'Microsoft-Windows-Bits-Client'),
            "rdp_local": re.compile(r'Microsoft-Windows-TerminalServices-LocalSessionManager'),
            "powershell": re.compile(r'(Microsoft-Windows-PowerShell)|(PowerShell)'),
            "wmi": re.compile(r'Microsoft-Windows-WMI-Activity'),
            "application_experience": re.compile(r'Microsoft-Windows-Application-Experience')
        }
        self.d_regex_artefact_by_parser_name = {
            "amcache": re.compile(r'amcache'),
            "appCompat": re.compile(r'appcompatcache'),
            "sam": re.compile(r'windows_sam_users'),
            "userassist": re.compile(r'userassist'),
            "mru": re.compile(r'(bagmru)|(mru)'),
            "ff_history": re.compile(r'firefox_history'),
            "prefetch": re.compile(r'prefetch'),
            "lnk": re.compile(r'lnk'),
            "srum": re.compile(r'srum'),
            "run": re.compile(r'windows_run')
        }

        self.logon_res_file = ""
        self.logon_failed_file = ""
        self.logon_spe_file = ""
        self.logon_exp_file = ""
        self.new_proc_file = ""
        self.task_scheduler_file = ""
        self.remote_rdp_file = ""
        self.local_rdp_file = ""
        self.bits_file = ""
        self.service_file = ""
        self.powershell_file = ""
        self.powershell_script_file = ""
        self.wmi_file = ""
        self.app_exp_file = ""
        self.amcache_res_file = ""
        self.app_compat_res_file = ""
        self.sam_res_file = ""
        self.user_assist_file = ""
        self.mru_res_file = ""
        self.ff_history_res_file = ""
        self.prefetch_res_file = ""
        self.srum_res_file = ""
        self.run_res_file = ""

        if self.output_type == "csv":
            self.initialise_csv_files()
        elif self.output_type == "json":
            self.initialise_json_files()

    @staticmethod
    def read_json_config(path_to_config):
        with open(path_to_config, 'r') as config:
            return json.load(config)

    @staticmethod
    def convert_epoch_to_date(epoch_time_str):
        dt = datetime.fromtimestamp(epoch_time_str / 1000000).strftime('%Y-%m-%dT%H:%M:%S')
        l_dt = dt.split("T")
        return l_dt[0], l_dt[1]

    def identify_type_artefact_by_parser(self, line):
        for key, value in self.d_regex_type_artefact.items():
            if re.search(value, line.get("parser")):
                return key

    def identify_artefact_by_filename(self, line):
        for key, value in self.d_regex_aterfact_by_file_name.items():
            if re.search(value, line.get("filename")):
                return key

    def identify_artefact_by_source_name(self, line):
        for key, value in self.d_regex_artefact_by_source_name.items():
            if re.search(value, line.get("source_name")):
                return key

    def identify_artefact_by_parser_name(self, line):
        for key, value in self.d_regex_artefact_by_parser_name.items():
            if re.search(value, line.get("parser")):
                return key

    def assign_parser(self, line, type_artefact):
        if type_artefact == "evtx":
            self.parse_logs(line)
        if type_artefact == "hive":
            self.parse_hives(line)
        if type_artefact == "db":
            self.parse_db(line)
        if type_artefact == "winFile":
            self.parse_win_file(line)

    def initialise_csv_files(self):

        if self.config.get("4624"):
            l_res_4624_header = ["Date", "time", "event_code", "logon_type", "subject_user_name", "target_user_name",
                                 "ip_address", "ip_port", "workstation_name"]

            self.logon_res_file = open(os.path.join(self.dir_out, "4624.csv"), 'a')
            self.logon_res_file.write(self.separator.join(l_res_4624_header))
            self.logon_res_file.write("\n")

        if self.config.get("4625"):
            l_res_4625_header = ["Date", "time", "event_code", "logon_type", "subject_user_name", "target_user_name",
                                 "ip_address", "ip_port", "workstation_name"]
            self.logon_failed_file = open(os.path.join(self.dir_out, "4625.csv"), 'a')
            self.logon_failed_file.write(self.separator.join(l_res_4625_header))
            self.logon_failed_file.write("\n")

        if self.config.get("4672"):
            l_res_4672_header = ["Date", "time", "event_code", "logon_type", "subject_user_name", "target_user_name",
                                 "ip_address", "ip_port", "workstation_name"]
            self.logon_spe_file = open(os.path.join(self.dir_out, "4672.csv"), 'a')
            self.logon_spe_file.write(self.separator.join(l_res_4672_header))
            self.logon_spe_file.write("\n")

        if self.config.get("4648"):
            l_res_4648_header = ["Date", "time", "event_code", "logon_type", "subject_user_name", "target_user_name",
                                 "ip_address", "ip_port", "workstation_name"]
            self.logon_exp_file = open(os.path.join(self.dir_out, "4648.csv"), 'a')
            self.logon_exp_file.write(self.separator.join(l_res_4648_header))
            self.logon_exp_file.write("\n")

        if self.config.get("4688"):
            l_res_4688_header = ["Date", "time", "event_code", "new_process_name", "command_line",
                                 "parent_process_name",
                                 "subject_user_name", "target_user_name", "workstation_name"]
            self.new_proc_file = open(os.path.join(self.dir_out, "4688.csv"), 'a')
            self.new_proc_file.write(self.separator.join(l_res_4688_header))
            self.new_proc_file.write("\n")

        if self.config.get("task_scheduler"):
            l_task_scheduler_header = ["Date", "time", "event_code", "name", "task_name", "instance_id", "action_name",
                                       "result_code", "user_name", "user_context"]

            self.task_scheduler_file = open(os.path.join(self.dir_out, "task_scheduler.csv"), 'a')
            self.task_scheduler_file.write(self.separator.join(l_task_scheduler_header))
            self.task_scheduler_file.write("\n")

        if self.config.get("remote_rdp"):
            l_rdp_remote_header = ["date", "time", "event_code", "user_name", "ip_addr"]
            self.remote_rdp_file = open(os.path.join(self.dir_out, "rdp_remote.csv"), 'a')
            self.remote_rdp_file.write(self.separator.join(l_rdp_remote_header))
            self.remote_rdp_file.write("\n")

        if self.config.get("local_rdp"):
            l_rdp_local_header = ["date", "time", "event_code", "user_name", "ip_addr", "session_id", "source",
                                  "target_session", "reason_n", "reason"]
            self.local_rdp_file = open(os.path.join(self.dir_out, "rdp_local.csv"), 'a')
            self.local_rdp_file.write(self.separator.join(l_rdp_local_header))
            self.local_rdp_file.write("\n")

        if self.config.get("bits"):
            l_bits_header = ["date", "time", "event_code", "id", "job_id", "job_title", "job_owner", "user",
                             "bytes_total",
                             "bytes_transferred", "file_count", "file_length", "file_time", "name", "url",
                             "process_path"]
            self.bits_file = open(os.path.join(self.dir_out, "bits.csv"), 'a')
            self.bits_file.write(self.separator.join(l_bits_header))
            self.bits_file.write("\n")

        if self.config.get("service"):
            l_7045_header = ["date", "time", "event_code", "account_name", "img_path", "service_name", "start_type"]
            self.service_file = open(os.path.join(self.dir_out, "7045.csv"), 'a')
            self.service_file.write(self.separator.join(l_7045_header))
            self.service_file.write("\n")

        if self.config.get("powershell"):
            l_powershell_header = ["date", "time", "event_code", "path_to_script", "script_block_text"]
            self.powershell_file = open(os.path.join(self.dir_out, "powershell.csv"), 'a')
            self.powershell_file.write(self.separator.join(l_powershell_header))
            self.powershell_file.write("\n")

        if self.config.get("powershell_script"):
            l_powershell_script_header = ["date", "time", "event_code", "cmd"]
            self.powershell_script_file = open(os.path.join(self.dir_out, "powershell_script.csv"), 'a')
            self.powershell_script_file.write(self.separator.join(l_powershell_script_header))
            self.powershell_script_file.write("\n")

        if self.config.get("wmi"):
            l_wmi_header = ["date", "time", "user", "nameSpace", "Query"]
            self.wmi_file = open(os.path.join(self.dir_out, "wmi.csv"), 'a')
            self.wmi_file.write(self.separator.join(l_wmi_header))
            self.wmi_file.write("\n")

        # ----------------------------- Hives ------------------------------------------------

        if self.config.get("app_exp"):
            l_app_exp_header = ["date", "time", "ExePath", "FixName", "Query"]
            self.app_exp_file = open(os.path.join(self.dir_out, "application_experience.csv"), 'a')
            self.app_exp_file.write(self.separator.join(l_app_exp_header))
            self.app_exp_file.write("\n")

        if self.config.get("amcache"):
            l_res_amcache_header = ["Date", "time", "name", "id", "sha256", "full_path"]
            self.amcache_res_file = open(os.path.join(self.dir_out, "amcache.csv"), 'a')
            self.amcache_res_file.write(self.separator.join(l_res_amcache_header))
            self.amcache_res_file.write("\n")

        if self.config.get("app_compat"):
            l_res_app_compat_header = ["Date", "time", "name", "sha256", "full_path"]
            self.app_compat_res_file = open(os.path.join(self.dir_out, "app_compat.csv"), 'a')
            self.app_compat_res_file.write(self.separator.join(l_res_app_compat_header))
            self.app_compat_res_file.write("\n")

        if self.config.get("sam"):
            l_res_sam_header = ["Date", "time", "username", "login_count"]
            self.sam_res_file = open(os.path.join(self.dir_out, "sam.csv"), 'a')
            self.sam_res_file.write(self.separator.join(l_res_sam_header))
            self.sam_res_file.write("\n")

        if self.config.get("user_assist"):
            l_res_ussera_header = ["Date", "time", "valueName", "appFocus", "appDuration"]
            self.user_assist_file = open(os.path.join(self.dir_out, "userassist.csv"), 'a')
            self.user_assist_file.write(self.separator.join(l_res_ussera_header))
            self.user_assist_file.write("\n")

        if self.config.get("mru"):
            l_res_mru_header = ["Date", "time", "entries"]
            self.mru_res_file = open(os.path.join(self.dir_out, "shellBags.csv"), 'a')
            self.mru_res_file.write(self.separator.join(l_res_mru_header))
            self.mru_res_file.write("\n")

        if self.config.get("srum"):
            l_res_srum_header = ["Date", "time", "description"]
            self.srum_res_file = open(os.path.join(self.dir_out, "srum.csv"), 'a')
            self.srum_res_file.write(self.separator.join(l_res_srum_header))
            self.srum_res_file.write("\n")

        if self.config.get("run"):
            l_res_run_header = ["Date", "time", "entrie"]
            self.run_res_file = open(os.path.join(self.dir_out, "run.csv"), 'a')
            self.run_res_file.write(self.separator.join(l_res_run_header))
            self.run_res_file.write("\n")

        # ----------------------------- Other ------------------------------------------------

        if self.config.get("ff_history"):
            l_res_ff_histo_header = ["Date", "time", "url", "visit_count", "visit_type", "isType", "from_visit"]
            self.ff_history_res_file = open(os.path.join(self.dir_out, "firefox_history.csv"), 'a')
            self.ff_history_res_file.write(self.separator.join(l_res_ff_histo_header))
            self.ff_history_res_file.write("\n")

        if self.config.get("prefetch"):
            l_res_prefetch_header = ["Date", "time", "name", "path", "nbExec", "sha256"]
            self.prefetch_res_file = open(os.path.join(self.dir_out, "prefetch.csv"), 'a')
            self.prefetch_res_file.write(self.separator.join(l_res_prefetch_header))
            self.prefetch_res_file.write("\n")

        if self.config.get("lnk"):
            l_res_lnk_header = ["Date", "time", "description", "working_dir"]
            self.lnk_res_file = open(os.path.join(self.dir_out, "lnk.csv"), 'a')
            self.lnk_res_file.write(self.separator.join(l_res_lnk_header))
            self.lnk_res_file.write("\n")

    def initialise_json_files(self):

        if self.config.get("4624"):
            self.logon_res_file = open(os.path.join(self.dir_out, "4624.json"), 'a')

        if self.config.get("4625"):
            self.logon_failed_file = open(os.path.join(self.dir_out, "4625.json"), 'a')

        if self.config.get("4672"):
            self.logon_spe_file = open(os.path.join(self.dir_out, "4672.json"), 'a')

        if self.config.get("4648"):
            self.logon_exp_file = open(os.path.join(self.dir_out, "4648.json"), 'a')

        if self.config.get("4688"):
            self.new_proc_file = open(os.path.join(self.dir_out, "4688.json"), 'a')

        if self.config.get("task_scheduler"):
            self.task_scheduler_file = open(os.path.join(self.dir_out, "task_scheduler.json"), 'a')

        if self.config.get("remote_rdp"):
            self.remote_rdp_file = open(os.path.join(self.dir_out, "rdp_remote.json"), 'a')

        if self.config.get("local_rdp"):
            self.local_rdp_file = open(os.path.join(self.dir_out, "rdp_local.json"), 'a')

        if self.config.get("bits"):
            self.bits_file = open(os.path.join(self.dir_out, "bits.json"), 'a')

        if self.config.get("service"):
            self.service_file = open(os.path.join(self.dir_out, "7045.json"), 'a')

        if self.config.get("powershell"):
            self.powershell_file = open(os.path.join(self.dir_out, "powershell.json"), 'a')

        if self.config.get("powershell_script"):
            self.powershell_script_file = open(os.path.join(self.dir_out, "powershell_script.json"), 'a')

        if self.config.get("wmi"):
            self.wmi_file = open(os.path.join(self.dir_out, "wmi.json"), 'a')

        # ----------------------------- Hives ------------------------------------------------

        if self.config.get("app_exp"):
            self.app_exp_file = open(os.path.join(self.dir_out, "application_experience.json"), 'a')

        if self.config.get("amcache"):
            self.amcache_res_file = open(os.path.join(self.dir_out, "amcache.json"), 'a')

        if self.config.get("app_compat"):
            self.app_compat_res_file = open(os.path.join(self.dir_out, "app_compat.json"), 'a')

        if self.config.get("sam"):
            self.sam_res_file = open(os.path.join(self.dir_out, "sam.json"), 'a')

        if self.config.get("user_assist"):
            self.user_assist_file = open(os.path.join(self.dir_out, "userassist.json"), 'a')

        if self.config.get("mru"):
            self.mru_res_file = open(os.path.join(self.dir_out, "shellBags.json"), 'a')

        if self.config.get("srum"):
            self.srum_res_file = open(os.path.join(self.dir_out, "srum.json"), 'a')

        if self.config.get("run"):
            self.run_res_file = open(os.path.join(self.dir_out, "run.json"), 'a')

        # ----------------------------- Other ------------------------------------------------

        if self.config.get("ff_history"):
            self.ff_history_res_file = open(os.path.join(self.dir_out, "firefox_history.json"), 'a')

        if self.config.get("prefetch"):
            self.prefetch_res_file = open(os.path.join(self.dir_out, "prefetch.json"), 'a')

        if self.config.get("lnk"):
            self.lnk_res_file = open(os.path.join(self.dir_out, "lnk.json"), 'a')

    def close_files(self):
        self.logon_res_file.close()
        self.logon_failed_file.close()
        self.logon_spe_file.close()
        self.new_proc_file.close()
        self.logon_exp_file.close()
        self.task_scheduler_file.close()
        self.remote_rdp_file.close()
        self.local_rdp_file.close()
        self.bits_file.close()
        self.service_file.close()
        self.powershell_file.close()
        self.powershell_script_file.close()
        self.wmi_file.close()
        self.app_exp_file.close()

        self.amcache_res_file.close()
        self.app_compat_res_file.close()
        self.sam_res_file.close()
        self.user_assist_file.close()
        self.srum_res_file.close()
        self.run_res_file.close()

        self.ff_history_res_file.close()

        self.prefetch_res_file.close()
        self.lnk_res_file.close()

    def parse_timeline(self, path_to_tl):
        try:
            with open(path_to_tl) as timeline:
                for line in timeline:
                    d_line = json.loads(line)
                    type_artefact = self.identify_type_artefact_by_parser(d_line)
                    if type_artefact:
                        self.assign_parser(d_line, type_artefact)
            self.close_files()

        except Exception as ex:
            print("error with parsing")
            print("error is {}".format(traceback.format_exc()))
            self.close_files()

    #  -------------------------------------------------------------  Logs ---------------------------------------------
    #  -----------------------------------------------------------------------------------------------------------------

    def parse_logs(self, line):
        log_type = self.identify_artefact_by_source_name(line)
        if log_type == "security":
            self.parse_security_evtx(line)
        if log_type == "taskScheduler":
            self.parse_task_scheduler(line)
        if log_type == "bits":
            self.parse_bits(line)
        if log_type == "system":
            self.parse_system_evtx(line)
        if log_type == "rdp_local":
            self.parse_rdp(line)
        if log_type == "powershell":
            self.parse_powershell(line)
        if log_type == "wmi":
            self.parse_wmi(line)
        if log_type == "application_experience":
            self.parse_app_experience(line)

    #  ----------------------------------------  Wmi ---------------------------------------------
    def parse_wmi(self, event):
        event_code = event.get("event_identifier")
        if str(event_code) in ["5860", "5861"]:
            self.parse_wmi_evtx_from_xml(event)
        if str(event_code) in ["5858"]:
            self.parse_wmi_failure_from_xml(event)

    def parse_wmi_evtx_from_xml(self, event):
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {})

        operation_name = list(event_data.keys())[0]
        op_dict = event_data.get(operation_name, {})
        namespace = op_dict.get("NamespaceName", "-")
        user = op_dict.get("User", "-")
        cause = op_dict.get("PossibleCause", "-").replace("\n", "")
        query = op_dict.get("Query", "-").replace("\n", "")
        consumer = op_dict.get("CONSUMER", "-")
        res = "{}|{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, operation_name, user, namespace,
                                                  consumer, cause, query)

        self.wmi_file.write(res)
        self.wmi_file.write('\n')

    def parse_wmi_failure_from_xml(self, event):
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {})

        operation_name = list(event_data.keys())[0]
        op_dict = event_data.get(operation_name, {})
        namespace = op_dict.get("NamespaceName", "-")
        user = op_dict.get("User", "-")
        cause = op_dict.get("PossibleCause", "-").replace("\n", "")
        query = op_dict.get("Operation", "-").replace("\n", "")
        consumer = op_dict.get("CONSUMER", "-")

        res = "{}|{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, operation_name, user, namespace,
                                                  consumer, cause, query)

        self.wmi_file.write(res)
        self.wmi_file.write('\n')

    #  ----------------------------------------  RDP ---------------------------------------------
    def parse_rdp(self, event):
        event_code = event.get("event_identifier")
        if str(event_code) in ["1149"]:
            self.parse_rdp_remote_evtx_from_xml(event)
        if str(event_code) in ["21", "24", "25", "39", "40"]:
            self.parse_rdp_local_evtx_from_xml(event)

    def parse_rdp_remote_evtx_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {}).get("EventXML", {})

        event_code = event.get("event_identifier")
        user_name = event_data.get("Param1", "-")
        ip_addr = event_data.get("Param3", "-")

        res = "{}|{}|{}|InitConnexion|{}|{}".format(ts_date, ts_time, event_code, user_name, ip_addr)
        self.remote_rdp_file.write(res)
        self.remote_rdp_file.write('\n')

    def parse_rdp_local_evtx_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {}).get("EventXML", [])
        event_code = str(event.get("event_identifier"))
        user_name = event_data.get("User", "-")
        ip_addr = event_data.get("Adress", "-")
        session_id = event_data.get("SessionID", "-")
        source = event_data.get("Source", '-')
        reason_n = event_data.get("Reason", "-")
        target_session = event_data.get("", "-")

        if event_code == "21":
            reason = "AuthSuccess"
        elif event_code == "24":
            reason = "UserDisconnected"
        elif event_code == "25":
            reason = "UserReconnected"
        elif event_code == "39":
            reason = "UserHasBeenDisconnected"
        elif event_code == "40":
            reason = "UserHasBeenDisconnected"
        else:
            reason = "-"

        res = "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, user_name, ip_addr,
                                                     session_id, source, target_session, reason_n, reason)
        self.local_rdp_file.write(res)
        self.local_rdp_file.write('\n')

    #  ----------------------------------------  Bits ---------------------------------------------

    def parse_bits(self, event):
        event_code = event.get("event_identifier")
        if str(event_code) in ["3", "4", "59", "60", "61"]:
            self.parse_bits_evtx_from_xml(event)

    def parse_bits_evtx_from_xml(self, event):
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        user = "-"
        id = "-"
        job_owner = "-"
        job_id = "-"
        job_title = "-"
        bytes_total = "-"
        bytes_transferred = "-"
        file_count = "-"
        file_length = "-"
        file_time = "-"
        name = "-"
        url = "-"
        process_path = "-"

        for data in event_data:
            if data.get("@Name", "") == "User":
                user = data.get("#text", "-")

            elif data.get("@Name", "") == "Id":
                id = data.get("#text", "-")

            elif data.get("@Name", "") == "jobOwner":
                job_owner = data.get("#text", "-")

            elif data.get("@Name", "") == "jobId":
                job_id = data.get("#text", "-")

            elif data.get("@Name", "") == "jobTitle":
                job_title = data.get("#text", "-")

            elif data.get("@Name", "") == "bytesTotal":
                bytes_total = data.get("#text", "-")

            elif data.get("@Name", "") == "bytesTransferred":
                bytes_transferred = data.get("#text", "-")

            elif data.get("@Name", "") == "fileCount":
                file_count = data.get("#text", "-")

            elif data.get("@Name", "") == "fileLength":
                file_length = data.get("#text", "-")

            elif data.get("@Name", "") == "fileTime":
                file_time = data.get("#text", "-")

            elif data.get("@Name", "") == "name":
                name = data.get("#text", "-")

            elif data.get("@Name", "") == "url":
                url = data.get("#text", "-")

            elif data.get("@Name", "") == "processPath":
                process_path = data.get("#text", "-")

        res = "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|".format(ts_date, ts_time, event_code, id, job_id,
                                                                        job_title, job_owner, user, bytes_total,
                                                                        bytes_transferred, file_count, file_length,
                                                                        file_time, name, url, process_path)

        self.bits_file.write(res)
        self.bits_file.write('\n')

    #  ----------------------------------------  Security ---------------------------------------------

    def parse_security_evtx(self, event):

        event_code = event.get("event_identifier")
        if event_code == 4624:
            self.parse_logon_from_xml(event)

        if event_code == 4625:
            self.parse_failed_logon_from_xml(event)

        if event_code == 4672:
            self.parse_spe_logon_from_xml(event)

        if event_code == 4648:
            self.parse_logon_exp_from_xml(event)

        if event_code == 4688:
            self.parse_new_proc_from_xml(event)

    def parse_logon_from_xml(self, event):
        event_code = "4624"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, subject_user_name, target_user_name,
                                               ip_address, ip_port, logon_type)
        self.logon_res_file.write(res)
        self.logon_res_file.write('\n')

    def parse_failed_logon_from_xml(self, event):
        event_code = "4625"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, subject_user_name, target_user_name,
                                               ip_address, ip_port, logon_type)
        self.logon_failed_file.write(res)
        self.logon_failed_file.write('\n')

    def parse_spe_logon_from_xml(self, event):
        event_code = "4672"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, subject_user_name, target_user_name,
                                               ip_address, ip_port, logon_type)
        self.logon_spe_file.write(res)
        self.logon_spe_file.write('\n')

    def parse_logon_exp_from_xml(self, event):
        event_code = "4648"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, subject_user_name, target_user_name,
                                               ip_address, ip_port, logon_type)
        self.logon_exp_file.write(res)
        self.logon_exp_file.write('\n')

    def parse_new_proc_from_xml(self, event):
        event_code = "4688"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        cmd_line = "-"
        new_proc_name = "-"
        parent_proc_name = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "CommandLine":
                cmd_line = data.get("#text", "-")
            elif data.get("@Name", "") == "NewProcessName":
                new_proc_name = data.get("#text", "-")
            elif data.get("@Name", "") == "ParentProcessName":
                parent_proc_name = data.get("#text", "-")

        res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, subject_user_name, target_user_name,
                                               cmd_line, new_proc_name, parent_proc_name)
        self.new_proc_file.write(res)
        self.new_proc_file.write('\n')

    #  ----------------------------------------  System ---------------------------------------------
    def parse_system_evtx(self, event):
        event_code = event.get("event_identifier")
        if event_code == 7045:
            self.parse_service_from_xml(event)

    def parse_service_from_xml(self, event):

        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        account_name = "-"
        img_path = "-"
        service_name = "-"
        start_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "AccountName":
                account_name = data.get("#text", "-")

            elif data.get("@Name", "") == "ImagePath":
                img_path = data.get("#text", "-")

            elif data.get("@Name", "") == "ServiceName":
                service_name = data.get("#text", "-")

            elif data.get("@Name", "") == "StartType":
                start_type = data.get("#text", "-")

        res = "{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, account_name, img_path, service_name, start_type)

        self.service_file.write(res)
        self.service_file.write('\n')

    #  ----------------------------------------  Tasks ---------------------------------------------
    def parse_task_scheduler(self, event):
        event_code = event.get("event_identifier")
        if str(event_code) in ["106", "107", "140", "141", "200", "201"]:
            self.parse_task_scheduler_from_xml(event)
        if str(event_code) in ["4698", "4702"]:
            pass

    def parse_task_scheduler_from_xml(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        event_code = event.get("event_identifier")
        name = "-"
        task_name = "-"
        instance_id = "-"
        action_name = "-"
        result_code = "-"
        user_name = "-"
        user_context = "-"

        for data in event_data:
            if data.get("@Name", "") == "Name":
                name = data.get("#text", "-")
            elif data.get("@Name", "") == "TaskName":
                task_name = data.get("#text", "-")
            elif data.get("@Name", "") == "InstanceId":
                instance_id = data.get("#text", "-")
            elif data.get("@Name", "") == "ActionName":
                action_name = data.get("#text", "-")
            elif data.get("@Name", "") == "ResultCode":
                result_code = data.get("#text", "-")
            elif data.get("@Name", "") == "UserName":
                user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "UserContext":
                user_context = data.get("#text", "-")

        res = "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, name, task_name,
                                                     instance_id, action_name, result_code, user_name, user_context)
        self.task_scheduler_file.write(res)
        self.task_scheduler_file.write('\n')

        '''
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {})
        event_code = event.get("event_identifier")

        name = event_data.get("Name", "-")
        task_name = event_data.get("TaskName", "-")
        instance_id = event_data.get("InstanceId", "-")
        action_name = event_data.get("ActionName", "-")
        result_code = event_data.get("ResultCode", "-")
        user_name = event_data.get("UserName", "-")
        user_context = event_data.get("UserContext", "-")

        res = "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, name, task_name,
                                                     instance_id, action_name, result_code, user_name, user_context)
        self.task_scheduler_file.write(res)
        self.task_scheduler_file.write('\n')

        '''

    #  ----------------------------------------  PowerShell ---------------------------------------------
    def parse_powershell(self, event):
        event_code = event.get("event_identifier")
        if str(event_code) in ["4104", "4105", "4106"]:
            self.parse_powershell_script_from_xml(event)
        if str(event_code) in ["400", "600"]:
            self.parse_powershell_cmd_from_xml(event)

    def parse_powershell_script_from_xml(self, event):
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        path_to_script = "-"
        script_block_text = "-"

        for data in event_data:
            if data.get("@Name", "") == "Path":
                path_to_script = data.get("#text", "-")

            elif data.get("@Name", "") == "ScriptBlockText":
                script_block_text = data.get("#text", "-")

        res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, path_to_script, script_block_text)

        self.powershell_script_file.write(res)
        self.powershell_script_file.write('\n')

    def parse_powershell_cmd_from_xml(self, event):
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])
        cmdu = "-"

        for line in event_data:
            if "HostApplication=" in line:
                l2 = line.split("\n")
                for i in l2:
                    if "HostApplication" in i:
                        cmdu = i.split("HostApplication=")[1].replace("\n", " ").replace("\t", "").replace("\r", "")

        res = "{}|{}|{}|{}".format(ts_date, ts_time, event_code, cmdu)

        self.powershell_file.write(res)
        self.powershell_file.write('\n')

    #  ----------------------------------------  App Experience ---------------------------------------------
    def parse_app_experience(self, event):
        event_code = event.get("event_identifier")
        if str(event_code) in ["500", "505", "17"]:
            self.parse_app_experience_from_xml(event)

    def parse_app_experience_from_xml(self, event):
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)

        fix_name = evt_as_json.get("Event", {}).get("UserData", {}).get("CompatibilityFixEvent", {}).get("FixName")
        exe_path = evt_as_json.get("Event", {}).get("UserData", {}).get("CompatibilityFixEvent", {}).get("ExePath")

        res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, fix_name, exe_path)

        self.app_exp_file.write(res)
        self.app_exp_file.write('\n')

    #  -------------------------------------------------------------  Hives --------------------------------------------
    #  -----------------------------------------------------------------------------------------------------------------

    def parse_hives(self, line):
        hive_type = self.identify_artefact_by_parser_name(line)
        if hive_type == "amcache":
            self.parse_amcache(line)
        if hive_type == "appCompat":
            self.parse_app_compat_cache(line)
        if hive_type == "sam":
            self.parse_sam(line)
        if hive_type == "userassist":
            self.parse_user_assist(line)
        if hive_type == "mru":
            self.parse_mru(line)
        if hive_type == "run":
            self.parse_run(line)

    def parse_amcache(self, event):
        full_path = event.get("full_path", "-")
        if full_path != "-":
            name = full_path.split("\\")[-1]
            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
            identifier = event.get("program_identifier", "-")
            sha256_hash = event.get("sha256_hash", "-")
            #res = "{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, name, identifier, sha256_hash, full_path)
            res = "{}|{}|{}|{}".format(ts_date, ts_time, name, identifier)
            self.amcache_res_file.write(res)
            self.amcache_res_file.write('\n')

    def parse_app_compat_cache(self, event):
        full_path = event.get("path", "-")
        if full_path != "-":
            name = full_path.split("\\")[-1]
            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
            sha256_hash = event.get("sha256_hash", "-")
            res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, name, sha256_hash, full_path)
            self.app_compat_res_file.write(res)
            self.app_compat_res_file.write('\n')

    def parse_sam(self, event):
        user_name = event.get("username", "-")
        login_count = event.get("login_count", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        res = "{}|{}|{}|{}".format(ts_date, ts_time, user_name, login_count)

        self.sam_res_file.write(res)
        self.sam_res_file.write('\n')

    def parse_user_assist(self, event):
        value_name = event.get("value_name", "-")
        application_focus_count = event.get("application_focus_count", "-")
        application_focus_duration = event.get("application_focus_duration", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, value_name, application_focus_count, application_focus_duration)

        self.user_assist_file.write(res)
        self.user_assist_file.write('\n')

    def parse_mru(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if event.get("parser") == "winreg/bagmru/shell_items":
            shell_item_path = event.get("shell_item_path", "-")
            name = event.get("name", "-")
            res = "{}|{}|{}|{}".format(ts_date, ts_time, name, shell_item_path)
            self.mru_res_file.write(res)
            self.mru_res_file.write('\n')

        elif event.get("entries"):
            entries = event.get("entries")
            l_entries = entries.split("Index:")
            for entrie in l_entries:
                header = r'( \d{1,9} \[MRU Value \d{1,9}\]: Shell item path:)|(<UNKNOWN: .*?>)|((\d|[a-z]){1,9} \[MRU Value .{1,9}\]:)'
                cleaned = re.sub(header, '', entrie).strip()
                if cleaned:
                    res = "{}|{}|-|{}".format(ts_date, ts_time, cleaned)
                    self.mru_res_file.write(res)
                    self.mru_res_file.write('\n')

    def parse_run(self, event):
        entries = event.get("entries", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if entries:
            for entrie in entries:
                res = "{}|{}|{}".format(ts_date, ts_time, entrie)
                self.run_res_file.write(res)
                self.run_res_file.write('\n')

    #  -------------------------------------------------------------  DB -----------------------------------------------
    #  -----------------------------------------------------------------------------------------------------------------

    def parse_db(self, line):
        db_type = self.identify_artefact_by_parser_name(line)
        if db_type == "ff_history":
            self.parse_ff_history(line)
        if db_type == "ie_history":
            pass
        if db_type == "srum":
            self.parse_srum(line)

    def parse_srum(self, event):
            description = event.get("message", "-")

            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

            res = "{}|{}|{}".format(ts_date, ts_time, description)

            self.srum_res_file.write(res)
            self.srum_res_file.write('\n')

    def parse_ff_history(self, event):

            url = event.get("url", "-")
            visit_count = event.get("visit_count", "-")
            visit_type = event.get("visit_type", "-")
            is_typed = event.get("typed", "-")
            from_visit = event.get("from_visit", "-")

            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

            res = "{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, url, visit_count, visit_type, is_typed, from_visit)

            self.ff_history_res_file.write(res)
            self.ff_history_res_file.write('\n')

    #  ------------------------------------------------------  Win Files -----------------------------------------------
    #  -----------------------------------------------------------------------------------------------------------------

    def parse_win_file(self, line):
        file_type = self.identify_artefact_by_parser_name(line)
        if file_type == "prefetch":
            self.parse_prefetch(line)
        if file_type == "lnk":
            self.parse_lnk(line)

    def parse_prefetch(self, event):

        run_count = event.get("run_count", "-")
        path_hints = event.get("path_hints", "-")
        executable = event.get("executable", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, executable, path_hints, run_count)

        self.prefetch_res_file.write(res)
        self.prefetch_res_file.write('\n')

    def parse_lnk(self, event):
        description = event.get("description", "-")
        working_directory = event.get("working_directory", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if description != "-" and working_directory != "-":
            res = "{}|{}|{}|{}".format(ts_date, ts_time, description, working_directory)
            self.lnk_res_file.write(res)
            self.lnk_res_file.write('\n')


def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Solution to parse a json plaso timeline'))

    argument_parser.add_argument('-t', '--timeline', action="store",
                                 required=True, dest="timeline", default=False,
                                 help="path to the timeline , must be json timeline")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")

    argument_parser.add_argument("-c", "--casename", action="store",
                                 required=False, dest="case_name", default=None,
                                 help="name of the case u working on")

    argument_parser.add_argument("-s", "--separator", action="store",
                                 required=False, dest="separator", default="|",
                                 help="separator that will be used on csv files")

    argument_parser.add_argument("--type", action="store",
                                 required=False, dest="type_output", default="csv",
                                 choices=["csv", "json"], metavar="csv or json",
                                 help="type of the output file format : csv or json. Default is csv")

    argument_parser.add_argument("--config", action="store",
                                 required=False, dest="config_file", default=None,
                                 help="path to the json config file to be used")

    return argument_parser


if __name__ == '__main__':
    parser = parse_args()
    args = parser.parse_args()

    start_time = time.time()

    mp = MaximumPlasoParser(args.output_dir, args.type_output, args.separator, args.case_name, args.config_file)
    mp.parse_timeline(args.timeline)

    print("Finished in {} secondes".format(time.time() - start_time))

'''
d_parser = {
parser": "custom_destinations/lnk",
parser": "custom_destinations/lnk/shell_items",
parser": "esedb/msie_webcache",
parser": "esedb/srum",
parser": "filestat",
parser": "lnk",
parser": "lnk/shell_items",
parser": "mft",
parser": "olecf/olecf_automatic_destinations",
parser": "olecf/olecf_automatic_destinations/lnk",
parser": "olecf/olecf_automatic_destinations/lnk/shell_items",
parser": "olecf/olecf_default",
parser": "pe",
parser": "prefetch",
parser": "sqlite/firefox_history",
parser": "sqlite/windows_timeline",
parser": "text/setupapi",
parser": "utmp",
parser": "winevtx",
parser": "winreg/amcache",
parser": "winreg/appcompatcache",
parser": "winreg/bagmru",
parser": "winreg/bagmru/shell_items",
parser": "winreg/bam",
parser": "winreg/explorer_mountpoints2",
parser": "winreg/explorer_programscache",
parser": "winreg/mrulistex_shell_item_list",
parser": "winreg/mrulistex_shell_item_list/shell_items",
parser": "winreg/mrulistex_string",
parser": "winreg/mrulistex_string_and_shell_item",
parser": "winreg/mrulistex_string_and_shell_item_list",
parser": "winreg/mrulistex_string_and_shell_item_list/shell_items",
parser": "winreg/mrulist_string",
parser": "winreg/msie_zone",
parser": "winreg/networks",
parser": "winreg/userassist",
parser": "winreg/windows_boot_execute",
parser": "winreg/windows_run",
parser": "winreg/windows_sam_users",
parser": "winreg/windows_services",
parser": "winreg/windows_shutdown",
parser": "winreg/windows_task_cache",
parser": "winreg/windows_timezone",
parser": "winreg/windows_typed_urls",
parser": "winreg/windows_usb_devices",
parser": "winreg/windows_usbstor_devices",
parser": "winreg/windows_version",
parser": "winreg/winlogon",
parser": "winreg/winreg_default"
}
'''