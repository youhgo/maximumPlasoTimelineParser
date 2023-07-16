#!/usr/bin/python3
import json
import os
import traceback
import argparse
import re
from datetime import datetime
import xmltodict
import time
import pathlib
import csv
import string


class MaximumPlasoParserCsv:
    """
       Class MaximumPlasoParser
       MPP or MaximumPlasoParser is a python script that will parse a plaso - Log2Timeline json timeline file.
       The goal is to provide easily readable and straight forward files for the Forensic analyst.
       MPP will create a file for each artefact.
       Attributes :
       None
    """

    def __init__(self, dir_out, output_type="csv", separator="|", case_name=None, config_file=None) -> None:
        """
        Constructor for the MaximumPlasoParser Class

        :param dir_out: (str) directory where the results file will be written
        :param output_type: (str) output format, can be csv or json
        :param separator: (str) separator for csv output file
        :param case_name:  (str) name that will be set into json result files (for practical purpose with elk)
        :param config_file: (str) full path to a json file containing a configuration
        """

        self.dir_out = dir_out
        self.output_type = output_type
        self.separator = separator
        self.case_name = case_name
        self.workstation_name = "-"
        if config_file:
            self.config = self.read_json_config(config_file)
        else:
            self.config = {
                "4624": 1,
                "4625": 1,
                "4672": 1,
                "4648": 1,
                "4688": 1,
                "7045": 1,
                "taskScheduler": 1,
                "remote_rdp": 0,
                "local_rdp": 0,
                "bits": 0,
                "powershell": 0,
                "powershell_script": 0,
                "wmi": 0,
                "application_experience": 0,
                "amcache": 0,
                "app_compat": 0,
                "sam": 0,
                "run": 1,
                "user_assist": 0,
                "ff_history": 1,
                "srum": 1,
                "mru": 0,
                "prefetch": 1,
                "lnk": 1,
                "mft": 1
            }

        self.d_regex_artefact_by_source = {
            "security": re.compile(r'Microsoft-Windows-Security-Auditing'),
            "service": re.compile(r'Service Control Manager'),
            "taskScheduler": re.compile(r'Microsoft-Windows-TaskScheduler'),
            "bits": re.compile(r'Microsoft-Windows-Bits-Client'),
            "rdp_local": re.compile(r'Microsoft-Windows-TerminalServices-LocalSessionManager'),
            "powershell": re.compile(r'(Microsoft-Windows-PowerShell)|(PowerShell)'),
            "wmi": re.compile(r'Microsoft-Windows-WMI-Activity'),
            "application_experience": re.compile(r'Microsoft-Windows-Application-Experience'),
            "sam": re.compile(r'windows_sam_users'),
            "amcache": re.compile(r'Amcache Registry'),
            "app_compat": re.compile(r'AppCompatCache Registry'),
            "run": re.compile(r'windows_run'),
            "user_assist": re.compile(r'userassist'),
            "mru": re.compile(r'(bagmru)|(mru)'),
            "ff_history": re.compile(r'firefox_history'),
            "prefetch": re.compile(r'prefetch'),
            "lnk": re.compile(r'lnk'),
            "srum": re.compile(r'srum'),
            "mft": re.compile(r'(usnjrnl)|(mft)|(filestat)')
        }

        self.d_regex_global_type_artefact = {
            "evtx": re.compile(r'winevtx'),
            "hive": re.compile(r'winreg'),
            "db": re.compile(r'(sqlite)|(esedb)'),
            "winFile": re.compile(r'(lnk)|(text)|(prefetch)'),
            "mft": re.compile(r'(usnjrnl)|(mft)|(filestat)')
        }

        self.d_regex_evtx = {
            "event": re.compile(r'(\[(\d{1,6}) \/)'),
            "msg_str": re.compile(r'Message string:.*'),
            "ip_addr": re.compile(r'(Source Network Address:(.*?)\\n)'),
            "port": re.compile(r'(Source Port:(.*?)\\n)'),
            "account_name": re.compile(r'(\\nAccount Name:(.*?)\\n)'),
            "timestamp": re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),
            "logon_type": re.compile(r'(Logon Type:(\d)?\\n)'),
            "new_proc_name": re.compile(r'(\\nNew Process Name:(.*?)\\n)'),
            "service_name": re.compile(r'(\\nService Name:(.*?)\\n)'),
            "service_file_name": re.compile(r'(\\nService File Name:(.*?)\\n)'),
            "start_type": re.compile(r'(\\nService Start Type:(.*?)\\n)'),
            "service_account": re.compile(r'(\\nService Account:(.*?),)'),
            "strings": re.compile(r'Strings: \[(.*?)\]')
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
        self.lnk_res_file = ""
        self.mft_res_file = ""

        if self.output_type == "csv":
            self.initialise_csv_files()
        elif self.output_type == "json":
            self.initialise_json_files()

    @staticmethod
    def read_json_config(path_to_config):
        """
        Function to read and load a json file into a dict
        :param path_to_config: (str) full path to a json file
        :return: (dict) dict containing the content of the json file
        """
        with open(path_to_config, 'r') as config:
            return json.load(config)

    @staticmethod
    def convert_epoch_to_date(epoch_time):
        """
        Function to convert an epoch time (nanoseconds) into date and time.
        Split into 2 variable date and time
        :param epoch_time: (int) epoch time to be converted
        :return:
        (str) date in format %Y-%m-%d
        (str) time in format %H:%M:%S
        """
        dt = datetime.fromtimestamp(epoch_time / 1000000).strftime('%Y-%m-%dT%H:%M:%S')
        l_dt = dt.split("T")
        return l_dt[0], l_dt[1]

    def identify_artefact_by_source_name(self, line):
        """
        Function to indentify an artefact type depending on the source type of the file that was parsed
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the source name
        """
        for key, value in self.d_regex_artefact_by_source.items():
            if re.search(value, line):
                return key

    def identify_artefact_type(self, line):
        """
        Function to indentify an artefact type depending on the source type of the file that was parsed
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the source name
        """
        for key, value in self.d_regex_global_type_artefact.items():
            if re.search(value, line.split(',')[5]):
                return key

    def initialise_csv_files(self):
        """
        Function that will initialise all csv result file.
        It will open a stream to all results file and write header into it.
        Stream are keeped open to avoid opening and closing multiple file every new line of the timeline
        :return: None
        """

        if self.config.get("4624", 0):
            l_res_4624_header = ["Date", "time", "event_code", "logon_type", "subject_user_name", "target_user_name",
                                 "ip_address", "ip_port", "workstation_name"]

            self.logon_res_file = open(os.path.join(self.dir_out, "4624.csv"), 'a')
            self.logon_res_file.write(self.separator.join(l_res_4624_header))
            self.logon_res_file.write("\n")

        if self.config.get("4625", 0):
            l_res_4625_header = ["Date", "time", "event_code", "logon_type", "subject_user_name", "target_user_name",
                                 "ip_address", "ip_port", "workstation_name"]
            self.logon_failed_file = open(os.path.join(self.dir_out, "4625.csv"), 'a')
            self.logon_failed_file.write(self.separator.join(l_res_4625_header))
            self.logon_failed_file.write("\n")

        if self.config.get("4672", 0):
            l_res_4672_header = ["Date", "time", "event_code", "logon_type", "subject_user_name", "target_user_name",
                                 "ip_address", "ip_port", "workstation_name"]
            self.logon_spe_file = open(os.path.join(self.dir_out, "4672.csv"), 'a')
            self.logon_spe_file.write(self.separator.join(l_res_4672_header))
            self.logon_spe_file.write("\n")

        if self.config.get("4648", 0):
            l_res_4648_header = ["Date", "time", "event_code", "logon_type", "subject_user_name", "target_user_name",
                                 "ip_address", "ip_port", "workstation_name"]
            self.logon_exp_file = open(os.path.join(self.dir_out, "4648.csv"), 'a')
            self.logon_exp_file.write(self.separator.join(l_res_4648_header))
            self.logon_exp_file.write("\n")

        if self.config.get("4688", 0):
            l_res_4688_header = ["Date", "time", "event_code", "new_process_name", "command_line",
                                 "parent_process_name",
                                 "subject_user_name", "target_user_name", "workstation_name"]
            self.new_proc_file = open(os.path.join(self.dir_out, "4688.csv"), 'a')
            self.new_proc_file.write(self.separator.join(l_res_4688_header))
            self.new_proc_file.write("\n")

        if self.config.get("taskScheduler", 0):
            l_task_scheduler_header = ["Date", "time", "event_code", "name", "task_name", "instance_id", "action_name",
                                       "result_code", "user_name", "user_context"]

            self.task_scheduler_file = open(os.path.join(self.dir_out, "task_scheduler.csv"), 'a')
            self.task_scheduler_file.write(self.separator.join(l_task_scheduler_header))
            self.task_scheduler_file.write("\n")

        if self.config.get("remote_rdp", 0):
            l_rdp_remote_header = ["date", "time", "event_code", "user_name", "ip_addr"]
            self.remote_rdp_file = open(os.path.join(self.dir_out, "rdp_remote.csv"), 'a')
            self.remote_rdp_file.write(self.separator.join(l_rdp_remote_header))
            self.remote_rdp_file.write("\n")

        if self.config.get("local_rdp", 0):
            l_rdp_local_header = ["date", "time", "event_code", "user_name", "ip_addr", "session_id", "source",
                                  "target_session", "reason_n", "reason"]
            self.local_rdp_file = open(os.path.join(self.dir_out, "rdp_local.csv"), 'a')
            self.local_rdp_file.write(self.separator.join(l_rdp_local_header))
            self.local_rdp_file.write("\n")

        if self.config.get("bits", 0):
            l_bits_header = ["date", "time", "event_code", "id", "job_id", "job_title", "job_owner", "user",
                             "bytes_total",
                             "bytes_transferred", "file_count", "file_length", "file_time", "name", "url",
                             "process_path"]
            self.bits_file = open(os.path.join(self.dir_out, "bits.csv"), 'a')
            self.bits_file.write(self.separator.join(l_bits_header))
            self.bits_file.write("\n")

        if self.config.get("7045", 0):
            l_7045_header = ["date", "time", "event_code", "account_name", "img_path", "service_name", "start_type"]
            self.service_file = open(os.path.join(self.dir_out, "7045.csv"), 'a')
            self.service_file.write(self.separator.join(l_7045_header))
            self.service_file.write("\n")

        if self.config.get("powershell", 0):
            l_powershell_header = ["date", "time", "event_code", "path_to_script", "script_block_text"]
            self.powershell_file = open(os.path.join(self.dir_out, "powershell.csv"), 'a')
            self.powershell_file.write(self.separator.join(l_powershell_header))
            self.powershell_file.write("\n")

        if self.config.get("powershell_script", 0):
            l_powershell_script_header = ["date", "time", "event_code", "cmd"]
            self.powershell_script_file = open(os.path.join(self.dir_out, "powershell_script.csv"), 'a')
            self.powershell_script_file.write(self.separator.join(l_powershell_script_header))
            self.powershell_script_file.write("\n")

        if self.config.get("wmi", 0):
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

        if self.config.get("mft"):
            l_res_mft_header = ["Date", "time", "type", "action", "filePath"]
            self.mft_res_file = open(os.path.join(self.dir_out, "mft.csv"), 'a')
            self.mft_res_file.write(self.separator.join(l_res_mft_header))
            self.mft_res_file.write("\n")

    def initialise_json_files(self):
        """
        Function that will initialise all json result file.
        It will open a stream to all results file.
        Stream are keeped open to avoid opening and closing multiple file every new line of the timeline
        :return: None
        """

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
        """
        Function to close all opened stream
        :return:
        """
        if self.logon_res_file:
            self.logon_res_file.close()
        if self.logon_failed_file:
            self.logon_failed_file.close()
        if self.logon_spe_file:
            self.logon_spe_file.close()
        if self.task_scheduler_file:
            self.task_scheduler_file.close()
        if self.remote_rdp_file:
            self.remote_rdp_file.close()
        if self.local_rdp_file:
            self.local_rdp_file.close()
        if self.bits_file:
            self.bits_file.close()
        if self.service_file:
            self.service_file.close()
        if self.powershell_file:
            self.powershell_file.close()
        if self.powershell_script_file:
            self.powershell_script_file.close()
        if self.wmi_file:
            self.wmi_file.close()
        if self.app_exp_file:
            self.app_exp_file.close()

        if self.amcache_res_file:
            self.amcache_res_file.close()
        if self.app_compat_res_file:
            self.app_compat_res_file.close()
        if self.sam_res_file:
            self.sam_res_file.close()
        if self.user_assist_file:
            self.user_assist_file.close()
        if self.srum_res_file:
            self.srum_res_file.close()
        if self.run_res_file:
            self.run_res_file.close()

        if self.ff_history_res_file:
            self.ff_history_res_file.close()
        if self.prefetch_res_file:
            self.prefetch_res_file.close()
        if self.lnk_res_file:
            self.lnk_res_file.close()
        if self.mft_res_file:
            self.mft_res_file.close()

    def parse_timeline(self, path_to_tl):
        """
        Main function to parse the plaso timeline
        :param path_to_tl: (str) full path to the timeline
        :return: None
        """
        try:
            with open(path_to_tl) as timeline:
                for line in timeline:
                    line_clean = line.replace("\\t", "")
                    self.assign_parser(line_clean)
            self.close_files()

        except Exception as ex:
            print("error with parsing")
            print("error is {}".format(traceback.format_exc()))
            self.close_files()

    #  -------------------------------------------------------------  Logs ---------------------------------------------
    #  -----------------------------------------------------------------------------------------------------------------

    def assign_parser(self, line):
        """
        Main function to parse log type artefacts
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        artefact_type = self.identify_artefact_type(line)
        if artefact_type == "evtx":
            self.parse_evtx(line)

        if artefact_type == "db":
            self.parse_db(line)

        if artefact_type == "hive":
            self.parse_hives(line)

        if artefact_type == "winfile":
            return
            self.parse_winfile(line)

        if artefact_type == "mft":
            self.parse_mft(line)

    def parse_winfile(self, line):
        artefact_subtype = self.identify_artefact_by_source_name(line)

        # -------- WinFiles ----------------
        if artefact_subtype == "prefetch":
            self.parse_prefetch(line)
        elif artefact_subtype == "lnk":
            self.parse_lnk(line)

    def parse_db(self, line):
        artefact_subtype = self.identify_artefact_by_source_name(line)
        # -------- DB ----------------
        if artefact_subtype == "ff_history":
            self.parse_ff_history(line)
        elif artefact_subtype == "ie_history":
            pass
        elif artefact_subtype == "srum":
            self.parse_srum(line)

    def parse_hives(self, line):
        artefact_subtype = self.identify_artefact_by_source_name(line)

        # -------- Hives ----------------
        if artefact_subtype == "amcache":
            return
            self.parse_amcache(line)
        elif artefact_subtype == "appCompat":
            return
            self.parse_app_compat_cache(line)
        elif artefact_subtype == "sam":
            return
            self.parse_sam(line)
        elif artefact_subtype == "userassist":
            return
            self.parse_user_assist(line)
        elif artefact_subtype == "mru":
            return
            self.parse_mru(line)
        elif artefact_subtype == "run":
            self.parse_run(line)

    def parse_evtx(self, line):
        artefact_subtype = self.identify_artefact_by_source_name(line)
        if not artefact_subtype:
            return
        # -------- Logs ----------------
        if artefact_subtype == "security":
            self.parse_security_evtx(line)
        elif artefact_subtype == "service":
            self.parse_service_evtx(line)
        elif artefact_subtype == "taskScheduler":
            self.parse_task_scheduler(line)
        elif artefact_subtype == "bits":
            self.parse_bits(line)
        elif artefact_subtype == "rdp_local":
            self.parse_rdp(line)
        elif artefact_subtype == "powershell":
            self.parse_powershell(line)
        elif artefact_subtype == "wmi":
            self.parse_wmi(line)
        elif artefact_subtype == "application_experience":
            self.parse_app_experience(line)

    #  ----------------------------------------  Wmi ---------------------------------------------
    def parse_wmi(self, event):
        """
        Main function to parse wmi type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        return
        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)
        if str(event_code) in ["5860", "5861"]:
            self.parse_wmi_evtx_from_xml(event)
        if str(event_code) in ["5858"]:
            self.parse_wmi_failure_from_xml(event)

    def parse_wmi_evtx_from_xml(self, event):
        """
        Function to parse wmi log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, operation_name, user, namespace,
                                                      consumer, cause, query)

            self.wmi_file.write(res)
        else:
            workstation_name = op_dict.get("computer_name", "-")
            res = {
                "case_name": self.case_name,
                "workstation": workstation_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "operation_name": operation_name,
                "user": user,
                "namespace": namespace,
                "consumer": consumer,
                "cause": cause,
                "query": query
            }
            json.dump(res, self.wmi_file)

        self.wmi_file.write('\n')

    def parse_wmi_failure_from_xml(self, event):
        """
        Function to parse wmi failure log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, operation_name, user, namespace,
                                                      consumer, cause, query)

            self.wmi_file.write(res)
        else:
            workstation_name = op_dict.get("computer_name", "-")
            res = {
                "case_name": self.case_name,
                "workstation": workstation_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "operation_name": operation_name,
                "user": user,
                "namespace": namespace,
                "consumer": consumer,
                "cause": cause,
                "query": query
            }
            json.dump(res, self.wmi_file)

        self.wmi_file.write('\n')

    #  ----------------------------------------  RDP ---------------------------------------------
    def parse_rdp(self, event):
        """
        Main function to parse rdp type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)
        if self.config.get("remote_rdp", ""):
            if str(event_code) in ["1149"]:
                self.parse_rdp_remote_evtx_from_xml(event)
        if self.config.get("local_rdp", ""):
            if str(event_code) in ["21", "24", "25", "39", "40"]:
                self.parse_rdp_local_evtx_from_xml(event)

    def parse_rdp_remote_evtx_from_xml(self, event):
        """
        Function to parse remote rdp log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {}).get("EventXML", {})

        event_code = event.get("event_identifier")
        user_name = event_data.get("Param1", "-")
        ip_addr = event_data.get("Param3", "-")

        if self.output_type == "csv":
            res = "{}|{}|{}|InitConnexion|{}|{}".format(ts_date, ts_time, event_code, user_name, ip_addr)
            self.remote_rdp_file.write(res)

        else:
            workstation_name = event.get("computer_name", "-")
            res = {
                "case_name": self.case_name,
                "workstation": workstation_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "user_name": user_name,
                "ip_address": ip_addr
            }
            json.dump(res, self.remote_rdp_file)

        self.remote_rdp_file.write('\n')

    def parse_rdp_local_evtx_from_xml(self, event):
        """
        Function to parse local rdp log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, user_name, ip_addr,
                                                         session_id, source, target_session, reason_n, reason)
            self.local_rdp_file.write(res)

        else:
            workstation_name = event.get("computer_name", "-")
            res = {
                "case_name": self.case_name,
                "workstation_name": workstation_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "user_name": user_name,
                "ip_address": ip_addr,
                "session_id": session_id,
                "source": source,
                "target_session": target_session,
                "reason_n": reason_n,
                "reason": reason
            }
            json.dump(res, self.local_rdp_file)

        self.local_rdp_file.write('\n')

    #  ----------------------------------------  Bits ---------------------------------------------

    def parse_bits(self, event):
        """
        Main function to parse bits type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        if not self.config.get("bits", ""):
            return
        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)
        if str(event_code) in ["3", "4", "59", "60", "61"]:
            self.parse_bits_evtx_from_xml(event)

    def parse_bits_evtx_from_xml(self, event):
        """
        Function to parse remote bits log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        user = "-"
        identifiant = "-"
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
                identifiant = data.get("#text", "-")

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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|".format(ts_date, ts_time, event_code, id, job_id,
                                                                            job_title, job_owner, user, bytes_total,
                                                                            bytes_transferred, file_count, file_length,
                                                                            file_time, name, url, process_path)
            self.bits_file.write(res)

        else:
            workstation_name = event.get("computer_name", "-")
            res = {
                "caseName": self.case_name,
                "workstation": workstation_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "identifiant": identifiant,
                "job_id": job_id,
                "job_title": job_title,
                "job_owner": job_owner,
                "user": bytes_total,
                "bytes_transferred": bytes_transferred,
                "file_count": file_count,
                "file_length": file_length,
                "file_time": file_time,
                "name": name,
                "url": url,
                "process_path": process_path
            }
            json.dump(res, self.bits_file)

        self.bits_file.write('\n')

    #  ----------------------------------------  Security ---------------------------------------------,

    def parse_security_evtx(self, event):
        """
        Main function to parse security type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)
        if not self.config.get(str(event_code), ""):
            return

        if event_code == "4624":
            self.parse_logon_with_regex(event)

        elif event_code == "4625":
            self.parse_failed_logon_with_regex(event)

        elif event_code == "4672":
            self.parse_spe_logon_with_regex(event)

        elif event_code == "4648":
            self.parse_logon_exp_with_regex(event)

        elif event_code == "4688":
            self.parse_new_proc_with_regex(event)

    def parse_logon_with_regex(self, event):
        """
        Function to parse logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (str) str containing one line of the plaso timeline,
        :return: None
        """

        event_code = "4624"
        ip_address = re.search(self.d_regex_evtx.get("ip_addr"), event).group(2)
        ip_port = re.search(self.d_regex_evtx.get("port"), event).group(2)
        target_user_name = re.findall(self.d_regex_evtx.get("account_name"), event)[1][1]
        logon_type = re.search(self.d_regex_evtx.get("logon_type"), event).group(2)
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), event).group().split('T')
        computer_name = re.search("(Computer Name: (.*? ))", event).group(2)

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], target_user_name, ip_address, ip_port,
                                             logon_type)
            self.logon_res_file.write(res)

        else:
            res = {
                "caseName": self.case_name,
                "workstation": computer_name,
                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                "eventCode": event_code,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type
            }
            json.dump(res, self.logon_res_file)

        self.logon_res_file.write('\n')

    def parse_failed_logon_with_regex(self, event):
        """
        Function to parse failed logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4625"
        ip_address = re.search(self.d_regex_evtx.get("ip_addr"), event).group(2)
        ip_port = re.search(self.d_regex_evtx.get("port"), event).group(2)
        target_user_name = re.findall(self.d_regex_evtx.get("account_name"), event)[1][1]
        logon_type = re.search(self.d_regex_evtx.get("logon_type"), event).group(2)
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), event).group().split('T')
        computer_name = re.search("(Computer Name: (.*? ))", event).group(2)

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], target_user_name, ip_address, ip_port,
                                             logon_type)
            self.logon_failed_file.write(res)

        else:
            res = {
                "caseName": self.case_name,
                "workstation": computer_name,
                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                "eventCode": event_code,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type
            }
            json.dump(res, self.logon_failed_file)

        self.logon_failed_file.write('\n')

    def parse_spe_logon_with_regex(self, event):
        """
        Function to parse special logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4672"
        account_name = re.findall(self.d_regex_evtx.get("account_name"), event)[0][1]
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), event).group().split('T')
        computer_name = re.search("(Computer Name: (.*? ))", event).group(2)

        if self.output_type == "csv":
            res = "{}|{}|{}|{}".format(timestamp[0], timestamp[1], event_code, account_name)
            self.logon_spe_file.write(res)

        else:
            res = {
                "caseName": self.case_name,
                "workstation": computer_name,
                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                "eventCode": event_code,
                "account_name": account_name,
            }
            json.dump(res, self.logon_spe_file)

        self.logon_spe_file.write('\n')

    def parse_logon_exp_with_regex(self, event):
        """
        Function to explicit logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        event_code = "4648"
        target_user_name = re.findall(self.d_regex_evtx.get("account_name"), event)[1][1]
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), event).group().split('T')
        computer_name = re.search("(Computer Name: (.*? ))", event).group(2)

        if self.output_type == "csv":
            res = "{}|{}|{}".format(timestamp[0], timestamp[1], target_user_name)
            self.logon_exp_file.write(res)

        else:
            res = {
                "caseName": self.case_name,
                "workstation": computer_name,
                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                "eventCode": event_code,
                "target_user_name": target_user_name
            }
            json.dump(res, self.logon_exp_file)

        self.logon_exp_file.write('\n')

    def parse_new_proc_with_regex(self, event):
        """
        Function to parse new process log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        event_code = "4688"
        account_name = re.findall(self.d_regex_evtx.get("account_name"), event)[0][1]
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), event).group().split('T')
        new_proc_name = re.search(self.d_regex_evtx.get("new_proc_name"), event).group(2).replace("S!", "")
        computer_name = re.search("(Computer Name: (.*? ))", event).group(2)

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], event_code, new_proc_name, account_name)
            self.new_proc_file.write(res)

        else:
            res = {
                "caseName": self.case_name,
                "workstation": computer_name,
                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                "eventCode": event_code,
                "new_proccess_name": new_proc_name,
                "account_name": account_name
            }

            json.dump(res, self.new_proc_file)

        self.new_proc_file.write('\n')

    #  ----------------------------------------  System ---------------------------------------------
    def parse_service_evtx(self, event):
        """
        Main function to parse system type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)
        if not self.config.get(str(event_code), ""):
            return
        if event_code == "7045":
            self.parse_service_with_regex(event)

    def parse_service_with_regex(self, event):
        """
        Function to parse service creation log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), event).group().split('T')
        service_name = re.search(self.d_regex_evtx.get("service_name"), event).group(2).strip()
        service_file_name = re.search(self.d_regex_evtx.get("service_file_name"), event).group(2).strip()
        start_type = re.search(self.d_regex_evtx.get("start_type"), event).group(2).strip()
        computer_name = re.search("(Computer Name: (.*? ))", event).group(2)
        service_account = re.search(self.d_regex_evtx.get("service_account"), event).group(2).replace(",", '').strip()

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], event_code, service_account, service_name,
                                                service_file_name, start_type)
            self.service_file.write(res)

        else:
            res = {
                "caseName": self.case_name,
                "workstation": computer_name,
                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                "eventCode": event_code,
                "service_name": service_name,
                "service_file_name": service_file_name,
                "service_account": service_account,
                "start_type": start_type
            }

            json.dump(res, self.service_file)

        self.service_file.write('\n')

    #  ----------------------------------------  Tasks ---------------------------------------------

    def parse_task_scheduler(self, event):
        """
        Main function to parse task scheduler type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)

        if not self.config.get("taskScheduler", ""):
            return
        if str(event_code) in ["106", "107", "140", "141"]:
            self.parse_task_scheduler_action_with_regex(event)
        elif str(event_code) in ["200", "201"]:
            self.parse_task_scheduler_launch_and_completion_with_regex(event)
        elif str(event_code) in ["4698", "4702"]:
            pass

    def parse_task_scheduler_action_with_regex(self, event):
        """
        Function to parse task scheduler log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), event).group().split('T')
        str_line = re.search(self.d_regex_evtx.get("strings"), event).groups()[0].replace("'", "").split("  ")
        computer_name = re.search("(Computer Name: (.*? ))", event).group(2)
        action = "-"
        if event_code == "106":
            action = "JOB_REGISTERED"
        if event_code == "107":
            action = "TIME_TRIGGER"
        if event_code == "140":
            action = "TASK_UPDATED"
        if event_code == "141":
            action = "TASK_DELETED"

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], event_code, action, str_line[1], str_line[0])
            self.task_scheduler_file.write(res)

        else:
            res = {
                "caseName": self.case_name,
                "workstation": computer_name,
                "timestamp": timestamp,
                "eventCode": event_code,
                "user_name": str_line[1],
                "task_name": str_line[0],
                "action": action
            }

            json.dump(res, self.task_scheduler_file)

        self.task_scheduler_file.write('\n')

    def parse_task_scheduler_launch_and_completion_with_regex(self, event):
        """
        Function to parse task scheduler log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), event).group().split('T')
        str_line = re.search(self.d_regex_evtx.get("strings"), event).groups()[0].replace("'", "").split("  ")
        computer_name = re.search("(Computer Name: (.*? ))", event).group(2)

        if event_code == "200":
            action = "ACTION_START"
            if self.output_type == "csv":
                res = "{}|{}|{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], event_code, action,
                                                    str_line[0], str_line[1], str_line[3])
                self.task_scheduler_file.write(res)

            else:
                res = {
                    "caseName": self.case_name,
                    "workstation": computer_name,
                    "timestamp": timestamp,
                    "eventCode": event_code,
                    "action": action,
                    "task_name": str_line[0],
                    "binary_path": str_line[1],
                    "reason": str_line[3]
                }

                json.dump(res, self.task_scheduler_file)
        if event_code == "201":

            action = "ACTION_SUCCESS"
            if self.output_type == "csv":
                res = "{}|{}|{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], event_code, action,
                                                    str_line[0], str_line[2], str_line[3])
                self.task_scheduler_file.write(res)

            else:
                res = {
                    "caseName": self.case_name,
                    "workstation": computer_name,
                    "timestamp": timestamp,
                    "eventCode": event_code,
                    "action": action,
                    "task_name": str_line[0],
                    "binary_path": str_line[2],
                    "reason": str_line[3]
                }

                json.dump(res, self.task_scheduler_file)

        self.task_scheduler_file.write('\n')

    #  ----------------------------------------  PowerShell ---------------------------------------------
    def parse_powershell(self, event):
        """
        Main function to parse powershell type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        return
        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)
        if self.config.get("powershell_script", ""):
            if str(event_code) in ["4104", "4105", "4106"]:
                self.parse_powershell_script_from_xml(event)
        elif self.config.get("powershell", ""):
            if str(event_code) in ["400", "600"]:
                self.parse_powershell_cmd_from_xml(event)

    def parse_powershell_script_from_xml(self, event):
        """
        Function to parse powershell script execution log type.
        It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, path_to_script, script_block_text)
            self.powershell_script_file.write(res)

        else:
            workstation_name = event.get("computer_name", "-")
            res = {
                "caseName": self.case_name,
                "workstation": workstation_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "path_to_script": path_to_script,
                "script_block_text": script_block_text
            }

            json.dump(res, self.powershell_script_file)

        self.powershell_script_file.write('\n')

    def parse_powershell_cmd_from_xml(self, event):
        """
        Function to parse powershell cmdu execution log type. It will parse and write results to the appropriate
        result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}".format(ts_date, ts_time, event_code, cmdu)
            self.powershell_file.write(res)

        else:
            workstation_name = event.get("computer_name", "-")
            res = {
                "caseName": self.case_name,
                "workstation": workstation_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "cmdu": cmdu
            }

            json.dump(res, self.powershell_file)

        self.powershell_file.write('\n')

    #  ----------------------------------------  App Experience ---------------------------------------------
    def parse_app_experience(self, event):
        """
        Main function to parse application experience type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        return
        event_code = re.search(r'(\[(\d{1,6}) \/)', event).group(2)
        if not self.config.get("hive", {}).get("type", {}).get("application_experience"):
            return
        if str(event_code) in ["500", "505", "17"]:
            self.parse_app_experience_from_xml(event)

    def parse_app_experience_from_xml(self, event):
        """
        Function to parse application experience log type.
        It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        return
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)

        fix_name = evt_as_json.get("Event", {}).get("UserData", {}).get("CompatibilityFixEvent", {}).get("FixName")
        exe_path = evt_as_json.get("Event", {}).get("UserData", {}).get("CompatibilityFixEvent", {}).get("ExePath")

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, fix_name, exe_path)
            self.app_exp_file.write(res)

        else:
            workstation_name = event.get("computer_name", "-")
            res = {
                "caseName": self.case_name,
                "workstation": workstation_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "fix_name": fix_name,
                "exe_path": exe_path
            }

            json.dump(res, self.app_exp_file)

        self.app_exp_file.write('\n')

    #  -------------------------------------------------------------  Hives --------------------------------------------
    #  -----------------------------------------------------------------------------------------------------------------

    def parse_amcache(self, event):
        """
        Function to parse amcache hive type.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        return
        full_path = "-"

        if full_path != "-":
            name = full_path.split("\\")[-1]
            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
            identifier = event.get("program_identifier", "-")
            sha256_hash = event.get("sha256_hash", "-")

            if self.output_type == "csv":
                res = "{}|{}|{}|{}".format(ts_date, ts_time, name, identifier)
                # res = "{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, name, identifier, sha256_hash, full_path)
                self.amcache_res_file.write(res)

            else:
                workstation_name = event.get("computer_name", "-")
                res = {
                    "caseName": self.case_name,
                    "workstation": workstation_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "name": name,
                    "identifier": identifier
                }
                json.dump(res, self.amcache_res_file)

            self.amcache_res_file.write('\n')

    def parse_app_compat_cache(self, event):
        """
        Function to parse app compat hive type.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        full_path = event.get("path", "-")
        if full_path != "-":
            name = full_path.split("\\")[-1]
            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
            sha256_hash = event.get("sha256_hash", "-")

            if self.output_type == "csv":
                res = "{}|{}|{}|{}".format(ts_date, ts_time, name, full_path)
                self.app_compat_res_file.write(res)

            else:
                workstation_name = event.get("computer_name", "-")
                res = {
                    "caseName": self.case_name,
                    "workstation": workstation_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "name": name,
                    "identifier": full_path
                }
                json.dump(res, self.app_compat_res_file)
            self.app_compat_res_file.write('\n')

    def parse_sam(self, event):
        """
        Function to parse sam hive type.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        user_name = event.get("username", "-")
        login_count = event.get("login_count", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type == "csv":
            res = "{}|{}|{}|{}".format(ts_date, ts_time, user_name, login_count)
            self.sam_res_file.write(res)

        else:
            workstation_name = event.get("computer_name", "-")
            res = {
                "caseName": self.case_name,
                "workstation": workstation_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "user_name": user_name,
                "login_count": login_count
            }
            json.dump(res, self.sam_res_file)
        self.sam_res_file.write('\n')

    def parse_user_assist(self, event):
        """
        Function to user assist artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        value_name = event.get("value_name", "-")
        application_focus_count = event.get("application_focus_count", "-")
        application_focus_duration = event.get("application_focus_duration", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, value_name, application_focus_count,
                                          application_focus_duration)
            self.user_assist_file.write(res)

        else:
            workstation_name = event.get("computer_name", "-")
            res = {
                "caseName": self.case_name,
                "workstation": workstation_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "value_name": value_name,
                "application_focus_count": application_focus_count,
                "application_focus_duration": application_focus_duration
            }
            json.dump(res, self.user_assist_file)
        self.user_assist_file.write('\n')

    def parse_mru(self, event):
        """
        Function to parse mru artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if event.get("parser") == "winreg/bagmru/shell_items":
            shell_item_path = event.get("shell_item_path", "-")
            name = event.get("name", "-")

            if self.output_type == "csv":
                res = "{}|{}|{}|{}".format(ts_date, ts_time, name, shell_item_path)
                self.mru_res_file.write(res)

            else:
                workstation_name = event.get("computer_name", "-")
                res = {
                    "caseName": self.case_name,
                    "workstation": workstation_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "name": name,
                    "shell_item_path": shell_item_path
                }
                json.dump(res, self.mru_res_file)
            self.mru_res_file.write('\n')

        elif event.get("entries"):
            entries = event.get("entries")
            l_entries = entries.split("Index:")
            for entrie in l_entries:
                header = r'( \d{1,9} \[MRU Value \d{1,9}\]: Shell item path:)|(<UNKNOWN: .*?>)|((\d|[a-z]){1,9} \[MRU Value .{1,9}\]:)'
                cleaned = re.sub(header, '', entrie).strip()
                if cleaned:
                    if self.output_type == "csv":
                        res = "{}|{}|-|{}".format(ts_date, ts_time, cleaned)
                        self.mru_res_file.write(res)
                    else:
                        workstation_name = event.get("computer_name", "-")
                        res = {
                            "caseName": self.case_name,
                            "workstation": workstation_name,
                            "timestamp": "{}T{}".format(ts_date, ts_time),
                            "mru_entrie": cleaned
                        }
                        json.dump(res, self.mru_res_file)
                    self.mru_res_file.write('\n')

    def parse_run(self, line):
        """
        Function to parse run/RunOnce reg key entries.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        l_col = line.split(",")
        parser = l_col[5]
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), l_col[0])
        if timestamp:
            timestamp = timestamp.group().split("T")

        if parser in ["winreg/windows_run"]:
            action = l_col[4]
            entries = re.search(r'Entries: \[(.*)\]', action)
            if entries:
                entries = entries.group(1).split("  ")
                for entrie in entries:
                    if entrie:
                        if self.output_type == "csv":
                            res = "{}|{}|{}".format(timestamp[0], timestamp[1], entrie)
                            self.run_res_file.write(res)
                        else:
                            res = {
                                "caseName": self.case_name,
                                "workstation": self.workstation_name,
                                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                                "run_entrie": entrie
                            }
                            json.dump(res, self.run_res_file)
                        self.run_res_file.write('\n')

    #  -------------------------------------------------------------  DB -----------------------------------------------
    #  -----------------------------------------------------------------------------------------------------------------

    def parse_srum(self, line):
        """
        Function to parse srum artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        l_col = line.split(",")
        parser = l_col[5]
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), l_col[0])
        if timestamp:
            timestamp = timestamp.group().split("T")

        if parser in ["esedb/srum"]:
            action = l_col[4]

            if self.output_type == "csv":
                res = "{}|{}|{}".format(timestamp[0], timestamp[1], action)
                self.srum_res_file.write(res)
            else:
                res = {
                    "caseName": self.case_name,
                    "workstation": self.workstation_name,
                    "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                    "description": action
                }
                json.dump(res, self.srum_res_file)
            self.srum_res_file.write('\n')

    def parse_ff_history(self, line):
        """
        Function to parse firefox history.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        l_col = line.split(",")
        parser = l_col[5]
        type_log = l_col[3]
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), l_col[0])
        if timestamp:
            timestamp = timestamp.group().split("T")

        if parser in ["sqlite/firefox_history"] and type_log == "Firefox History":
            type_action = l_col[1]
            run_count_regex = re.search(r'\[count: (\d{0,99})\]', l_col[4])
            uri = re.search(
                r'(https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*))',
                l_col[4])
            visited_from = re.search(
                r'visited from: (https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*))',
                l_col[4])

            if run_count_regex:
                run_count_regex = run_count_regex.group(1)
            if visited_from:
                visited_from = visited_from.group(1)
            if uri:
                uri = uri.group(1)
            else:
                return

            if self.output_type == "csv":
                res = "{}|{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], type_action, run_count_regex, uri,
                                                 visited_from)
                self.ff_history_res_file.write(res)
            else:
                res = {
                    "caseName": self.case_name,
                    "workstation": self.workstation_name,
                    "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                    "type_action": type_action,
                    "uri": uri,
                    "run_count": run_count_regex,
                    "visited_from": visited_from
                }
                json.dump(res, self.ff_history_res_file)
            self.ff_history_res_file.write('\n')

    #  ------------------------------------------------------  Win Files -----------------------------------------------
    #  -----------------------------------------------------------------------------------------------------------------

    def parse_prefetch(self, line):
        """
        Function to parse prefetch files.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        l_col = line.split(",")
        type_entrie = l_col[5]
        line_clean = line.replace("\\t", "")
        type_log = l_col[3]

        if type_entrie in ["prefetch"] and type_log == "WinPrefetch":
            run_count_regex = re.search(r'(run count (\d{1,99}))', l_col[4]).group(2)
            path_int_regex = re.search(r'(path hints: (.*?) )', l_col[4]).group(2)
            prefetch_name_regex = re.search(r'Prefetch (\[.*?\])', l_col[4]).group(1)
            timestamp = re.search(self.d_regex_evtx.get("timestamp"), line_clean).group().split('T')
            action = l_col[1]

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], action, prefetch_name_regex, run_count_regex,
                                             path_int_regex)
            self.prefetch_res_file.write(res)
        else:
            res = {
                "caseName": self.case_name,
                "workstation": self.workstation_name,
                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                "executable": prefetch_name_regex,
                "path_hints": path_int_regex,
                "run_count": run_count_regex
            }
            json.dump(res, self.prefetch_res_file)
        self.prefetch_res_file.write('\n')

    def parse_lnk(self, line):
        """
        Function to parse lnk type artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        l_col = line.split(",")
        type_entrie = l_col[5]
        line_clean = line.replace("\\t", "")
        type_log = l_col[3]
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), l_col[0])
        res = ""
        if timestamp:
            timestamp = timestamp.group().split("T")
        if type_entrie in ["lnk"] and type_log in ["Windows Shortcut"]:
            lnk_target = re.search(r' Link target: ([\w\s\d\(\)\.\<\>\%\\\{\}\-\:]+)', line_clean)
            local_path_regex = re.search(
                r'Local path: ((?:[a-zA-Z]\:|\\\\[\w\s\.]+\\[\w\s\.$]+)\\(?:[\w\s\.]+\\)*(\w+\.\w+))', line_clean)
            cmd_argument = re.search(r'(cmd arguments: (.*?) )', line_clean)
            description = re.search(r'\[.*?\]', l_col[4])
            env_path_regex = re.search(r'env location: ([\w\s\d\(\)\.\<\>\%\\\{\}\-]+)', line_clean)

            if self.output_type == "csv":
                if description:
                    description = description.group()
                if cmd_argument:
                    cmd_argument = cmd_argument.group(2)

                if lnk_target:
                    lnk_target = lnk_target.group(1)
                    res = "{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], lnk_target, cmd_argument, description)
                elif local_path_regex:
                    local_path_regex = local_path_regex.group(1)
                    res = "{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], local_path_regex, cmd_argument,
                                                  description)
                elif env_path_regex:
                    env_path_regex = env_path_regex.group(1)
                    res = "{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], env_path_regex, cmd_argument, description)
                else:
                    res = "{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], l_col[4], cmd_argument, description)
                self.lnk_res_file.write(res)
            else:
                if description:
                    description = description.group()
                if cmd_argument:
                    cmd_argument = cmd_argument.group(2)

                if lnk_target:
                    lnk_target = lnk_target.group(1)
                    res = {
                        "caseName": self.case_name,
                        "workstation": self.workstation_name,
                        "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                        "description": description,
                        "lnk_target": lnk_target,
                        "cmd_argument": cmd_argument
                    }
                elif local_path_regex:
                    local_path_regex = local_path_regex.group(1)
                    res = {
                        "caseName": self.case_name,
                        "workstation": self.workstation_name,
                        "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                        "description": description,
                        "lnk_target": local_path_regex,
                        "cmd_argument": cmd_argument
                    }
                elif env_path_regex:
                    env_path_regex = env_path_regex.group(1)
                    res = {
                        "caseName": self.case_name,
                        "workstation": self.workstation_name,
                        "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                        "description": description,
                        "lnk_target": env_path_regex,
                        "cmd_argument": cmd_argument
                    }
                else:
                    res = {
                        "caseName": self.case_name,
                        "workstation": self.workstation_name,
                        "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                        "description": description,
                        "lnk_target": l_col[4],
                        "cmd_argument": cmd_argument
                    }


                json.dump(res, self.lnk_res_file)
            self.lnk_res_file.write('\n')

    #  -------------------------------------------------------------  MFT --------------------------------------------
    #  -----------------------------------------------------------------------------------------------------------------

    def parse_mft(self, line):
        """
        Function to parse special logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        if not self.config.get("mft", ""):
            return

        l_col = line.split(",")
        type_entrie = l_col[5]
        if type_entrie in ["usnjrnl"]:
            self.parse_usnjrl(line)
        elif type_entrie in ["mft"]:
            self.parse_filemft(line)
        elif type_entrie in ["filestat"] and re.search("NTFS:", l_col[4]):
            self.parse_filestat(line)

    def parse_usnjrl(self, line):
        l_col = line.split(",")
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), l_col[0]).group().split('T')
        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], line.split(",")[2], l_col[1], l_col[4])
            self.mft_res_file.write(res)
        else:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                "workstation_name": self.workstation_name,
                "action_type": line.split(",")[2],
                "file_type": l_col[1],
                "path": l_col[4]
            }
            json.dump(res, self.mft_res_file)

        self.mft_res_file.write('\n')

    def parse_filemft(self, line):
        l_col = line.split(",")
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), l_col[0]).group().split('T')
        cleaned = re.sub(r"(OS:.*Path hints:)", "", l_col[4])

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], l_col[2], l_col[1], cleaned.strip())
            self.mft_res_file.write(res)

        else:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                "workstation_name": self.workstation_name,
                "action_type": l_col[1],
                "file_type": l_col[2],
                "path": cleaned.strip()
            }
            json.dump(res, self.mft_res_file)
        self.mft_res_file.write('\n')

    def parse_filestat(self, line):
        l_col = line.split(",")
        timestamp = re.search(self.d_regex_evtx.get("timestamp"), l_col[0]).group().split('T')

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}".format(timestamp[0], timestamp[1], l_col[2], l_col[1], l_col[6])
            self.mft_res_file.write(res)
        else:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(timestamp[0], timestamp[1]),
                "workstation_name": self.workstation_name,
                "action_type": l_col[1],
                "file_type": l_col[2],
                "path": l_col[6]
            }
            json.dump(res, self.mft_res_file)

        self.mft_res_file.write('\n')


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


def validate_json(timeline):
    with open(timeline, 'r') as tl:
        first_line = tl.readline()
        try:
            json.loads(first_line)
            return True
        except ValueError as err:
            return False


def validate_csv(timeline):
    try:
        with open(timeline, newline='') as csvfile:
            start = csvfile.read(4096)

            if not all([c in string.printable or c.isprintable() for c in start]):
                return False
            dialect = csv.Sniffer().sniff(start)
            return True
    except csv.Error:
        # Could not get a csv dialect -> probably not a csv.
        return False


# File appears not to be in CSV format; move along
def check_input(timeline):
    if validate_json(timeline):
        return "json"
    elif validate_csv(timeline):
        return "csv"
    else:
        print("Cannot read timeline correctly, are you sure that it is a valid csv or json ?")
        exit(1)


if __name__ == '__main__':

    parser = parse_args()
    args = parser.parse_args()
    start_time = time.time()

    #stype_input = check_input(args.timeline)
    print("started at {} ".format(time.time()))

    mp = MaximumPlasoParserCsv(args.output_dir, args.type_output, args.separator, args.case_name, args.config_file)
    mp.parse_timeline(args.timeline)

    print("Finished in {} secondes".format(time.time() - start_time))

    '''
    d_regex_4624 = {
        "taskScheduler": re.compile(r'Microsoft-Windows-TaskScheduler'),
        "event": re.compile(r"\[200"),
        "msg_str": re.compile(r'Message string:.*'),
        "ip_addr": re.compile(r'(Source Network Address:(.*?)\\n)'),
        "port": re.compile(r'(Source Port:(.*?)\\n)'),
        "account_name": re.compile(r'(\\nAccount Name:(.*?)\\n)'),
        "timestamp": re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),
        "logon_type": re.compile(r'(Logon Type:(\d)?\\n)'),
        "new_proc_name": re.compile(r'(\\nNew Process Name:(.*?)\\n)'),
        "service_name": re.compile(r'(\\nService Name:(.*?)\\n)'),
        "service_file_name": re.compile(r'(\\nService File Name:(.*?)\\n)'),
        "start_type": re.compile(r'(\\nService Start Type:(.*?)\\n)'),
        "strings": re.compile(r'Strings: \[(.*?)\]')
    }

    with open(args.timeline, "r") as tl:
        for line in tl:
            l_col = line.split(",")
            parser = l_col[5]
            type_log = l_col[3]

            timestamp = re.search(d_regex_4624.get("timestamp"), l_col[0])
            res = ""
            if timestamp:
                timestamp = timestamp.group().split("T")

            if parser in ["winreg/windows_run"]:
                action = l_col[4]
                entries = re.search(r'Entries: \[(.*)\]', action)
                if entries:
                    entries = entries.group(1).split("  ")
                    for entrie in entries:
                        if entrie:
                            res = "{}|{}|{}".format(timestamp[0], timestamp[1], entrie)
                            print(res)
                #print(line)
                #print("----------------------------------------------------------------------------------------------")
                #print("\n")


filestat
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
custom_destinations/lnk
custom_destinations/lnk/shell_items
esedb/msie_webcache
esedb/srum
filestat
lnk
lnk/shell_items
mft
olecf/olecf_automatic_destinations
olecf/olecf_automatic_destinations/lnk
olecf/olecf_automatic_destinations/lnk/shell_items
olecf/olecf_default
parser
pe
prefetch
sqlite/firefox_history
sqlite/windows_timeline
text/setupapi
utmp
winevtx
winreg/amcache
winreg/appcompatcache
winreg/bagmru
winreg/bagmru/shell_items
winreg/bam
winreg/explorer_mountpoints2
winreg/explorer_programscache
winreg/mrulistex_shell_item_list
winreg/mrulistex_shell_item_list/shell_items
winreg/mrulistex_string
winreg/mrulistex_string_and_shell_item
winreg/mrulistex_string_and_shell_item_list
winreg/mrulistex_string_and_shell_item_list/shell_items
winreg/mrulist_string
winreg/msie_zone
winreg/networks
winreg/userassist
winreg/windows_boot_execute
winreg/windows_run
winreg/windows_sam_users
winreg/windows_services
winreg/windows_shutdown
winreg/windows_task_cache
winreg/windows_timezone
winreg/windows_typed_urls
winreg/windows_usb_devices
winreg/windows_usbstor_devices
winreg/windows_version
winreg/winlogon
winreg/winreg_default


'''
