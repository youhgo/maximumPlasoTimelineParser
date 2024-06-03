#!/usr/bin/python3
import json
import os
import traceback
import argparse
import re
from datetime import datetime
import xmltodict
import time
import sys

# TODO : Parsing
# TODO : Parse AV Detection
# TODO : Parse Firewall Detection
# TODO : Parse Shutdown + restart
# TODO : Parse Log erasure

# TODO : General
# TODO : Parse Task Scheduler event 4698 + 4702
# TODO : Remove duplicate
# TODO : Be able to produce CSV and JSON output in 1 run


class MaximumPlasoParserJson:
    """
       Class MaximumPlasoParser
       MPP or MaximumPlasoParser is a python script that will parse a plaso - Log2Timeline json timeline file.
       The goal is to provide easily readable and straight forward files for the Forensic analyst.
       MPP will create a file for each artefact.
       Attributes :
       None
    """

    def __init__(self, dir_out, output_type="csv", separator="|", case_name=None, config_file=None, machine_name="workstation") -> None:
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
        self.machine_name = machine_name

        self.current_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        self.work_dir = os.path.join(os.path.abspath(dir_out), "mpp_{}_{}".format(self.machine_name, self.current_date))
        self.initialise_working_directories()

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
                "lnk": 1,
                "mft": 1,
                "windefender": 1
            }

        self.d_regex_type_artefact = {
            "evtx": re.compile(r'winevtx'),
            "hive": re.compile(r'winreg'),
            "db": re.compile(r'(sqlite)|(esedb)'),
            "winFile": re.compile(r'(lnk)|(text)|(prefetch)'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)')
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
            "application_experience": re.compile(r'Microsoft-Windows-Application-Experience'),
            "windefender": re.compile(r'Microsoft-Windows-Windows Defender') #.*Microsoft-Windows-Windows_Defender%4Operational
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
            "run": re.compile(r'windows_run'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)')
        }

        self.l_csv_header_4624 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                           "target_user_name", "ip_address", "ip_port", "workstation_name"]
        self.l_csv_header_4625 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                           "target_user_name", "ip_address", "ip_port", "workstation_name"]
        self.l_csv_header_4672 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                           "target_user_name", "ip_address", "ip_port", "workstation_name"]
        self.l_csv_header_4648 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                           "target_user_name", "ip_address", "ip_port", "workstation_name"]
        self.l_csv_header_4688 = ["Date", "Time", "event_code", "new_process_name", "command_line",
                                  "parent_process_name", "subject_user_name", "target_user_name", "workstation_name"]
        self.l_csv_header_tscheduler = ["Date", "Time", "event_code", "name", "task_name", "instance_id",
                                        "action_name", "result_code", "user_name", "user_context"]
        self.l_csv_header_remot_rdp = ["Date", "Time", "event_code", "user_name", "ip_addr"]
        self.l_csv_header_local_rdp = ["Date", "Time", "event_code", "user_name", "ip_addr", "session_id",
                                       "source", "target_session", "reason_n", "reason"]
        self.l_csv_header_bits = ["Date", "Time", "event_code", "id", "job_id", "job_title", "job_owner",
                                  "user", "bytes_total", "bytes_transferred", "file_count", "file_length", "file_Time",
                                  "name", "url", "process_path"]
        self.l_csv_header_7045 = ["Date", "Time", "event_code", "account_name", "img_path", "service_name", "start_type"]
        self.l_csv_header_powershell = ["Date", "Time", "event_code", "path_to_script", "script_block_text"]
        self.l_csv_header_script_powershell = ["Date", "Time", "event_code", "cmd"]
        self.l_csv_header_wmi = ["Date", "Time", "user", "nameSpace", "Query"]
        self.l_csv_header_app_exp = ["Date", "Time", "ExePath", "FixName", "Query"]
        self.l_csv_header_amcache = ["Date", "Time", "Name", "id", "FullPath", "Hash"]
        self.l_csv_header_appcompat = ["Date", "Time", "Name", "FullPath", "Hash"]
        self.l_csv_header_sam = ["Date", "Time", "username", "login_count"]
        self.l_csv_header_usserassit = ["Date", "Time", "valueName", "appFocus", "appDuration"]
        self.l_csv_header_mru = ["Date", "Time", "entries"]
        self.l_csv_header_srum = ["Date", "Time", "description"]
        self.l_csv_header_run = ["Date", "Time", "entrie"]
        self.l_csv_header_ff_history = ["Date", "Time", "url", "visit_count", "visit_type", "isType", "from_visit"]
        self.l_csv_header_ie_history = ["Date", "Time", "url", "visit_count", "visit_type", "isType", "from_visit"]
        self.l_csv_header_prefetch = ["Date", "Time", "name", "path", "nbExec", "sha256"]
        self.l_csv_header_lnk = ["Date", "Time", "description", "working_dir"]
        self.l_csv_header_mft = ["Date", "Time", "source", "fileName", "action", "fileType"]
        self.l_csv_header_windefender = ["Date", "Time", "Event", "ThreatName", "Severity", "User", "ProcessName",
                                         "Path", "Action"]
        
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
        self.ie_history_res_file = ""
        self.prefetch_res_file = ""
        self.srum_res_file = ""
        self.run_res_file = ""
        self.lnk_res_file = ""

        self.mft_res_file = ""

        self.windefender_res_file = ""

        self.initialise_results_files()

    def initialise_working_directories(self):
        """
        To create directories where the results will be written
        :return:
        """
        try:
            #print("creating {}".format(self.work_dir))
            os.makedirs(self.work_dir, exist_ok=True)
            print("result directory is located at : {}".format(self.work_dir))
        except:
            sys.stderr.write("\nfailed to initialises directories {}\n".format(traceback.format_exc()))

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

    def initialise_result_file(self, header, file_name, extension):
        """
        initialise a result file, write the header into it and return a stream to this file
        :param header: (list[str]) list containing all column name
        :param file_name: (str) the name of the file containing
        :param extension: (str) the name of the extension of the file
        :return: stream to a file
        """
        result_file_stream = open(os.path.join(self.work_dir, "{}.{}".format(file_name, extension)), 'a')
        if extension == "csv":
            result_file_stream.write(self.separator.join(header))
            result_file_stream.write("\n")
        return result_file_stream

    def initialise_results_files(self):
        """
        Function that will initialise all csv result file.
        It will open a stream to all results file and write header into it.
        Stream are keeped open to avoid opening and closing multiple file every new line of the timeline
        :return: None
        """

        if self.config.get("4624", 0):
            self.logon_res_file = self.initialise_result_file(self.l_csv_header_4624, "4624", self.output_type)

        if self.config.get("4625", 0):
            self.logon_failed_file = self.initialise_result_file(self.l_csv_header_4625, "4625", self.output_type)

        if self.config.get("4672", 0):
            self.logon_spe_file = self.initialise_result_file(self.l_csv_header_4672, "4672", self.output_type)

        if self.config.get("4648", 0):
            self.logon_exp_file = self.initialise_result_file(self.l_csv_header_4648, "4648", self.output_type)

        if self.config.get("4688", 0):
            self.new_proc_file = self.initialise_result_file(self.l_csv_header_4688, "4688", self.output_type)

        if self.config.get("taskScheduler", 0):
            self.task_scheduler_file = self.initialise_result_file(self.l_csv_header_tscheduler,
                                                                   "task_scheduler", self.output_type)
        if self.config.get("remote_rdp", 0):
            self.remote_rdp_file = self.initialise_result_file(self.l_csv_header_remot_rdp,
                                                               "remote_rdp", self.output_type)

        if self.config.get("local_rdp", 0):
            self.local_rdp_file =self.initialise_result_file(self.l_csv_header_local_rdp,
                                                             "local_rdp", self.output_type)

        if self.config.get("bits", 0):
            self.bits_file = self.initialise_result_file(self.l_csv_header_bits, "bits", self.output_type)

        if self.config.get("service", 0):
            self.service_file = self.initialise_result_file(self.l_csv_header_7045, "7045", self.output_type)

        if self.config.get("powershell", 0):
            self.powershell_file = self.initialise_result_file(self.l_csv_header_powershell,
                                                               "powershell", self.output_type)
        if self.config.get("powershell_script", 0):
            self.powershell_script_file = self.initialise_result_file(self.l_csv_header_script_powershell,
                                                                      "powershell_script", self.output_type)

        if self.config.get("wmi", 0):
            self.wmi_file = self.initialise_result_file(self.l_csv_header_wmi, "wmi", self.output_type)

        # ----------------------------- Hives ------------------------------------------------

        if self.config.get("app_exp"):
            self.app_exp_file = self.initialise_result_file(self.l_csv_header_app_exp,
                                                            "application_experience", self.output_type)

        if self.config.get("amcache"):
            self.amcache_res_file = self.initialise_result_file(self.l_csv_header_amcache, "amcache",
                                                                self.output_type)

        if self.config.get("app_compat"):

            self.app_compat_res_file = self.initialise_result_file(self.l_csv_header_appcompat,
                                                                   "app_compat_cache", self.output_type)
        if self.config.get("sam"):
            self.sam_res_file = self.initialise_result_file(self.l_csv_header_sam, "sam", self.output_type)

        if self.config.get("user_assist"):
            self.user_assist_file = self.initialise_result_file(self.l_csv_header_usserassit, "user_assist",
                                                                self.output_type)

        if self.config.get("mru"):

            self.mru_res_file = self.initialise_result_file(self.l_csv_header_mru, "mru", self.output_type)

        if self.config.get("srum"):
            self.srum_res_file = self.initialise_result_file(self.l_csv_header_srum, "srum", self.output_type)

        if self.config.get("run"):
            self.run_res_file = self.initialise_result_file(self.l_csv_header_run, "run_key", self.output_type)

        # ----------------------------- Other ------------------------------------------------

        if self.config.get("ff_history"):
            self.ff_history_res_file = self.initialise_result_file(self.l_csv_header_ff_history, "ff_history",
                                                                   self.output_type)

        if self.config.get("ie_history"):
            self.ie_history_res_file = self.initialise_result_file(self.l_csv_header_ie_history, "ie_history",
                                                                   self.output_type)

        if self.config.get("prefetch"):
            self.prefetch_res_file = self.initialise_result_file(self.l_csv_header_prefetch, "prefetch",
                                                                 self.output_type)

        if self.config.get("lnk"):
            self.lnk_res_file = self.initialise_result_file(self.l_csv_header_lnk, "lnk", self.output_type)

        if self.config.get("mft"):
            self.mft_res_file = self.initialise_result_file(self.l_csv_header_mft, "mft", self.output_type)

        if self.config.get("windefender"):
            self.windefender_res_file = self.initialise_result_file(self.l_csv_header_windefender,
                                                                    "windefender", self.output_type)

    def identify_type_artefact_by_parser(self, line):
        """
        Function to indentify an artefact type depending on the plaso parser used
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the parser
        """
        for key, value in self.d_regex_type_artefact.items():
            if re.search(value, line.get("parser")):
                return key

    def identify_artefact_by_filename(self, line):
        """
        Function to indentify an artefact type depending on the name of the file that was parsed
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the filename
        """
        for key, value in self.d_regex_aterfact_by_file_name.items():
            if re.search(value, line.get("filename")):
                return key

    def identify_artefact_by_source_name(self, line):
        """
        Function to indentify an artefact type depending on the source type of the file that was parsed
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the source name
        """
        for key, value in self.d_regex_artefact_by_source_name.items():
            if re.search(value, line.get("source_name")):
                return key

    def identify_artefact_by_parser_name(self, line):
        """
        Function to indentify an artefact depending on the plaso parser used
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the parser
        """
        for key, value in self.d_regex_artefact_by_parser_name.items():
            if re.search(value, line.get("parser")):
                return key

    def assign_parser(self, line, type_artefact):
        """
        Function to assign a parser depending on the artefact type
        :param line: (dict) dict containing one line of the plaso timeline,
        :param type_artefact: (str) type of artefact
        :return: None
        """
        #print('type artefact is {}'.format(type_artefact))
        if type_artefact == "evtx":
            self.parse_logs(line)
        if type_artefact == "hive":
            self.parse_hives(line)
        if type_artefact == "db":
            self.parse_db(line)
        if type_artefact == "winFile":
            self.parse_win_file(line)
        if type_artefact == "mft":
            self.parse_mft(line)

    def close_files_leg(self):
        """
        Function to close all opened stream
        :return:
        """
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
        self.ie_history_res_file.close()

        self.prefetch_res_file.close()
        self.lnk_res_file.close()
        self.mft_res_file.close()

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
        if self.ie_history_res_file:
            self.ie_history_res_file.close()
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
        """
        Main function to parse log type artefacts
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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
        if log_type == "windefender":
            self.parse_windows_defender(line)


    #  ----------------------------------------  Wmi ---------------------------------------------
    def parse_wmi(self, event):
        """
        Main function to parse wmi type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.wmi_file:
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
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
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
            
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
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
        event_code = event.get("event_identifier")
        if self.remote_rdp_file:
            if str(event_code) in ["1149"]:
                self.parse_rdp_remote_evtx_from_xml(event)
        if self.local_rdp_file:
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
            
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
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
            
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
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
        if self.bits_file:
            event_code = event.get("event_identifier")
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
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
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

    #  ----------------------------------------  Security ---------------------------------------------

    def parse_security_evtx(self, event):
        """
        Main function to parse security type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if event_code == 4624 and self.logon_res_file:
            self.parse_logon_from_xml(event)

        if event_code == 4625 and self.logon_failed_file:
            self.parse_failed_logon_from_xml(event)

        if event_code == 4672 and self.logon_spe_file:
            self.parse_spe_logon_from_xml(event)

        if event_code == 4648 and self.logon_exp_file :
            self.parse_logon_exp_from_xml(event)

        if event_code == 4688 and self.new_proc_file:
            self.parse_new_proc_from_xml(event)

    def parse_logon_from_xml(self, event):
        """
        Function to parse logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, subject_user_name, target_user_name,
                                                   ip_address, ip_port, logon_type)
            self.logon_res_file.write(res)

        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type
            }
            json.dump(res, self.logon_res_file)

        self.logon_res_file.write('\n')

    def parse_failed_logon_from_xml(self, event):
        """
        Function to parse failed logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, subject_user_name, target_user_name,
                                                   ip_address, ip_port, logon_type)
            self.logon_failed_file.write(res)

        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type
            }
            json.dump(res, self.logon_failed_file)

        self.logon_failed_file.write('\n')

    def parse_spe_logon_from_xml(self, event):
        """
        Function to parse special logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, subject_user_name, target_user_name,
                                                   ip_address, ip_port, logon_type)
            self.logon_spe_file.write(res)

        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type
            }
            json.dump(res, self.logon_spe_file)

        self.logon_spe_file.write('\n')

    def parse_logon_exp_from_xml(self, event):
        """
        Function to explicit logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, subject_user_name, target_user_name,
                                                   ip_address, ip_port, logon_type)
            self.logon_exp_file.write(res)

        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type
            }
            json.dump(res, self.logon_exp_file)

        self.logon_exp_file.write('\n')

    def parse_new_proc_from_xml(self, event):
        """
        Function to parse new process log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, subject_user_name, target_user_name,
                                                   cmd_line, new_proc_name, parent_proc_name)
            self.new_proc_file.write(res)

        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "cmd_line": cmd_line,
                "new_process_name": new_proc_name,
                "parent_process_name": parent_proc_name
            }
            json.dump(res, self.new_proc_file)

        self.new_proc_file.write('\n')

    #  ----------------------------------------  System ---------------------------------------------
    def parse_system_evtx(self, event):
        """
        Main function to parse system type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if event_code == 7045 and self.service_file:
            self.parse_service_from_xml(event)

    def parse_service_from_xml(self, event):
        """
        Function to parse service creation log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, account_name, img_path, service_name,
                                             start_type)

            self.service_file.write(res)

        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "account_name": account_name,
                "imgage_path": img_path,
                "service_name": service_name,
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
        event_code = event.get("event_identifier")
        if self.task_scheduler_file:
            if str(event_code) in ["106", "107", "140", "141", "200", "201"]:
                self.parse_task_scheduler_from_xml(event)
            if str(event_code) in ["4698", "4702"]:
                pass

    def parse_task_scheduler_from_xml(self, event):
        """
        Function to parse task scheduler log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
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

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, name, task_name,
                                                         instance_id, action_name, result_code, user_name, user_context)
            self.task_scheduler_file.write(res)

        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "name": name,
                "task_name": task_name,
                "instance_id": instance_id,
                "action_name": action_name,
                "result_code": result_code,
                "user_name": user_name,
                "user_context": user_context
            }

            json.dump(res, self.task_scheduler_file)

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
        
        '''

    #  ----------------------------------------  PowerShell ---------------------------------------------
    def parse_powershell(self, event):
        """
        Main function to parse powershell type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        event_code = event.get("event_identifier")
        if self.powershell_script_file:
            if str(event_code) in ["4104", "4105", "4106"]:
                self.parse_powershell_script_from_xml(event)
        if self.powershell_file:
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
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
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
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
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
        event_code = event.get("event_identifier")
        if self.app_exp_file:
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
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "fix_name": fix_name,
                "exe_path": exe_path
            }

            json.dump(res, self.app_exp_file)

        self.app_exp_file.write('\n')

    #  -------------------------------------------------------------  Hives --------------------------------------------

    def parse_hives(self, line):
        """
        Main function to parse windows hive type artefact
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        hive_type = self.identify_artefact_by_parser_name(line)
        if hive_type == "amcache" and self.amcache_res_file:
            self.parse_amcache(line)
        if hive_type == "appCompat" and self.app_compat_res_file:
            self.parse_app_compat_cache(line)
        if hive_type == "sam" and self.sam_res_file:
            self.parse_sam(line)
        if hive_type == "userassist" and self.user_assist_file:
            self.parse_user_assist(line)
        if hive_type == "mru" and self.mru_res_file:
            self.parse_mru(line)
        if hive_type == "run" and self.run_res_file:
            self.parse_run(line)

    def parse_amcache(self, event):
        """
        Function to parse amcache hive type.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        full_path = event.get("full_path", "-")
        if full_path != "-":
            name = full_path.split("\\")[-1]
            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
            identifier = event.get("program_identifier", "-")
            sha256_hash = event.get("sha256_hash", "-")

            if self.output_type == "csv":
                #res = "{}|{}|{}|{}".format(ts_date, ts_time, name, identifier)
                res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, name, identifier, sha256_hash)
                self.amcache_res_file.write(res)

            else:
                
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "name": name,
                    "identifier": identifier,
                    "hash": sha256_hash
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
                #res = "{}|{}|{}|{}".format(ts_date, ts_time, name, full_path)
                res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, name, full_path, sha256_hash)
                self.app_compat_res_file.write(res)

            else:
                
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "name": name,
                    "identifier": full_path,
                    "hash": sha256_hash
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
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
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
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
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
                
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
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
                        
                        res = {
                            "caseName": self.case_name,
                            "workstation_name": self.machine_name,
                            "timestamp": "{}T{}".format(ts_date, ts_time),
                            "mru_entrie": cleaned
                        }
                        json.dump(res, self.mru_res_file)
                    self.mru_res_file.write('\n')

    def parse_run(self, event):
        """
        Function to parse run/RunOnce reg key entries.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        entries = event.get("entries", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if entries:
            for entrie in entries:
                if self.output_type == "csv":
                    res = "{}|{}|{}".format(ts_date, ts_time, entrie)
                    self.run_res_file.write(res)
                else:
                    
                    res = {
                        "caseName": self.case_name,
                        "workstation_name": self.machine_name,
                        "timestamp": "{}T{}".format(ts_date, ts_time),
                        "run_entrie": entrie
                    }
                    json.dump(res, self.run_res_file)
                self.run_res_file.write('\n')

    #  -------------------------------------------------------------  DB -----------------------------------------------

    def parse_db(self, line):
        """
        Main function to parse db type artefact
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        db_type = self.identify_artefact_by_parser_name(line)
        if db_type == "ff_history" and self.ff_history_res_file:
            self.parse_ff_history(line)
        if db_type == "ie_history" and self.ie_history_res_file:
            pass
        if db_type == "srum" and self.srum_res_file:
            self.parse_srum(line)

    def parse_srum(self, event):
        """
        Function to parse srum artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        description = event.get("message", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type == "csv":
            res = "{}|{}|{}".format(ts_date, ts_time, description)
            self.srum_res_file.write(res)

        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "description": description
            }
            json.dump(res, self.srum_res_file)
        self.srum_res_file.write('\n')

    def parse_ff_history(self, event):
        """
        Function to parse firefox history.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        url = event.get("url", "-")
        visit_count = event.get("visit_count", "-")
        visit_type = event.get("visit_type", "-")
        is_typed = event.get("typed", "-")
        from_visit = event.get("from_visit", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, url, visit_count, visit_type, is_typed, from_visit)
            self.ff_history_res_file.write(res)
        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "url": url,
                "visit_count": visit_count,
                "visit_type": visit_type,
                "is_typed": is_typed,
                "from_visit": from_visit,
            }
            json.dump(res, self.ff_history_res_file)
        self.ff_history_res_file.write('\n')

    #  ------------------------------------------------------  Win Files -----------------------------------------------

    def parse_win_file(self, line):
        """
        Main function to parse windows type artefact
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        file_type = self.identify_artefact_by_parser_name(line)
        if file_type == "prefetch" and self.prefetch_res_file:
            self.parse_prefetch(line)
        if file_type == "lnk" and self.lnk_res_file:
            self.parse_lnk(line)

    def parse_prefetch(self, event):
        """
        Function to parse prefetch files.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        run_count = event.get("run_count", "-")
        path_hints = event.get("path_hints", "-")
        executable = event.get("executable", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}".format(ts_date, ts_time, executable, path_hints, run_count)
            self.prefetch_res_file.write(res)
        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "executable": executable,
                "path_hints": path_hints,
                "run_count": run_count
            }
            json.dump(res, self.prefetch_res_file)
        self.prefetch_res_file.write('\n')

    def parse_lnk(self, event):
        """
        Function to parse lnk type artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        description = event.get("description", "-")
        working_directory = event.get("working_directory", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if description != "-" and working_directory != "-":
            if self.output_type == "csv":
                res = "{}|{}|{}|{}".format(ts_date, ts_time, description, working_directory)
                self.lnk_res_file.write(res)
            else:
                
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "description": description,
                    "working_directory": working_directory
                }
                json.dump(res, self.lnk_res_file)
            self.lnk_res_file.write('\n')

    #  -------------------------------------------------------------  MFT --------------------------------------------

    def parse_mft(self, line):
        """
        Main function to parse windows mft
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        reg_ntfs = re.compile(r'NTFS')
        if not self.config.get("mft", "") or not line:
            return
        parser = line.get("parser")
        if parser in ["usnjrnl"]:
            self.parse_usnjrl(line)
        elif parser in ["mft"]:
            self.parse_file_mft(line)
        elif parser in ["filestat"] and re.search(reg_ntfs, json.dumps(line)):
            self.parse_filestat(line)

#TODO: Improve name regex
    def parse_usnjrl(self, event):
        """
        :param event: (dict) dict containing one line of the plaso timeline,
        :return:
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        msg = event.get("message")
        file_name_re = re.compile(r'^(.{1,}\.){1,}(\w){1,3}')
        file_name = re.search(file_name_re, msg)
        update_reason_reg = re.compile(r'Update reason: (.*)')
        update_reason = re.search(update_reason_reg, msg)
        if update_reason:
            try:
                update_reason = update_reason.group(1).replace(',', '')
            except:
                update_reason = "noReason"
        if file_name:
            try:
                file_name = file_name.group()
            except:
                pass

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, "USNJRNL", "N/A", update_reason, file_name)
            self.mft_res_file.write(res)
        else:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "workstation_name": self.machine_name,
                "message": msg,
                "file_name": file_name
            }
            json.dump(res, self.mft_res_file)

        self.mft_res_file.write('\n')

    def parse_filestat(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        file_name_path = event.get("filename")
        file_type = event.get("file_entry_type")
        action = event.get("timestamp_desc")
        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, 'FILESTAT', file_type, action, file_name_path)
            self.mft_res_file.write(res)
        else:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(ts_date, ts_time,),
                "workstation_name": self.machine_name,
                "action": action,
                "file_type": file_type,
                "path": file_name_path
            }
            json.dump(res, self.mft_res_file)
        self.mft_res_file.write('\n')

    def parse_file_mft(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        file_name_path = event.get("filename")
        file_type = event.get("file_entry_type")
        action = event.get("timestamp_desc")
        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, "MFT", file_type, action, file_name_path)
            self.mft_res_file.write(res)

        else:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(ts_date, ts_time,),
                "workstation_name": self.machine_name,
                "action": action,
                "file_type": file_type,
                "path": file_name_path
            }
            json.dump(res, self.mft_res_file)
        self.mft_res_file.write('\n')

    def parse_windows_defender(self, line):
        """
        Main function to parse windows defender logs
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        if not self.config.get("windefender", "") or not line:
            return
        event_code = str(line.get("event_identifier"))
        if event_code in ["1116"] and self.windefender_res_file:
            self.parse_windef_detection_from_xml(line)
        if event_code in ["1117", "1118", "1119"] and self.windefender_res_file:
            self.parse_windef_action_from_xml(line)
        if event_code in ["1006"] and self.windefender_res_file:
            pass
            #self.parse_windef_detection_from_xml_legacy(line)
        if event_code in ["1007"] and self.windefender_res_file:
            pass
            #self.parse_windef_action_from_xml_legacy(line)

    def parse_windef_detection_from_xml(self, event):
        """
        Function to parse windefender detection log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1116 - Detection"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, threat_name, severity,
                                                   detection_user, process_name, action)
            self.windefender_res_file.write(res)

        else:
            
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action
            }
            json.dump(res, self.logon_res_file)
        self.windefender_res_file.write('\n')

    def parse_windef_action_from_xml(self, event):
        """
        Function to parse windefender action log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1117 - Action"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, threat_name, severity,
                                                   detection_user, process_name, action)
            self.windefender_res_file.write(res)

        else:

            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action
            }
            json.dump(res, self.logon_res_file)
        self.windefender_res_file.write('\n')

    def parse_windef_detection_from_xml_legacy(self, event):
        """
        Function to parse windefender detection log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1006"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            print(data)
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")
        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, threat_name, severity,
                                                   detection_user, process_name, action)
            self.windefender_res_file.write(res)

        else:

            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action
            }
            json.dump(res, self.logon_res_file)
        self.windefender_res_file.write('\n')

    def parse_windef_action_from_xml_legacy(self, event):
        """
        Function to parse windefender action log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1117"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")

        if self.output_type == "csv":
            res = "{}|{}|{}|{}|{}|{}|{}|{}".format(ts_date, ts_time, event_code, threat_name, severity,
                                                   detection_user, process_name, action)
            self.windefender_res_file.write(res)

        else:

            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action
            }
            json.dump(res, self.logon_res_file)
        self.windefender_res_file.write('\n')


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

    argument_parser.add_argument("-m", "--machine_name", action="store",
                                 required=False, dest="machine_name", default="machineX",
                                 metavar="name of the machine",
                                 help="name of the machine")

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


# File appears not to be in CSV format; move along
def check_input(timeline):
    if validate_json(timeline):
        return "json"
    else:
        print("Cannot read timeline correctly, are you sure that it is a valid json line format?")
        exit(1)


if __name__ == '__main__':

    parser = parse_args()
    args = parser.parse_args()

    start_time = time.time()
    now = datetime.now()  # current date and time
    date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

    print("Started at:", date_time)

    type_input = check_input(args.timeline)
    if type_input == "json":
        mp = MaximumPlasoParserJson(args.output_dir, args.type_output, args.separator, args.case_name, args.config_file,
                                    args.machine_name)
        mp.parse_timeline(args.timeline)
    else:
        print("Timeline is not a valide Json, aboarding")
        exit(1)

    print("Finished in {} secondes".format(time.time() - start_time))


"""
location": "Microsoft-Windows-Windows Defender%4Operational.evtx
location": "Microsoft-Windows-Windows Defender%4WHC.evtx
event id 1116 1117 1015 1013 1014 1012 1011 1010 1009 1008 1007 1006 1005 1004 1003 1002 

location": "Microsoft-Windows-Windows Firewall With Advanced Security%4ConnectionSecurity.evtx
location": "Microsoft-Windows-Windows Firewall With Advanced Security%4FirewallDiagnostics.evtx
location": "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx
location": "Microsoft-Windows-WindowsUpdateClient%4Operational.evtx
location": "Microsoft-Windows-WinINet-Config%4ProxyConfigChanged.evtx
location": "Microsoft-Windows-Winlogon%4Operational.evtx
location": "Microsoft-Windows-WinRM%4Operational.evtx
location": "Microsoft-Windows-WMI-Activity%4Operational.evtx

"""