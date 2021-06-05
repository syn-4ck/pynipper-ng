
import configparser
import array
import os

from ..cisco.cisco_api_vulns.cisco_ios_vulns_service import get_cisco_ios_vulns_data
from ..cisco.cisco_api_vulns.cisco_vuln import CiscoVuln
from ..cisco.cisco_parser.parse_config import get_cisco_ios_version

from ...error.cisco_errors import GenericCiscoError

from ..cisco.cisco_api_vulns.cisco_vuln import CiscoVuln

from ..cisco.process_cisco_ios_conf import process_cisco_ios_conf
from ..cisco.cisco_parser.parse_config import get_cisco_ios_hostname

from ...report.report import generate_html_report, generate_json_report
from ...report.common.types import ReportType

from ...error.files_errors import PynipperConfigurationFileNotFound


def analyze_cisco_device(args: array, cisco_devices: array):
    if args["device_type"] in cisco_devices:

        print("[1/4] Initializing pynipper-ng")
        version_cisco_device = get_cisco_ios_version(args["input_file"])

        # Get vulns by Cisco API
        if not os.path.isfile(args["conf_file"]):
            raise PynipperConfigurationFileNotFound(
                "ERROR: Pynipper configuration file doesn't exists"
            )
        config_file = configparser.ConfigParser()
        config_file.read(args["conf_file"])
        client_id = ""
        if config_file.has_option('Cisco', 'CLIENT_ID'):
            client_id = config_file['Cisco']['CLIENT_ID']
        client_secret = ""
        if config_file.has_option('Cisco', 'CLIENT_SECRET'):
            client_secret = config_file['Cisco']['CLIENT_SECRET']

        vulns = get_cisco_ios_vulns_data(
            version_cisco_device, client_id, client_secret, args["offline"])

        vulns_array = _vulns_get_fields(vulns)
        vulns_array_sorted = sorted(vulns_array, reverse=True)

        # Get Cisco report missconfigurations
        print("[3/4] Checking missconfiguration vulnerabilities")
        issues = process_cisco_ios_conf(args["input_file"])
        data = {}
        data['hostname'] = get_cisco_ios_hostname(args["input_file"])
        data['device-type'] = str(args["device_type"])

        # Generate report
        print("[4/4] Generating report")
        if args["output_type"] == ReportType._member_names_[0]:
            generate_html_report(args["output_file"],
                                 issues, vulns_array_sorted, data)
        elif args["output_type"] == ReportType._member_names_[1]:
            generate_json_report(args["output_file"],
                                 issues, vulns_array_sorted, data)

def _vulns_get_fields(vulns: str) -> array:
    vulns_array = []
    try:
        if vulns != '{}':
            for vuln in vulns["advisories"]:
                v = CiscoVuln(
                    vuln["advisoryTitle"],
                    vuln["summary"],
                    vuln["cves"],
                    vuln["cvssBaseScore"],
                    vuln["publicationUrl"]
                )
                vulns_array.append(v)
    except KeyError:
        try:
            if vulns["errorCode"]:
                raise GenericCiscoError(vulns["errorMessage"])
        except KeyError:
            raise GenericCiscoError(
                "Unexpected error getting vulns from Cisco API"
            )
    except Exception:
        raise GenericCiscoError(
            "Unexpected error getting vulns from Cisco API"
        )

    return vulns_array