
import os

from .api.cisco_ios_vulns_service import get_api_vulnerabilities
from .cisco_parser.parse_config import get_cisco_ios_version, get_cisco_ios_hostname
from ....devices.common.types import DeviceType

from .core.process_cisco_ios_conf import process_cisco_ios_conf
from .core.process_password_issues import get_exposed_passwords

from ....report.report import generate_report

from ....error.files_errors import PynipperConfigurationFileNotFound


def analyze_cisco_device(device, input_filename, output_filename, output_type, configuration, online):

    print("[1/4] Initializing pynipper-ng")
    version_cisco_device = get_cisco_ios_version(input_filename)
    if not os.path.isfile(configuration):
        raise PynipperConfigurationFileNotFound(
            "ERROR: Pynipper configuration file doesn't exists"
        )

    # Get vulns by Cisco API
    print("[2/4] Fetching Cisco API information")
    vulns = get_api_vulnerabilities(configuration, version_cisco_device, online)

    # Get Cisco report missconfigurations
    print("[3/4] Checking missconfiguration vulnerabilities")
    issues = process_cisco_ios_conf(input_filename)

    passwords = get_exposed_passwords(input_filename)

    # Device data to generate report
    data = {}
    data['hostname'] = get_cisco_ios_hostname(input_filename)

    data['device-type'] = [dev.value for dev in DeviceType if dev.name == device][0]

    # Generate report
    print("[4/4] Generating report")
    generate_report(output_type, output_filename, issues, vulns, passwords, data)
