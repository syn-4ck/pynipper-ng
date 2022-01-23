import os

from ..error.files_errors import DeviceConfigurationFileNotFound

from .cisco.ios.analyze_cisco_device import analyze_cisco_device


def analyze_device(device, input_filename, output_filename, output_type, configuration, online) -> None:

    # Check configuration file exists
    if not os.path.isfile(input_filename):
        raise DeviceConfigurationFileNotFound(
            "ERROR: Device configuration file doesn't exists")

    # Only for Cisco IOS devices yet
    analyze_cisco_device(device, input_filename, output_filename, output_type, configuration, online)
