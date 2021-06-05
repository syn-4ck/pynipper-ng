import os

from ..devices.common.types import DeviceType
from ..error.files_errors import DeviceConfigurationFileNotFound

from .cisco.analyze_cisco_device import analyze_cisco_device


def analyze_device(args: dict) -> None:

    # Check configuration file exists
    if not os.path.isfile(args["input_file"]):
        raise DeviceConfigurationFileNotFound(
            "ERROR: Device configuration file doesn't exists")

    # Cisco IOS devices
    cisco_devices = DeviceType._member_names_[:3]
    analyze_cisco_device(args, cisco_devices)
