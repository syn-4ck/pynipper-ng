import os

<<<<<<< HEAD
from ..devices.common.types import DeviceType
from ..error.files_errors import DeviceConfigurationFileNotFound

from .cisco.analyze_cisco_device import analyze_cisco_device
=======
from ..error.files_errors import DeviceConfigurationFileNotFound

from .cisco.ios.analyze_cisco_device import analyze_cisco_device
>>>>>>> main


def analyze_device(device, input_filename, output_filename, output_type, configuration, online) -> None:

    # Check configuration file exists
<<<<<<< HEAD
    if not os.path.isfile(args["input_file"]):
        raise DeviceConfigurationFileNotFound(
            "ERROR: Device configuration file doesn't exists")

    # Cisco IOS devices
    cisco_devices = DeviceType._member_names_[:3]
    analyze_cisco_device(args, cisco_devices)
=======
    if not os.path.isfile(input_filename):
        raise DeviceConfigurationFileNotFound(
            "ERROR: Device configuration file doesn't exists")

    # Only for Cisco IOS devices yet
    analyze_cisco_device(device, input_filename, output_filename, output_type, configuration, online)
>>>>>>> main
