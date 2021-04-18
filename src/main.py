import argparse

from typing import List
from typing import Optional

from common.banner import display_banner
from devices.common.types import DeviceType
from report.common.types import ReportType
from analyze.analyze_device import analyze_device


def main(argv: Optional[List[str]] = None) -> int:

    display_banner()

    device_type_list = [dev.name for dev in DeviceType]
    report_type_list = [report.name for report in ReportType]

    parser = argparse.ArgumentParser()

    parser.add_argument('--device', '-d', help="Device type to analyze",
                        dest="device_type", action="store",
                        choices=device_type_list, required=True)
    parser.add_argument('--input', '-i', help="Device configuration file",
                        dest="input_file", action="store",
                        type=str, required=True)
    parser.add_argument('--output-filename', '-f', help="Report filename",
                        dest="output_file", action="store",
                        type=str, default="./report.html")
    parser.add_argument('--output-type', '-o', help="Report type",
                        dest="output_type", action="store",
                        choices=report_type_list, default=ReportType.HTML)
    parser.add_argument('--configuration', '-c', help="Configuration file",
                        dest="conf_file", action="store", type=str,
                        default="./common/default.conf")
    parser.add_argument('--offline', '-x',
                        help="Disable get APIs vulnerabilities data (Cisco API)",  # noqa: E501
                        dest="offline", action='store_true')

    args = parser.parse_args()

    args_dict = vars(args)

    analyze_device(args_dict)

    return 0


if __name__ == "__main__":
    main()
