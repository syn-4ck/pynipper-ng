from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import datetime
import array
import json

from .common.types import ReportType

TEMPLATE_FILE = "html_template.html"

def generate_report(output_type, output_filename, issues, vulns_array_sorted, data):
    if output_type == ReportType._member_names_[0]:
        _generate_html_report(output_filename,
                            issues, vulns_array_sorted, data)
    elif output_type == ReportType._member_names_[1]:
        _generate_json_report(output_filename,
                            issues, vulns_array_sorted, data)


def _generate_html_report(filename: str, issues: dict, vulns: array, data: dict) -> None:
    html_file = open(filename, "w")

    date = datetime.datetime.now().date()
    device_type = data["device-type"]
    hostname = data["hostname"]

    template_loader = FileSystemLoader(os.path.dirname(
        os.path.abspath(__file__)) + "/templates")

    env = Environment(
        loader=template_loader,
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template(TEMPLATE_FILE)

    text = template.render(
        device_type=device_type,
        hostname=hostname,
        date=date,
        issues=issues,
        vulns=vulns
    )

    html_file.write(text)
    html_file.close()


def _generate_json_report(filename: str, issues: dict, vulns: array, data: dict) -> None:
    json_file = open(filename, "w")

    device_type = data["device-type"]
    hostname = data["hostname"]
    date = datetime.datetime.now()

    data = {}
    data["device-type"] = device_type
    data["hostname"] = hostname
    data["date"] = date

    vulns_dict = {}
    vulns_dict["data"] = data
    vulns_dict["vulnerabilities"] = vulns
    vulns_dict["security-audit"] = issues
    json_text = json.dumps(
        vulns_dict,
        indent=4,
        sort_keys=True,
        default=lambda x: x.__str__() if isinstance(
            x, datetime.datetime) else x.__dict__()
    )

    json_file.write(json_text)
    json_file.close()
