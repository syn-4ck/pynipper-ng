from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import datetime
import array
import json

TEMPLATE_FILE = "html_template.html"


def generate_html_report(filename: str, issues: dict, vulns: array, data: dict) -> None:
    html_file = open(filename, "w")

    date = datetime.datetime.now().date()
    device_type = data["device-type"]
    hostname = data["hostname"]

    templateLoader = FileSystemLoader(os.path.dirname(os.path.abspath(__file__)) + "/templates")

    env = Environment(
        loader=templateLoader,
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


def generate_json_report(filename: str, issues: dict, vulns: array, data: dict) -> None:
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
        default=lambda x: x.__str__() if isinstance(x, datetime.datetime) else x.__dict__()
    )

    json_file.write(json_text)
    json_file.close()
