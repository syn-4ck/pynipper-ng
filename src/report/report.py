from jinja2 import Environment, PackageLoader, select_autoescape
import datetime
import array
import json


def generate_html_report(filename: str, issues: dict, vulns: array) -> None:
    html_file = open(filename, "w")

    date = datetime.datetime.now().date()

    env = Environment(
        loader=PackageLoader('report', 'templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )
    TEMPLATE_FILE = "html_template.html"
    template = env.get_template(TEMPLATE_FILE)

    text = template.render(
        device_type="Cisco Router",
        hostname="retail",
        date=date,
        issues=issues,
        vulns=vulns
    )

    html_file.write(text)
    html_file.close()


def generate_json_report(filename: str, issues: dict, vulns: array) -> None:
    json_file = open(filename, "w")

    device_type = "Cisco Router"
    hostname = "retail"

    data = {}
    data["Device Type"] = device_type
    data["Hostname"] = hostname

    vulns_dict = {}
    vulns_dict["Data"] = data
    vulns_dict["Vulnerabilities"] = vulns
    vulns_dict["Security audit"] = issues
    text = json.dumps(vulns_dict, indent=4, sort_keys=True,
                      default=lambda x: x.__dict__)

    json_file.write(text)
    json_file.close()
