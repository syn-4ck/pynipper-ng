from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup
import markdown as _md
import re
import os
import datetime
import array
import json

from .common.types import ReportType

# ---------------------------------------------------------------------------
# Auto-Markdown helpers for Cisco IOS issue content
# ---------------------------------------------------------------------------

# Regex that identifies the start of a Cisco IOS command (used for inline
# code detection and colon-command detection).
_CISCO_CMD_START = re.compile(
    r'^(?:no\s+|ip\s+|aaa\s+|snmp-server\s+|ntp\s+|logging\s+|service\s+|'
    r'transport\s+|exec-timeout\s*\d|access-class\s+|access-list\s+|login\s+|'
    r'security\s+|enable\s+|archive(?:\s|$)|control-plane(?:\s|$)|line\s+|'
    r'interface\s+|router\s+|neighbor\s+|version\s+\d|area\s+|'
    r'management-interface\s+|service-policy\s+|ip\s+rip\s+|ip\s+ospf\s+|'
    r'ip\s+authentication\s+)',
    re.I,
)

# Matches ': command' where command starts with a known IOS keyword (≤ 70 chars,
# stops at '.', ',' or start of a new capitalised sentence).
_COLON_CMD_RE = re.compile(
    r':\s+'
    r'('
    r'(?:no\s+|ip\s+|aaa\s+|snmp-server\s+|ntp\s+|logging\s+|service\s+|'
    r'transport\s+|exec-timeout\s*\d|access-class\s+|access-list\s+|login\s+|'
    r'security\s+|enable\s+|archive(?:\s|$)|control-plane(?:\s|$)|line\s+|'
    r'interface\s+|version\s+\d|router\s+|neighbor\s+|area\s+)'
    r'[^\.,\n]{3,70}'
    r')'
    r'(?=[.,]|\s+[A-Z][a-z]|$)',
    re.I | re.M,
)

# Key network-security terms to bold automatically.
_BOLD_TERMS_RE = re.compile(
    r'\b(RADIUS|TACACS\+?|SNMPv[123v]+|TLS\s*[\d.]+|MD5|SHA-?256|BGP|OSPF|'
    r'EIGRP|RIPv?2?|CoPP|MPP|AAA)\b'
)


def _auto_md_cisco(text: str) -> str:
    """Pre-process plain-text issue content to add lightweight Markdown."""
    # 1. 'single-quoted Cisco command' → `inline code`
    def _quote_to_code(m: re.Match) -> str:
        cmd = m.group(1)
        return f'`{cmd}`' if _CISCO_CMD_START.match(cmd) else m.group(0)

    text = re.sub(r"'([^'\n]{5,80})'", _quote_to_code, text)

    # 2. Description: command → Description: `command`
    text = _COLON_CMD_RE.sub(lambda m: f': `{m.group(1)}`', text)

    # 3. Bold well-known security protocol/tech abbreviations
    text = _BOLD_TERMS_RE.sub(r'**\1**', text)

    return text


def _render_md(text: str) -> Markup:
    """Convert Issue content (plain text or Markdown) to safe HTML."""
    text = _auto_md_cisco(str(text))
    return Markup(_md.markdown(text, extensions=['nl2br']))

TEMPLATE_FILE = "html_template.html"


def generate_report(output_type, output_filename, issues, vulns_array_sorted, passwords, data):
    if output_type == ReportType._member_names_[0]:
        _generate_html_report(output_filename,
                              issues, vulns_array_sorted, passwords, data)
        print(f"Generated new HTML report file in {output_filename}")
    elif output_type == ReportType._member_names_[1]:
        _generate_json_report(output_filename,
                              issues, vulns_array_sorted, passwords, data)
        print(f"Generated new JSON report file in {output_filename}")
    else:
        print("Not a valid file format")


def _generate_html_report(filename: str, issues: dict, vulns: array, passwords: list, data: dict) -> None:
    html_file = open(filename, "w", encoding="utf8")

    date = datetime.datetime.now().date()
    device_type = data["device-type"]
    hostname = data["hostname"]

    template_loader = FileSystemLoader(os.path.dirname(
        os.path.abspath(__file__)) + "/templates")

    env = Environment(
        loader=template_loader,
        autoescape=select_autoescape(['html', 'xml'])
    )
    env.filters['md'] = _render_md

    template = env.get_template(TEMPLATE_FILE)

    text = template.render(
        device_type=device_type,
        hostname=hostname,
        date=date,
        issues=issues,
        vulns=vulns,
        exposed_passwords=passwords
    )

    html_file.write(text)
    html_file.close()


def _generate_json_report(filename: str, issues: dict, vulns: array, passwords: list, data: dict) -> None:
    json_file = open(filename, "w", encoding="utf8")

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
    vulns_dict["exposed-passwords-detected"] = passwords
    json_text = json.dumps(
        vulns_dict,
        indent=4,
        sort_keys=True,
        default=lambda x: x.__str__() if isinstance(
            x, datetime.datetime) else x.__dict__()
    )

    json_file.write(json_text)
    json_file.close()
