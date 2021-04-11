import array

from .ios_process.cisco_ios_issue import CiscoIOSIssue
from .ios_process.modules.ssh_module import get_ssh_missconfigurations
from .ios_process.modules.http_module import get_http_missconfigurations

def process_cisco_ios_conf(filename: str) -> dict:

    issues = {}
    index = 2

    # SSH issues
    ssh_issues = get_ssh_missconfigurations(filename)
    subindex = 0
    for issue in ssh_issues:
        title = "2." + str(index) + "." + str(subindex) + ". " + issue.title
        issues[title] = issue
        subindex += 1
    index += 1

    # HTTP issues
    http_issues = get_http_missconfigurations(filename)
    subindex = 0
    for issue in http_issues:
        title = "2." + str(index) + "." + str(subindex) + ". " + issue.title
        issues[title] = issue
        subindex += 1
    index += 1

    return issues

