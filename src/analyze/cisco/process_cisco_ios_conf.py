
import array
from .cisco_ios_process.modules.ssh_module import get_ssh_missconfigurations
from .cisco_ios_process.modules.http_module import get_http_missconfigurations


def process_cisco_ios_conf(filename: str) -> dict:

    issues = {}
    index = 2

    # SSH issues
    ssh_issues = get_ssh_missconfigurations(filename)
    index = _generate_section(issues, ssh_issues, index)

    # HTTP issues
    http_issues = get_http_missconfigurations(filename)
    index = _generate_section(issues, http_issues, index)

    return issues

def _generate_section(issues: dict, added_issues: array, index: int) -> int:
    subindex = 0
    for issue in added_issues:
        title = "2." + str(index) + "." + str(subindex) + ". " + issue.title
        issues[title] = issue
        subindex += 1
    return index + 1
