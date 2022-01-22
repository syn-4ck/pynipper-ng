import array
from abc import abstractmethod

from ciscoconfparse import CiscoConfParse

from ..issue.cisco_ios_issue import CiscoIOSIssue


class GenericPlugin(object):

    def __init__(self):
        self.issues = []  # A CiscoIOSIssue list with the reported issues

    def parse_cisco_ios_config_file(self, filename: str) -> CiscoConfParse:
        return CiscoConfParse(filename, syntax='ios')

    def get_issues(self) -> array:
        return self.issues

    def add_issue(self, issue: CiscoIOSIssue):
        self.issues.append(issue)

    # The plugins should implement the analyze() method
    # The developer should call add_issue(...) method in to add a issue
    @abstractmethod
    def analyze(self, config_file) -> None:
        pass
