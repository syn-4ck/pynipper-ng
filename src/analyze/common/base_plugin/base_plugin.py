import array
from abc import abstractmethod

from ..issue import Issue


class GenericPlugin(object):

    def __init__(self):
        self.issues = []  # A Issue list with the reported issues

    def get_issues(self) -> array:
        return self.issues

    def add_issue(self, issue: Issue):
        self.issues.append(issue)

    # The plugins should implement the analyze() method
    # The developer should call add_issue(...) method in to add a issue
    @abstractmethod
    def analyze(self, config_file) -> None:
        pass

    # The plugins should implement the name() method with the name plugin
    @abstractmethod
    def name(self) -> None:
        pass
