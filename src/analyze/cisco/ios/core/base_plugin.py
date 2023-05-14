from ciscoconfparse import CiscoConfParse

from ....common.base_plugin.base_plugin import GenericPlugin


class BasePlugin(GenericPlugin):

    def __init__(self):
        super().__init__()

    def parse_cisco_ios_config_file(self, filename: str) -> CiscoConfParse:
        return CiscoConfParse(filename, syntax='ios')
