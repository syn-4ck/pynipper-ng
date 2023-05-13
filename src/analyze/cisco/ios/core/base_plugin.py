from ciscoconfparse import CiscoConfParse

from ....common.base_plugin.base_plugin import GenericPlugin


class BasePlugin(GenericPlugin):

    def parse_cisco_ios_config_file(self, filename: str) -> CiscoConfParse:
        return CiscoConfParse(filename, syntax='ios')
