# flake8: noqa

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue

class PluginTelnet(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Telnet configuration"

    def _get_cisco_ios_telnet(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        transport_disable = parser.find_objects("transport input none")
        ssh_enable = parser.find_objects("transport input ssh")
        telnet_disable = parser.find_objects("no transport input telnet")
        if (len(transport_disable) > 0 or len(ssh_enable) > 0 or len(telnet_disable) > 0):  # noqa: E501
            return False
        else:
            return True
    
    def get_telnet_configuration(self, filename: str):
        if (self._get_cisco_ios_telnet(filename)):
            return Issue(
                "Telnet",
                "Telnet is widely used to provide remote command-based access to a variety of devices and is commonly used on network devices for remote administration. However, Telnet is a clear-text protocol and is vulnerable to various packet capture techniques.",  # noqa: E501
                "An attacker who was able to monitor network traffic could capture sensitive information or authentication credentials.",  # noqa: E501
                "Network packet and password sniffing tools are widely available on the Internet and some of the tools are specifically designed to capture clear-text protocol authentication credentials. However, in a switched environment an attacker may not be able to capture network traffic destined for other devices without employing an attack such as Address Resolution Protocol (ARP) spoofing.",
                "Nipper recommends that, if possible, Telnet be disabled. If remote administrative access to the device is required, Nipper recommends that SSH be configured. The Telnet service can be disabled on individual lines with the following command: transport input none. The following Cisco IOS command can be used to disable Telnet on individual lines, but enable SSH: transport input ssh"  # noqa: E501
            )
        return None
        
    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_telnet_configuration(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)