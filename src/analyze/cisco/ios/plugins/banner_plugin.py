# flake8: noqa

from ..core.base_plugin import GenericPlugin
from ....common.issue.issue import Issue

class PluginBanner(GenericPlugin):
    
    def __init__(self):
        super().__init__()

    def name(self):
        return "Banner"
    
    def _has_banner_login_defined(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        banner_text_defined = parser.find_objects("banner login ")
        if (len(banner_text_defined) > 0):
            return True
        else:
            return False
    
    def get_banner_login_text(self, filename: str):
        if not self._has_banner_login_defined(filename):
            return Issue(
                "Banner Login",
                "Network banners are electronic messages that provide notice of legal rights to users of computer networks. When a user connects to the router, the message-of-the-day (MOTD) banner (if configured) appears first, followed by the login banner and prompts. After the user successfully logs into the router, the EXEC banner or incoming banner will be displayed, depending on the type of connection",  # noqa: E501
                "Organizations should provide appropriate legal notice(s) and warning(s) to persons accessing their networks by using a 'banner-text' for the banner login command",  # noqa: E501
                "Not have a Login Banner with law impact is a bad practice to an organization. Users that access to the device should know the impact of their actions.",  # noqa: E501
                "Configure the device so a login banner presented to a user attempting to access the device: banner login <char>"  # noqa: E501
            )
    
    def _has_banner_motd_defined(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        banner_text_defined = parser.find_objects("banner motd ")
        if (len(banner_text_defined) > 0):
            return True
        else:
            return False
    
    def get_banner_motd_text(self, filename: str):
        if not self._has_banner_motd_defined(filename):
            return Issue(
                "Banner MOTD",
                "Network banners are electronic messages that provide notice to users of computer networks. The MOTD banner is displayed to all terminals connected and is useful for sending messages that affect all users (such as impending system shutdowns).",  # noqa: E501
                "Organizations should provide appropriate legal notice(s) and warning(s) to persons accessing their networks by using a 'banner-text' for the banner motd command.",  # noqa: E501
                "Not have a MOTD Banner with law impact is a bad practice to an organization. Users that access to the device should know the impact of their actions.",  # noqa: E501
                "Configure the message of the day (MOTD) banner presented when a user first connects to the device: banner motd <char>"  # noqa: E501
            )

    def _has_banner_webauth_defined(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        banner_text_defined = parser.find_objects("ip admission auth-proxy-banner http ")
        if (len(banner_text_defined) > 0):
            return True
        else:
            return False
    
    def get_banner_webauth_text(self, filename: str):
        if not self._has_banner_webauth_defined(filename):
            return Issue(
                "Banner WebAuth",
                "Network banners are electronic messages that provide notice to users of computer networks. The WebAuth banner is displayed to all terminals connected and is useful for sending messages that affect all users connected by HTTP.",  # noqa: E501
                "Organizations should provide appropriate legal notice(s) and warning(s) to persons accessing their networks by using a 'banner-text' for the banner webauth command.",  # noqa: E501
                "Not have a MOTD Banner with law impact is a bad practice to an organization. Users that access to the device by HTTP should know the impact of their actions.",  # noqa: E501
                "Configure the message of the day (MOTD) WebAuth banner presented when a user first connects to the device: ip admission auth-proxy-banner http <banner-text | filepath>"  # noqa: E501
            )
    
    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_banner_login_text(config_file))
        issues.append(self.get_banner_motd_text(config_file))
        issues.append(self.get_banner_webauth_text(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)