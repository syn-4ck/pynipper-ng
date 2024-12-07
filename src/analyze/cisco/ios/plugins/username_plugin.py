# flake8: noqa

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue

class PluginUsername(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Username credentials"
    
    def _has_password_encryption(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        no_pas_enc = parser.find_objects("no service password-encryption")
        if (len(no_pas_enc) > 0):
            return False
        else:
            pas_enc = parser.find_objects("service password-encryption")
            pas_enc_aes = parser.find_objects("password encryption aes")
            if (len(pas_enc) > 0 or len(pas_enc_aes) > 0):
                return True
        return False
    
    def get_users_without_password_encryption(self, filename: str):
        if (not self._has_password_encryption(filename)):
            return Issue(
                "Service Password Encryption",
                "Cisco service passwords are stored by default in their clear-text form rather than being encrypted. However, it is possible to have these passwords stored using the reversible Cisco encryption.",  # noqa: E501
                "If a malicious user were to see a Cisco configuration that contained clear-text passwords, they could use the passwords to access the device. However, an attacker who had access to a Cisco configuration file would easily be able to reverse the passwords.",  # noqa: E501
                "Encryption provide a greater level of security than clear-text passwords.",
                "The Cisco password encryption service be enabled. The Cisco password encryption service can be started with the following Cisco IOS commands: service password-encryption or password encryption aes"  # noqa: E501
            )
        return None
    
    def _has_cisco_password_0(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        password0_list= parser.find_objects(r'username .+ password 0 .+')
        if (len(password0_list) > 0):
            return True
        else:
            return False
    
    def get_users_with_password_0(self, filename: str):
        if (self._has_cisco_password_0(filename)):
            return Issue(
                "Cisco type-0 passwords",
                "Cisco passwords are stored in their clear-text form rather than being encrypted when we use the type 0. However, it is possible to have these passwords stored using the reversible Cisco encryption.",
                "If a malicious user were to see a Cisco configuration that contained clear-text passwords, they could use the passwords to access the device. However, an attacker who had access to a Cisco configuration file would easily be able to reverse the passwords.",  # noqa: E501
                "Encryption provide a greater level of security than clear-text passwords.",
                "The Cisco user passwords should be type 6, 8 or 9, and you can use the following Cisco IOS commands: username <username> password [6|8|9] <encrypted-password>"  # noqa: E501
            )
        return None
    
    def _has_cisco_password_7(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        password7_list= parser.find_objects(r'username .+ password 7 .+')
        if (len(password7_list) > 0):
            return True
        else:
            return False
    
    def get_users_with_password_7(self, filename: str):
        if (self._has_cisco_password_7(filename)):
            return Issue(
                "Cisco type-7 passwords",
                "Cisco passwords are stored using an old and broken algorithm when we use the type 7 (Vigenere cypher). However, it is possible to have these passwords stored using stronger algorithms, like AES.",  # noqa: E501
                "If a malicious user were to see a Cisco configuration that contained Vigenere encrypted passwords, they could crack the passwords to access the device. However, an attacker who had access to a Cisco configuration file would easily be able to decrypt the passwords.",  # noqa: E501
                "Newer and strong encryption provide a greater level of security than Vigenere cyphered passwords.",
                "The Cisco user passwords should be type 6, 8 or 9, and you can use the following Cisco IOS commands: username <username> password [6|8|9] <encrypted-password>"  # noqa: E501
            )
        return None
    
    def _has_cisco_password_5(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        password5_list= parser.find_objects(r'username .+ password 5 .+')
        if (len(password5_list) > 0):
            return True
        else:
            return False
    
    def get_users_with_password_5(self, filename: str):
        if (self._has_cisco_password_5(filename)):
            return Issue(
                "Cisco type-5 passwords",
                "Cisco passwords are stored using an old and broken algorithm when we use the type 5 (salted MD5 hashing). However, it is possible to have these passwords stored using stronger algorithms, like AES.",  # noqa: E501
                "If a malicious user were to see a Cisco configuration that contained MD5 hashed passwords, they could crack the passwords to access the device using HashCat. However, an attacker who had access to a Cisco configuration file would easily be able to get the passwords.",  # noqa: E501
                "Newer and strong encryption provide a greater level of security than salted MD5 hashed passwords.",
                "The Cisco user passwords should be type 6, 8 or 9, and you can use the following Cisco IOS commands: username <username> password [6|8|9] <encrypted-password>"  # noqa: E501
            )
        return None
    
    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_users_without_password_encryption(config_file))
        issues.append(self.get_users_with_password_0(config_file))
        issues.append(self.get_users_with_password_7(config_file))
        issues.append(self.get_users_with_password_5(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)