
from ..core.base_plugin import GenericPlugin
from ....common.issue.issue import Issue


class AAAPlugin(GenericPlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Local Authentication, Authorization and Accounting (AAA)"

    def _has_aaa_new_model(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        new_model = parser.find_objects("aaa new-model")
        return len(new_model) > 0
    
    def has_aaa_new_model(self, config):
        if not self._has_aaa_new_model(config):
            return Issue(
                "AAA new-model",
                "The aaa new-model command should be enabled to enforce AAA security.",
                "Implementing Cisco AAA is significantly disruptive as former access methods are immediately disabled. This can result in a loss of access to the device if the configuration is not correct.", # noqa: E501
                "Before implementing Cisco AAA, the organization should carefully review and plan their authentication criteria (logins & passwords, challenges & responses, and token technologies), authorization methods, and accounting requirements", # noqa: E501
                "Globally enable authentication, authorization and accounting (AAA) using the new-model command: aaa new-model",
                0
            )

    def _has_aaa_authentication_login(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        aaa_authentication_login = parser.find_objects("aaa authentication login")
        if (len(aaa_authentication_login) > 0):
            return True
        else:
            return False

    def has_aaa_authentication_login(self, config):
        if not self._has_aaa_authentication_login(config):
            return Issue(
                "AAA authentication login",
                "The aaa authentication login command should be enabled to enforce AAA security.",
                "Implementing Cisco AAA is significantly disruptive as former access methods are immediately disabled. This can result in a loss of access to the device if the configuration is not correct.", # noqa: E501
                "Before implementing Cisco AAA, the organization should carefully review and plan their authentication criteria (logins & passwords, challenges & responses, and token technologies), authorization methods, and accounting requirements", # noqa: E501
                "Configure AAA authentication for login using the following command: aaa authentication login {default | aaa_list_name} [passwd-expiry] [method1] [method2]",
                0
            )

    def _has_authentication_enable_default(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        authentication_enable_default = parser.find_objects("aaa authentication enable")
        if (len(authentication_enable_default) > 0):
            return True
        else:
            return False
    
    def has_authentication_enable_default(self, config):
        if not self._has_authentication_enable_default(config):
            return Issue(
                "AAA authentication enabled by default",
                "The aaa authentication enable command should be enabled to enforce AAA security.",
                "Enabling Cisco AAA 'authentication enable' mode is significantly disruptive as former access methods are immediately disabled.", # noqa: E501
                "Bbefore enabling 'aaa authentication enable default' mode, the organization should plan and implement authentication logins and passwords, challenges and responses, and token technologies.", # noqa: E501
                "Configure AAA authentication method(s) for enable authentication: aaa authentication enable default [method1] enable",
                0
            )

    def _has_login_authentication_line_console_0(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        login_authentication_line_console_0 = parser.find_objects("login authentication")
        if (len(login_authentication_line_console_0) > 0):
            return True
        else:
            return False
    
    def has_login_authentication_line_console_0(self, config):
        if not self._has_login_authentication_line_console_0(config):
            return Issue(
                "AAA authentication login console 0",
                "The login authentication console 0 command should be enabled to enforce AAA security.",
                "Enabling Cisco AAA 'line login' is significantly disruptive as former access methods are immediately disabled.", # noqa: E501
                "Bbefore enabling Cisco AAA 'line login', the organization should plan and implement authentication logins and passwords, challenges and responses, and token technologies.", # noqa: E501
                "Configure management lines to require login using the default or a named AAA authentication list. This configuration must be set individually for all line types: line console 0 & login authentication {default | aaa_list_name}",
                0
            )


    def analyze(self, config_file):
        issues = []

        issues.append(self.has_aaa_new_model(config_file))
        issues.append(self.has_aaa_authentication_login(config_file))
        issues.append(self.has_authentication_enable_default(config_file))
        issues.append(self.has_login_authentication_line_console_0(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
