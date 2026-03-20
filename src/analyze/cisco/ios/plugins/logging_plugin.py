# flake8: noqa
# CIS Cisco IOS Benchmark references:
#   3.1.1  - Ensure 'logging on' is configured
#   3.1.2  - Ensure 'logging buffered' is set with level 'informational' or lower
#   3.1.3  - Ensure 'logging host' (remote syslog) is configured
#   3.1.4  - Ensure 'logging source-interface' is set
#   3.1.5  - Ensure 'service timestamps log datetime' is configured
#   3.1.6  - Ensure 'logging userinfo' is enabled
#   3.1.7  - Ensure 'logging console critical' (or lower) is set
#   3.1.8  - Ensure 'logging trap informational' (or lower) is set
#   3.2.1  - Ensure 'archive log config' is enabled for configuration change audit

from ..core.base_plugin import BasePlugin
from ....common.issue.issue import Issue


class PluginLogging(BasePlugin):

    def __init__(self):
        super().__init__()

    def name(self):
        return "Logging and Auditing"

    # CIS 3.1.1 - Ensure 'logging on' is configured
    def _is_logging_on(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        if len(parser.find_objects(r"^no logging on")) > 0:
            return False
        return True  # 'logging on' is the IOS default

    def get_logging_on(self, filename: str):
        if not self._is_logging_on(filename):
            return Issue(
                "Logging explicitly disabled",
                "The 'no logging on' command is present. Logging has been explicitly disabled, preventing any log messages from being generated or forwarded.",  # noqa: E501
                "With logging disabled, there is no audit trail for authentication failures, configuration changes, or access attempts. Incident detection and post-incident forensics become impossible.",  # noqa: E501
                "Disabling logging masks attacker activity. An attacker who has already gained access may disable logging to cover their tracks.",  # noqa: E501
                "Re-enable logging:\n\n```\nlogging on\n```",  # noqa: E501
                "CIS 3.1.1"
            )
        return None

    # CIS 3.1.2 - Ensure 'logging buffered' is set at level informational or lower
    _LOG_LEVELS = {"emergencies": 0, "alerts": 1, "critical": 2, "errors": 3,
                   "warnings": 4, "notifications": 5, "informational": 6, "debugging": 7}

    def _get_buffered_level(self, filename: str) -> str:
        parser = self.parse_cisco_ios_config_file(filename)
        objs = parser.find_objects(r"^logging buffered")
        if objs:
            level = objs[0].re_match_typed(r'^logging buffered\s+(?:\d+\s+)?(\S+)$', default='')
            return level.lower()
        return ""

    def get_logging_buffered(self, filename: str):
        level = self._get_buffered_level(filename)
        if not level:
            return Issue(
                "Buffered logging not configured",
                "Buffered logging is not configured. Without a local log buffer, recent events cannot be inspected from the device CLI.",  # noqa: E501
                "If remote syslog connectivity is lost, absence of a local buffer means all recent log data is unrecoverable.",  # noqa: E501
                "This is a configuration gap rather than a directly exploitable vulnerability.",  # noqa: E501
                "Configure buffered logging at informational level or below:\n\n```\nlogging buffered 16384 informational\n```",  # noqa: E501
                "CIS 3.1.2"
            )
        numeric = self._LOG_LEVELS.get(level, 6)
        if numeric < self._LOG_LEVELS["informational"]:
            return Issue(
                "Buffered logging level too restrictive",
                f"Buffered logging is set to '{level}' (severity {numeric}), which suppresses informational and lower-severity messages that are important for security monitoring.",  # noqa: E501
                "A restrictive log level hides important security events such as failed logins, ACL hits, and state changes, reducing incident detection capability.",  # noqa: E501
                "This is a configuration gap that reduces security visibility.",  # noqa: E501
                "Lower the buffered log level to `informational` or below:\n\n```\nlogging buffered 16384 informational\n```",  # noqa: E501
                "CIS 3.1.2"
            )
        return None

    # CIS 3.1.3 - Ensure a remote syslog server is configured
    def _has_logging_host(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return (
            len(parser.find_objects(r"^logging host")) > 0
            or len(parser.find_objects(r"^logging \d+\.\d+\.\d+\.\d+")) > 0
        )

    def get_logging_host(self, filename: str):
        if not self._has_logging_host(filename):
            return Issue(
                "Remote syslog server not configured",
                "No remote syslog server is configured. Local-only logs can be erased by an attacker with device access, and are lost on device reload.",  # noqa: E501
                "Without centralised log storage, an attacker who compromises the device can delete all evidence of their activity by clearing the local buffer and rebooting.",  # noqa: E501
                "Clearing local logs requires only privileged CLI access, which an attacker who has already compromised the device would possess.",  # noqa: E501
                "Configure at least one remote syslog server and set a minimum trap level:\n\n```\nlogging host <ip>\nlogging trap informational\n```",  # noqa: E501
                "CIS 3.1.3"
            )
        return None

    # CIS 3.1.4 - Ensure 'logging source-interface' is configured
    def _has_logging_source_interface(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^logging source-interface")) > 0

    def get_logging_source_interface(self, filename: str):
        if not self._has_logging_source_interface(filename):
            return Issue(
                "Logging source-interface not configured",
                "No 'logging source-interface' is configured. Syslog packets may originate from different IP addresses depending on routing, complicating log-management rules.",  # noqa: E501
                "Without a consistent source address, syslog filtering and alerting at the collector may fail or produce duplicate/missing records, degrading security monitoring accuracy.",  # noqa: E501
                "This is a configuration reliability concern rather than a directly exploitable vulnerability.",  # noqa: E501
                "Bind syslog to a stable management interface:\n\n```\nlogging source-interface Loopback0\n```",  # noqa: E501
                "CIS 3.1.4"
            )
        return None

    # CIS 3.1.5 - Ensure 'service timestamps log' is configured
    def _has_log_timestamps(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^service timestamps log")) > 0

    def get_logging_timestamps(self, filename: str):
        if not self._has_log_timestamps(filename):
            return Issue(
                "Log timestamps not configured",
                "'service timestamps log' is not configured. Log messages do not include date and time, making event correlation and incident investigation impractical.",  # noqa: E501
                "Log entries without timestamps cannot be placed in a timeline or correlated with events on other systems, severely hampering forensic analysis.",  # noqa: E501
                "This is a configuration gap that eliminates the forensic value of log data.",  # noqa: E501
                "Enable log timestamps with full date, time, and timezone:\n\n```\nservice timestamps log datetime msec show-timezone localtime\n```",  # noqa: E501
                "CIS 3.1.5"
            )
        return None

    # CIS 3.1.6 - Ensure 'logging userinfo' is enabled
    def _has_logging_userinfo(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        return len(parser.find_objects(r"^logging userinfo")) > 0

    def get_logging_userinfo(self, filename: str):
        if not self._has_logging_userinfo(filename):
            return Issue(
                "User-level event logging not enabled",
                "'logging userinfo' is not configured. User-level events such as privilege escalation and authenticated line access may not appear in the log.",  # noqa: E501
                "Without user-level logging, privilege escalation activities and management access events may go unrecorded, hindering accountability and incident response.",  # noqa: E501
                "This is a monitoring gap rather than a directly exploitable vulnerability.",  # noqa: E501
                "Enable user-level event logging:\n\n```\nlogging userinfo\n```",  # noqa: E501
                "CIS 3.1.6"
            )
        return None

    # CIS 3.1.7 - Ensure 'logging console critical' or lower is set
    def _get_console_log_level(self, filename: str) -> str:
        parser = self.parse_cisco_ios_config_file(filename)
        objs = parser.find_objects(r"^logging console")
        if objs:
            level = objs[0].re_match_typed(r'^logging console\s+(\S+)', default='')
            return level.lower()
        return ""

    def get_logging_console(self, filename: str):
        level = self._get_console_log_level(filename)
        if not level:
            return Issue(
                "Console logging level not explicitly configured",
                "No 'logging console' level is set. By default, IOS logs all messages (debugging level) to the console, which can overwhelm console sessions during high-event periods.",  # noqa: E501
                "Without a configured console logging level, console output may be flooded with debug-level messages, obscuring important security events and degrading administrator experience during incidents.",  # noqa: E501
                "This is an operational concern rather than a directly exploitable vulnerability.",  # noqa: E501
                "Restrict console logging to critical events only:\n\n```\nlogging console critical\n```",  # noqa: E501
                "CIS 3.1.7"
            )
        numeric = self._LOG_LEVELS.get(level, -1)
        # Flag if level is more verbose than 'critical' (i.e., errors/warnings/informational/debugging)
        if numeric > self._LOG_LEVELS["critical"]:
            return Issue(
                "Console logging level too verbose",
                f"Console logging is set to '{level}' (severity {numeric}). A verbose console logging level can flood the console during high-event periods, hindering administration.",  # noqa: E501
                "Verbose console logging can overwhelm the console during security incidents, making it difficult for administrators to issue commands and respond effectively.",  # noqa: E501
                "This is an operational availability concern rather than a directly exploitable vulnerability.",  # noqa: E501
                "Restrict console logging to critical events only:\n\n```\nlogging console critical\n```",  # noqa: E501
                "CIS 3.1.7"
            )
        return None

    # CIS 3.1.8 - Ensure 'logging trap informational' or lower is set
    def _get_trap_log_level(self, filename: str) -> str:
        parser = self.parse_cisco_ios_config_file(filename)
        objs = parser.find_objects(r"^logging trap")
        if objs:
            level = objs[0].re_match_typed(r'^logging trap\s+(\S+)', default='')
            return level.lower()
        return ""

    def get_logging_trap(self, filename: str):
        level = self._get_trap_log_level(filename)
        if not level:
            return Issue(
                "Logging trap level (remote syslog severity) not configured",
                "No 'logging trap' level is configured. Without it, the level of messages forwarded to remote syslog servers depends on the IOS default, which may be informational but is not explicitly enforced.",  # noqa: E501
                "Without an explicit trap level, the categories of events forwarded to SIEM/syslog may silently change across IOS upgrades or reloads, creating unpredictable gaps in centralized monitoring.",  # noqa: E501
                "This is a configuration reliability concern that can cause undetected monitoring gaps.",  # noqa: E501
                "Explicitly set the syslog trap level to `informational` or lower:\n\n```\nlogging trap informational\n```",  # noqa: E501
                "CIS 3.1.8"
            )
        numeric = self._LOG_LEVELS.get(level, 6)
        if numeric < self._LOG_LEVELS["informational"]:
            return Issue(
                "Logging trap level too restrictive",
                f"The syslog trap level is set to '{level}' (severity {numeric}), which suppresses informational messages sent to the remote syslog server.",  # noqa: E501
                "A restrictive trap level means that important security events (authentication failures, ACL hits, state changes) may not reach the centralized SIEM, creating blind spots in security monitoring.",  # noqa: E501
                "This is a monitoring gap that prevents timely detection of security events.",  # noqa: E501
                "Lower the syslog trap level to include informational messages:\n\n```\nlogging trap informational\n```",  # noqa: E501
                "CIS 3.1.8"
            )
        return None

    # CIS 3.2.1 - Ensure 'archive log config' is enabled
    def _has_archive_log_config(self, filename: str) -> bool:
        parser = self.parse_cisco_ios_config_file(filename)
        archive_objs = parser.find_objects(r"^archive")
        if not archive_objs:
            return False
        for archive in archive_objs:
            if archive.re_search_children(r"log config"):
                return True
        return False

    def get_archive_log_config(self, filename: str):
        if not self._has_archive_log_config(filename):
            return Issue(
                "Configuration change logging (archive log config) not enabled",
                "The 'archive log config' feature is not enabled. Without it, configuration changes are not logged with the identity of the user who made them.",  # noqa: E501
                "Without configuration change audit logging, unauthorised or accidental changes to the device configuration cannot be detected or attributed, undermining change management and security controls.",  # noqa: E501
                "An attacker with privileged access who modifies the configuration will leave no audit trail if this feature is absent.",  # noqa: E501
                "Enable configuration change logging via the archive feature:\n\n```\narchive\n log config\n  logging enable\n  notify syslog contenttype plaintext\n  hidekeys\n```",  # noqa: E501
                "CIS 3.2.1"
            )
        return None

    def analyze(self, config_file) -> None:
        issues = []

        issues.append(self.get_logging_on(config_file))
        issues.append(self.get_logging_buffered(config_file))
        issues.append(self.get_logging_host(config_file))
        issues.append(self.get_logging_source_interface(config_file))
        issues.append(self.get_logging_timestamps(config_file))
        issues.append(self.get_logging_userinfo(config_file))
        issues.append(self.get_logging_console(config_file))
        issues.append(self.get_logging_trap(config_file))
        issues.append(self.get_archive_log_config(config_file))

        for issue in issues:
            if issue is not None:
                self.add_issue(issue)
