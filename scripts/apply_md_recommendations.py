#!/usr/bin/env python3
"""
Applies Markdown formatting to recommendation strings in key plugin files.
Converts plain-text recommendations that contain multi-step CLI commands
into properly formatted Markdown (code blocks, numbered lists).

Run from repository root:
    python3 scripts/apply_md_recommendations.py
"""

import os

PLUGIN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'src', 'analyze', 'cisco', 'ios', 'plugins'
)

# ---------------------------------------------------------------------------
# Replacement map: (plugin_file, unique_old_rec_fragment, new_rec_string)
# We only replace the recommendation field (last string before CIS arg).
# Each old fragment is long enough to be unique within the file.
# ---------------------------------------------------------------------------

REPLACEMENTS = {

    # -----------------------------------------------------------------------
    # aaa_plugin.py
    # -----------------------------------------------------------------------
    'aaa_plugin.py': [
        (
            '"Enable AAA globally: aaa new-model. Plan and configure authentication method lists before enabling to avoid loss of access.",  # noqa: E501',
            '"Enable **AAA** globally. Plan and configure authentication method lists **before** enabling to avoid locking yourself out:\\n\\n```\\naaa new-model\\n```",  # noqa: E501',
        ),
        (
            '"Configure an AAA authentication method list for login: aaa authentication login default local or aaa authentication login default group tacacs+ local.",  # noqa: E501',
            '"Configure an **AAA** authentication method list for login:\\n\\n```\\naaa authentication login default group tacacs+ local\\n```",  # noqa: E501',
        ),
        (
            '"Configure AAA enable authentication: aaa authentication enable default group tacacs+ enable.",  # noqa: E501',
            '"Configure **AAA** enable authentication:\\n\\n```\\naaa authentication enable default group tacacs+ enable\\n```",  # noqa: E501',
        ),
        (
            '"Apply a login authentication list to each management line: line console 0, login authentication default. line vty 0 4, login authentication default.",  # noqa: E501',
            '"Apply a login authentication list to all management lines:\\n\\n```\\nline console 0\\n login authentication default\\nline vty 0 4\\n login authentication default\\n```",  # noqa: E501',
        ),
        (
            '"Configure AAA authorisation for EXEC sessions: aaa authorization exec default group tacacs+ local.",  # noqa: E501',
            '"Configure **AAA** authorisation for EXEC sessions:\\n\\n```\\naaa authorization exec default group tacacs+ local\\n```",  # noqa: E501',
        ),
        (
            '"Configure AAA network authorisation: aaa authorization network default group tacacs+ local.",  # noqa: E501',
            '"Configure **AAA** network authorisation:\\n\\n```\\naaa authorization network default group tacacs+ local\\n```",  # noqa: E501',
        ),
        (
            '"Configure AAA exec accounting: aaa accounting exec default start-stop group tacacs+.",  # noqa: E501',
            '"Configure **AAA** exec accounting:\\n\\n```\\naaa accounting exec default start-stop group tacacs+\\n```",  # noqa: E501',
        ),
        (
            '"Configure AAA privilege-15 command accounting: aaa accounting commands 15 default start-stop group tacacs+.",  # noqa: E501',
            '"Configure **AAA** privilege-15 command accounting:\\n\\n```\\naaa accounting commands 15 default start-stop group tacacs+\\n```",  # noqa: E501',
        ),
        (
            '"Configure AAA connection accounting: aaa accounting connection default start-stop group tacacs+.",  # noqa: E501',
            '"Configure **AAA** connection accounting:\\n\\n```\\naaa accounting connection default start-stop group tacacs+\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # ssh_plugin.py
    # -----------------------------------------------------------------------
    'ssh_plugin.py': [
        (
            '"Disable SSHv1 and require SSHv2 only: ip ssh version 2.",  # noqa: E501',
            '"Disable SSHv1 and enforce **SSHv2** only:\\n\\n```\\nip ssh version 2\\n```",  # noqa: E501',
        ),
        (
            '"Configure a maximum of 3 SSH authentication retry attempts: ip ssh authentication-retries 3.",  # noqa: E501',
            '"Configure a maximum of 3 SSH authentication retry attempts:\\n\\n```\\nip ssh authentication-retries 3\\n```",  # noqa: E501',
        ),
        (
            '"Reduce SSH authentication retry limit to 3 or fewer: ip ssh authentication-retries 3.",  # noqa: E501',
            '"Reduce SSH authentication retry limit to 3 or fewer:\\n\\n```\\nip ssh authentication-retries 3\\n```",  # noqa: E501',
        ),
        (
            '"Configure SSH timeout to 60 seconds or less: ip ssh time-out 60.",  # noqa: E501',
            '"Configure SSH timeout to 60 seconds or less:\\n\\n```\\nip ssh time-out 60\\n```",  # noqa: E501',
        ),
        (
            '"Reduce SSH timeout to 60 seconds or less: ip ssh time-out 60.",  # noqa: E501',
            '"Reduce SSH timeout to 60 seconds or less:\\n\\n```\\nip ssh time-out 60\\n```",  # noqa: E501',
        ),
        (
            '"Bind SSH to a stable management interface: ip ssh source-interface Loopback0.",  # noqa: E501',
            '"Bind SSH to a stable management interface:\\n\\n```\\nip ssh source-interface Loopback0\\n```",  # noqa: E501',
        ),
        (
            '"Generate a 2048-bit or larger RSA key pair to support SSHv2: crypto key generate rsa modulus 2048.",  # noqa: E501',
            '"Generate a 2048-bit or larger RSA key pair to support **SSHv2**:\\n\\n```\\ncrypto key generate rsa modulus 2048\\n```",  # noqa: E501',
        ),
        (
            '"Replace the existing key with a 2048-bit or larger key: crypto key zeroize rsa, crypto key generate rsa modulus 2048.",  # noqa: E501',
            '"Replace the existing key with a 2048-bit or larger key:\\n\\n```\\ncrypto key zeroize rsa\\ncrypto key generate rsa modulus 2048\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # service_plugin.py
    # -----------------------------------------------------------------------
    'service_plugin.py': [
        (
            '"Disable PAD service: no service pad.",  # noqa: E501',
            '"Disable the PAD service:\\n\\n```\\nno service pad\\n```",  # noqa: E501',
        ),
        (
            '"Disable the UDP small servers service: no service udp-small-servers.",  # noqa: E501',
            '"Disable the UDP small servers service:\\n\\n```\\nno service udp-small-servers\\n```",  # noqa: E501',
        ),
        (
            '"Disable the TCP small servers service: no service tcp-small-servers.",  # noqa: E501',
            '"Disable the TCP small servers service:\\n\\n```\\nno service tcp-small-servers\\n```",  # noqa: E501',
        ),
        (
            '"Disable the BootP server service: no ip bootp server.",  # noqa: E501',
            '"Disable the BootP server service:\\n\\n```\\nno ip bootp server\\n```",  # noqa: E501',
        ),
        (
            '"Disable the IP Finger service: no ip finger.",  # noqa: E501',
            '"Disable the IP Finger service:\\n\\n```\\nno ip finger\\n```",  # noqa: E501',
        ),
        (
            '"Disable the IDENTD service: no ip identd.",  # noqa: E501',
            '"Disable the IDENTD service:\\n\\n```\\nno ip identd\\n```",  # noqa: E501',
        ),
        (
            '"Disable the config service: no service config.",  # noqa: E501',
            '"Disable the config service:\\n\\n```\\nno service config\\n```",  # noqa: E501',
        ),
        (
            '"Enable TCP keepalives for both inbound and outbound connections: service tcp-keepalives-in, service tcp-keepalives-out.",  # noqa: E501',
            '"Enable TCP keepalives for both inbound and outbound connections:\\n\\n```\\nservice tcp-keepalives-in\\nservice tcp-keepalives-out\\n```",  # noqa: E501',
        ),
        (
            '"Disable MOP on all interfaces: interface <type> <number>, no mop enabled.",  # noqa: E501',
            '"Disable MOP on all interfaces:\\n\\n```\\ninterface <type> <number>\\n no mop enabled\\n```",  # noqa: E501',
        ),
        (
            '"Disable gratuitous ARP on all interfaces: interface <type> <number>, no ip gratuitous-arps.",  # noqa: E501',
            '"Disable gratuitous ARP on all interfaces:\\n\\n```\\ninterface <type> <number>\\n no ip gratuitous-arps\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # password_policy_plugin.py
    # -----------------------------------------------------------------------
    'password_policy_plugin.py': [
        (
            '"Configure an enable secret using a strong hashing algorithm: enable algorithm-type sha256 secret <strong-password>. This supersedes and should replace any \'enable password\' configuration.",  # noqa: E501',
            '"Configure an enable secret using a strong hashing algorithm.\\nThis supersedes and should replace any `enable password` configuration:\\n\\n```\\nenable algorithm-type sha256 secret <strong-password>\\n```",  # noqa: E501',
        ),
        (
            '"Remove the \'enable password\' and rely exclusively on \'enable secret\': no enable password.",  # noqa: E501',
            '"Remove the `enable password` and rely exclusively on `enable secret`:\\n\\n```\\nno enable password\\n```",  # noqa: E501',
        ),
        (
            '"Replace \'enable password\' with \'enable secret\' using a strong hashing algorithm: enable algorithm-type sha256 secret <strong-password>. Remove the old enable password: no enable password.",  # noqa: E501',
            '"Replace `enable password` with `enable secret` using a strong hashing algorithm:\\n\\n```\\nenable algorithm-type sha256 secret <strong-password>\\nno enable password\\n```",  # noqa: E501',
        ),
        (
            '"Configure a minimum password length of at least 8 characters (CIS recommends 10+): security passwords min-length 10.",  # noqa: E501',
            '"Configure a minimum password length of at least 10 characters (CIS recommends 10+):\\n\\n```\\nsecurity passwords min-length 10\\n```",  # noqa: E501',
        ),
        (
            '"Increase the minimum password length to at least 10 characters: security passwords min-length 10.",  # noqa: E501',
            '"Increase the minimum password length to at least 10 characters:\\n\\n```\\nsecurity passwords min-length 10\\n```",  # noqa: E501',
        ),
        (
            '"Configure a login delay to slow brute-force attacks: login delay 4. A value between 2 and 5 seconds is recommended.",  # noqa: E501',
            '"Configure a login delay to slow brute-force attacks (2–5 seconds recommended):\\n\\n```\\nlogin delay 4\\n```",  # noqa: E501',
        ),
        (
            '"Configure a login lockout policy: login block-for 120 attempts 3 within 60. This blocks logins for 120 seconds if 3 failures occur within 60 seconds.",  # noqa: E501',
            '"Configure a login lockout policy (blocks all logins for 120 s after 3 failures within 60 s):\\n\\n```\\nlogin block-for 120 attempts 3 within 60\\n```",  # noqa: E501',
        ),
        (
            '"Enable logging of failed login attempts: login on-failure log [every <count>].",  # noqa: E501',
            '"Enable logging of failed login attempts:\\n\\n```\\nlogin on-failure log\\n```",  # noqa: E501',
        ),
        (
            '"Enable logging of successful login events: login on-success log [every <count>].",  # noqa: E501',
            '"Enable logging of successful login events:\\n\\n```\\nlogin on-success log\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # logging_plugin.py
    # -----------------------------------------------------------------------
    'logging_plugin.py': [
        (
            '"Re-enable logging: logging on.",  # noqa: E501',
            '"Re-enable logging:\\n\\n```\\nlogging on\\n```",  # noqa: E501',
        ),
        (
            '"Configure buffered logging at informational level or below: logging buffered 16384 informational.",  # noqa: E501',
            '"Configure buffered logging at informational level or below:\\n\\n```\\nlogging buffered 16384 informational\\n```",  # noqa: E501',
        ),
        (
            '"Lower the buffered log level: logging buffered 16384 informational.",  # noqa: E501',
            '"Lower the buffered log level to `informational` or below:\\n\\n```\\nlogging buffered 16384 informational\\n```",  # noqa: E501',
        ),
        (
            '"Configure at least one remote syslog server: logging host <ip>. Set a minimum trap level: logging trap informational.",  # noqa: E501',
            '"Configure at least one remote syslog server and set a minimum trap level:\\n\\n```\\nlogging host <ip>\\nlogging trap informational\\n```",  # noqa: E501',
        ),
        (
            '"Bind syslog to a stable management interface: logging source-interface Loopback0.",  # noqa: E501',
            '"Bind syslog to a stable management interface:\\n\\n```\\nlogging source-interface Loopback0\\n```",  # noqa: E501',
        ),
        (
            '"Enable log timestamps with full date/time and timezone: service timestamps log datetime msec show-timezone localtime.",  # noqa: E501',
            '"Enable log timestamps with full date, time, and timezone:\\n\\n```\\nservice timestamps log datetime msec show-timezone localtime\\n```",  # noqa: E501',
        ),
        (
            '"Enable user-level event logging: logging userinfo.",  # noqa: E501',
            '"Enable user-level event logging:\\n\\n```\\nlogging userinfo\\n```",  # noqa: E501',
        ),
        (
            '"Set the console logging level to \'critical\' or lower to limit console noise: logging console critical.",  # noqa: E501',
            '"Restrict console logging to critical events only:\\n\\n```\\nlogging console critical\\n```",  # noqa: E501',
        ),
        (
            '"Restrict console logging to critical events: logging console critical.",  # noqa: E501',
            '"Restrict console logging to critical events only:\\n\\n```\\nlogging console critical\\n```",  # noqa: E501',
        ),
        (
            '"Explicitly set the syslog trap level to informational or lower: logging trap informational.",  # noqa: E501',
            '"Explicitly set the syslog trap level to `informational` or lower:\\n\\n```\\nlogging trap informational\\n```",  # noqa: E501',
        ),
        (
            '"Lower the trap level to include informational messages: logging trap informational.",  # noqa: E501',
            '"Lower the syslog trap level to include informational messages:\\n\\n```\\nlogging trap informational\\n```",  # noqa: E501',
        ),
        (
            '"Enable configuration change logging: archive, log config, logging enable, notify syslog contenttype plaintext, hidekeys.",  # noqa: E501',
            '"Enable configuration change logging via the archive feature:\\n\\n```\\narchive\\n log config\\n  logging enable\\n  notify syslog contenttype plaintext\\n  hidekeys\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # snmp_plugin.py
    # -----------------------------------------------------------------------
    'snmp_plugin.py': [
        (
            '"Remove all SNMP community strings and replace with SNMPv3: no snmp-server community <string>. Migrate to SNMPv3 with authentication and privacy: snmp-server group <name> v3 priv, snmp-server user <user> <group> v3 auth sha <auth-pass> priv aes 128 <priv-pass>.",  # noqa: E501',
            '"Remove all SNMP community strings and migrate to **SNMPv3** with authentication and privacy:\\n\\n```\\nno snmp-server community <string>\\nsnmp-server group <name> v3 priv\\nsnmp-server user <user> <group> v3 auth sha <auth-pass> priv aes 128 <priv-pass>\\n```",  # noqa: E501',
        ),
        (
            '"Remove default community strings: no snmp-server community public, no snmp-server community private. Replace with SNMPv3 if SNMP is required.",  # noqa: E501',
            '"Remove default community strings and migrate to **SNMPv3** if SNMP is required:\\n\\n```\\nno snmp-server community public\\nno snmp-server community private\\n```",  # noqa: E501',
        ),
        (
            '"Migrate to SNMPv3 with authentication (SHA) and privacy (AES): snmp-server group <name> v3 priv, snmp-server user <user> <group> v3 auth sha <pass> priv aes 128 <priv-pass>.",  # noqa: E501',
            '"Migrate to **SNMPv3** with authentication (**SHA**) and privacy (**AES**):\\n\\n```\\nsnmp-server group <name> v3 priv\\nsnmp-server user <user> <group> v3 auth sha <pass> priv aes 128 <priv-pass>\\n```",  # noqa: E501',
        ),
        (
            '"Apply an ACL to restrict SNMP access to authorised management hosts: snmp-server community <string> RO <acl-number>.",  # noqa: E501',
            '"Apply an ACL to restrict SNMP access to authorised management hosts:\\n\\n```\\nsnmp-server community <string> RO <acl-number>\\n```",  # noqa: E501',
        ),
        (
            '"Configure SNMP trap notifications to a central monitoring host: snmp-server enable traps, snmp-server host <ip> version 3 priv <user>.",  # noqa: E501',
            '"Configure SNMP trap notifications to a central monitoring host:\\n\\n```\\nsnmp-server enable traps\\nsnmp-server host <ip> version 3 priv <user>\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # ntp_plugin.py
    # -----------------------------------------------------------------------
    'ntp_plugin.py': [
        (
            '"Configure at least two trusted NTP servers: ntp server <ip> prefer, ntp server <ip2>.",  # noqa: E501',
            '"Configure at least two trusted NTP servers:\\n\\n```\\nntp server <ip> prefer\\nntp server <ip2>\\n```",  # noqa: E501',
        ),
        (
            '"Configure NTP MD5 authentication: ntp authenticate, ntp authentication-key <id> md5 <key>, ntp trusted-key <id>. Associate the key with each NTP server: ntp server <ip> key <id>.",  # noqa: E501',
            '"Configure NTP **MD5** authentication and associate the key with each NTP server:\\n\\n```\\nntp authenticate\\nntp authentication-key <id> md5 <key>\\nntp trusted-key <id>\\nntp server <ip> key <id>\\n```",  # noqa: E501',
        ),
        (
            '"Apply an access group to control which hosts can query and synchronise with NTP: ntp access-group peer <acl-number>, ntp access-group serve-only <acl-number>.",  # noqa: E501',
            '"Apply an access group to control which hosts can query or synchronise with NTP:\\n\\n```\\nntp access-group peer <acl-number>\\nntp access-group serve-only <acl-number>\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # line_vty_plugin.py
    # -----------------------------------------------------------------------
    'line_vty_plugin.py': [
        (
            '"Apply an ACL to all VTY lines to restrict access to authorized management hosts: line vty 0 4, access-class <acl-number> in. Create an ACL that permits only management workstation IPs and denies all others.",  # noqa: E501',
            '"Apply an ACL to all VTY lines to restrict access to authorised management hosts:\\n\\n```\\naccess-list 10 permit <mgmt-host>\\naccess-list 10 deny any\\nline vty 0 4\\n access-class 10 in\\n```",  # noqa: E501',
        ),
        (
            '"Configure a non-zero exec-timeout on all VTY lines: line vty 0 4, exec-timeout 10 0. The recommended value is 10 minutes or less.",  # noqa: E501',
            '"Configure a non-zero exec-timeout on all VTY lines (10 minutes or less recommended):\\n\\n```\\nline vty 0 4\\n exec-timeout 10 0\\n```",  # noqa: E501',
        ),
        (
            '"Restrict VTY line input to SSH only: line vty 0 4, transport input ssh.",  # noqa: E501',
            '"Restrict VTY line input to SSH only:\\n\\n```\\nline vty 0 4\\n transport input ssh\\n```",  # noqa: E501',
        ),
        (
            '"Enable logging synchronous on all VTY lines: line vty 0 4, logging synchronous.",  # noqa: E501',
            '"Enable synchronous logging on all VTY lines:\\n\\n```\\nline vty 0 4\\n logging synchronous\\n```",  # noqa: E501',
        ),
        (
            '"Configure login authentication on all VTY lines using AAA or local credentials: line vty 0 4, login authentication <list-name> or login local.",  # noqa: E501',
            '"Configure login authentication on all VTY lines using **AAA** or local credentials:\\n\\n```\\nline vty 0 4\\n login authentication <list-name>\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # line_console_plugin.py
    # -----------------------------------------------------------------------
    'line_console_plugin.py': [
        (
            '"Configure an exec-timeout on the console line to automatically disconnect idle sessions: line console 0, exec-timeout 5 0. The recommended value is 5 minutes or less.",  # noqa: E501',
            '"Configure an exec-timeout on the console line to disconnect idle sessions (5 minutes or less recommended):\\n\\n```\\nline console 0\\n exec-timeout 5 0\\n```",  # noqa: E501',
        ),
        (
            '"Set a non-zero exec-timeout on the console line: line console 0, exec-timeout 5 0.",  # noqa: E501',
            '"Set a non-zero exec-timeout on the console line:\\n\\n```\\nline console 0\\n exec-timeout 5 0\\n```",  # noqa: E501',
        ),
        (
            '"Restrict inbound connections on the console line: line console 0, transport input none.",  # noqa: E501',
            '"Restrict inbound connections on the console line:\\n\\n```\\nline console 0\\n transport input none\\n```",  # noqa: E501',
        ),
        (
            '"Configure login authentication on the console line using AAA or a local password: line console 0, login authentication <list-name> or login local.",  # noqa: E501',
            '"Configure login authentication on the console line using **AAA** or a local password:\\n\\n```\\nline console 0\\n login authentication <list-name>\\n```",  # noqa: E501',
        ),
        (
            '"Enable logging synchronous on the console line: line console 0, logging synchronous.",  # noqa: E501',
            '"Enable synchronous logging on the console line:\\n\\n```\\nline console 0\\n logging synchronous\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # line_aux_plugin.py
    # -----------------------------------------------------------------------
    'line_aux_plugin.py': [
        (
            '"Disable the EXEC process on the AUX line: line aux 0, no exec. If the AUX port is not used at all, also set transport input none and exec-timeout 0 1.",  # noqa: E501',
            '"Disable the EXEC process on the AUX line. If the AUX port is unused, also restrict transport and set a short timeout:\\n\\n```\\nline aux 0\\n no exec\\n transport input none\\n exec-timeout 0 1\\n```",  # noqa: E501',
        ),
        (
            '"Set a short exec-timeout on the AUX line: line aux 0, exec-timeout 5 0.",  # noqa: E501',
            '"Set a short exec-timeout on the AUX line:\\n\\n```\\nline aux 0\\n exec-timeout 5 0\\n```",  # noqa: E501',
        ),
        (
            '"Set a non-zero exec-timeout on the AUX line: line aux 0, exec-timeout 5 0.",  # noqa: E501',
            '"Set a non-zero exec-timeout on the AUX line:\\n\\n```\\nline aux 0\\n exec-timeout 5 0\\n```",  # noqa: E501',
        ),
        (
            '"Reduce the AUX exec-timeout to 5 minutes or less: line aux 0, exec-timeout 5 0.",  # noqa: E501',
            '"Reduce the AUX exec-timeout to 5 minutes or less:\\n\\n```\\nline aux 0\\n exec-timeout 5 0\\n```",  # noqa: E501',
        ),
        (
            '"Disable all inbound transport on the AUX line: line aux 0, transport input none.",  # noqa: E501',
            '"Disable all inbound transport on the AUX line:\\n\\n```\\nline aux 0\\n transport input none\\n```",  # noqa: E501',
        ),
        (
            '"Configure login authentication on the AUX line: line aux 0, login authentication default (or login local if AAA is not in use).",  # noqa: E501',
            '"Configure login authentication on the AUX line:\\n\\n```\\nline aux 0\\n login authentication default\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # management_plane_plugin.py
    # -----------------------------------------------------------------------
    'management_plane_plugin.py': [
        (
            '"Configure Management Plane Protection to restrict management access to specific interfaces: control-plane host, management-interface <interface> allow ssh snmp https.",  # noqa: E501',
            '"Configure Management Plane Protection to restrict management access to specific interfaces:\\n\\n```\\ncontrol-plane host\\n management-interface <interface> allow ssh snmp https\\n```",  # noqa: E501',
        ),
        (
            '"Define an ACL that permits management access only from authorized hosts/networks and apply it to all VTY lines: access-list 10 permit <management-host>, line vty 0 4, access-class 10 in.",  # noqa: E501',
            '"Define an ACL that permits management access only from authorised hosts and apply it to all VTY lines:\\n\\n```\\naccess-list 10 permit <management-host>\\naccess-list 10 deny any\\nline vty 0 4\\n access-class 10 in\\n```",  # noqa: E501',
        ),
        (
            '"Configure the HTTPS server to use only TLS 1.2 or higher: ip http tls-version TLSv1.2.",  # noqa: E501',
            '"Configure the HTTPS server to use only TLS 1.2 or higher:\\n\\n```\\nip http tls-version TLSv1.2\\n```",  # noqa: E501',
        ),
        (
            '"Remove privilege 15 from local user accounts and require users to authenticate to privileged mode separately using \'enable secret\'. Use role-based access control (RBAC) and AAA to control privilege escalation.",  # noqa: E501',
            '"Remove privilege 15 from local user accounts and require separate `enable secret` authentication.\\nUse role-based access control (RBAC) and **AAA** to control privilege escalation.",  # noqa: E501',
        ),
        (
            '"Configure CoPP using Modular QoS CLI (MQC) to protect the control plane: define class-maps for known protocol types, set rate-limits on those classes, and apply the policy to the control-plane: control-plane, service-policy input <policy-name>.",  # noqa: E501',
            '"Configure **CoPP** using Modular QoS CLI (MQC) to rate-limit control-plane traffic:\\n\\n```\\ncontrol-plane\\n service-policy input <copp-policy-name>\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # routing_protocols_plugin.py
    # -----------------------------------------------------------------------
    'routing_protocols_plugin.py': [
        (
            '"Enable OSPF MD5 or SHA authentication on all OSPF interfaces: ip ospf message-digest-key <key-id> md5 <key>. Enable authentication per area in the OSPF process: area <area-id> authentication message-digest.",  # noqa: E501',
            '"Enable **OSPF** **MD5** authentication on all OSPF interfaces and areas:\\n\\n```\\ninterface <type> <number>\\n ip ospf message-digest-key <key-id> md5 <key>\\nrouter ospf <process-id>\\n area <area-id> authentication message-digest\\n```",  # noqa: E501',
        ),
        (
            '"Configure EIGRP MD5 authentication using key chains on all EIGRP-participating interfaces: ip authentication mode eigrp <as-number> md5, ip authentication key-chain eigrp <as-number> <key-chain-name>.",  # noqa: E501',
            '"Configure **EIGRP** **MD5** authentication using key chains on all EIGRP-participating interfaces:\\n\\n```\\ninterface <type> <number>\\n ip authentication mode eigrp <as-number> md5\\n ip authentication key-chain eigrp <as-number> <key-chain-name>\\n```",  # noqa: E501',
        ),
        (
            '"Configure MD5 authentication for all BGP neighbors: neighbor <ip-address> password <strong-password>. Consider using TTL security (GTSM) as an additional control: neighbor <ip-address> ttl-security hops <1-254>.",  # noqa: E501',
            '"Configure **MD5** authentication for all **BGP** neighbors, and consider adding TTL security (GTSM):\\n\\n```\\nrouter bgp <as-number>\\n neighbor <ip-address> password <strong-password>\\n neighbor <ip-address> ttl-security hops 1\\n```",  # noqa: E501',
        ),
        (
            '"Upgrade to RIPv2 and enable MD5 authentication: version 2 (under router rip), ip rip authentication mode md5, ip rip authentication key-chain <key-chain>.",  # noqa: E501',
            '"Upgrade to **RIPv2** and enable **MD5** authentication on all participating interfaces:\\n\\n```\\nrouter rip\\n version 2\\ninterface <type> <number>\\n ip rip authentication mode md5\\n ip rip authentication key-chain <key-chain-name>\\n```",  # noqa: E501',
        ),
        (
            '"Enable MD5 authentication for RIPv2 on all participating interfaces: ip rip authentication mode md5, ip rip authentication key-chain <key-chain-name>.",  # noqa: E501',
            '"Enable **MD5** authentication for **RIPv2** on all participating interfaces:\\n\\n```\\ninterface <type> <number>\\n ip rip authentication mode md5\\n ip rip authentication key-chain <key-chain-name>\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # routing_plugin.py  (IP routing services)
    # -----------------------------------------------------------------------
    'routing_plugin.py': [
        (
            '"Disable IP source routing: no ip source-route.",  # noqa: E501',
            '"Disable IP source routing:\\n\\n```\\nno ip source-route\\n```",  # noqa: E501',
        ),
        (
            '"Disable proxy ARP on all interfaces where it is not required: interface <type> <number>, no ip proxy-arp.",  # noqa: E501',
            '"Disable proxy ARP on all interfaces where it is not required:\\n\\n```\\ninterface <type> <number>\\n no ip proxy-arp\\n```",  # noqa: E501',
        ),
        (
            '"Remove or secure any tunnel interfaces that are not explicitly required for a documented business purpose.",  # noqa: E501',
            '"Remove or secure any tunnel interfaces that are not explicitly required for a documented business purpose. If required, apply ACLs, encryption, and authentication to all tunnel interfaces.",  # noqa: E501',
        ),
        (
            '"Enable uRPF in strict mode on all externally facing interfaces: interface <type> <number>, ip verify unicast source reachable-via rx.",  # noqa: E501',
            '"Enable uRPF in strict mode on all externally facing interfaces:\\n\\n```\\ninterface <type> <number>\\n ip verify unicast source reachable-via rx\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # interface_security_plugin.py
    # -----------------------------------------------------------------------
    'interface_security_plugin.py': [
        (
            '"Disable IP directed broadcasts on all interfaces: interface <type> <number>, no ip directed-broadcast.",  # noqa: E501',
            '"Disable IP directed broadcasts on all interfaces:\\n\\n```\\ninterface <type> <number>\\n no ip directed-broadcast\\n```",  # noqa: E501',
        ),
        (
            '"Disable ICMP unreachable messages on all interfaces: interface <type> <number>, no ip unreachables.",  # noqa: E501',
            '"Disable ICMP unreachable messages on all interfaces:\\n\\n```\\ninterface <type> <number>\\n no ip unreachables\\n```",  # noqa: E501',
        ),
        (
            '"Disable ICMP redirects on all interfaces: interface <type> <number>, no ip redirects.",  # noqa: E501',
            '"Disable ICMP redirects on all interfaces:\\n\\n```\\ninterface <type> <number>\\n no ip redirects\\n```",  # noqa: E501',
        ),
        (
            '"Disable ICMP mask replies on all interfaces: interface <type> <number>, no ip mask-reply.",  # noqa: E501',
            '"Disable ICMP mask replies on all interfaces:\\n\\n```\\ninterface <type> <number>\\n no ip mask-reply\\n```",  # noqa: E501',
        ),
        (
            '"Apply an inbound ACL on all externally facing interfaces that denies traffic from bogon/RFC 1918 source addresses: ip access-group <acl-name> in. Ensure the ACL denies 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, and other reserved ranges arriving from untrusted interfaces.",  # noqa: E501',
            '"Apply an inbound anti-spoofing ACL on all externally facing interfaces.\\nDeny RFC 1918, loopback, and other bogon source addresses arriving from untrusted interfaces:\\n\\n```\\nip access-list extended ANTISPOOFING-IN\\n deny ip 10.0.0.0 0.255.255.255 any\\n deny ip 172.16.0.0 0.15.255.255 any\\n deny ip 192.168.0.0 0.0.255.255 any\\n deny ip 127.0.0.0 0.255.255.255 any\\n permit ip any any\\ninterface <external-interface>\\n ip access-group ANTISPOOFING-IN in\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # telnet_plugin.py
    # -----------------------------------------------------------------------
    'telnet_plugin.py': [
        (
            '"Disable Telnet on all VTY lines and configure SSH as the sole remote management protocol: line vty 0 4, transport input ssh.",  # noqa: E501',
            '"Disable Telnet on all VTY lines and configure SSH as the only remote management protocol:\\n\\n```\\nline vty 0 4\\n transport input ssh\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # dns_plugin.py
    # -----------------------------------------------------------------------
    'dns_plugin.py': [
        (
            '"Disable DNS lookup to prevent unintentional DNS queries: no ip domain lookup. If DNS is required, ensure a trusted resolver is configured: ip name-server <trusted-dns-server>.",  # noqa: E501',
            '"Disable DNS lookup to prevent unintentional queries. If DNS is required, configure only trusted resolvers:\\n\\n```\\nno ip domain-lookup\\n```\\n\\nOr if a trusted resolver is needed:\\n\\n```\\nip name-server <trusted-dns-server>\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # http_plugin.py
    # -----------------------------------------------------------------------
    'http_plugin.py': [
        (
            '"Disable the HTTP server and use HTTPS or SSH for management: no ip http server.",  # noqa: E501',
            '"Disable the HTTP server. Use HTTPS or SSH for management access:\\n\\n```\\nno ip http server\\n```",  # noqa: E501',
        ),
        (
            '"Apply an ACL to restrict HTTP management access: ip http access-class <acl-number>.",  # noqa: E501',
            '"Apply an ACL to restrict HTTP management access to authorised hosts:\\n\\n```\\nip http access-class <acl-number>\\n```",  # noqa: E501',
        ),
        (
            '"Configure authentication for the HTTP server: ip http authentication local (or aaa).",  # noqa: E501',
            '"Configure authentication for the HTTP management server:\\n\\n```\\nip http authentication aaa\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # banner_plugin.py
    # -----------------------------------------------------------------------
    'banner_plugin.py': [
        (
            '"Configure a legal notice banner for login access: banner login # <legal-notice> #.",  # noqa: E501',
            '"Configure a legal notice banner displayed before login:\\n\\n```\\nbanner login ^\\nUnauthorized access is prohibited. All activity is monitored.\\n^\\n```",  # noqa: E501',
        ),
        (
            '"Configure a legal notice MOTD banner: banner motd # <legal-notice> #.",  # noqa: E501',
            '"Configure a legal notice message-of-the-day banner:\\n\\n```\\nbanner motd ^\\nUnauthorized access is prohibited. All activity is monitored.\\n^\\n```",  # noqa: E501',
        ),
        (
            '"Configure a legal notice for web authentication: banner webauth # <legal-notice> #.",  # noqa: E501',
            '"Configure a legal notice for the web authentication page:\\n\\n```\\nbanner webauth ^\\nUnauthorized access is prohibited. All activity is monitored.\\n^\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # username_plugin.py  (password encryption / type checks)
    # -----------------------------------------------------------------------
    'username_plugin.py': [
        (
            '"Enable the global service password encryption command to encrypt all type-0 passwords in the configuration: service password-encryption.",  # noqa: E501',
            '"Enable the global service password-encryption command to obfuscate all type-0 passwords in the configuration. This is a **minimum** measure — stronger hashing (type 5/8/9) is preferred:\\n\\n```\\nservice password-encryption\\n```",  # noqa: E501',
        ),
        (
            '"Replace all type-0 (clear-text) passwords with strongly hashed equivalents (type 5, 8, or 9). Enable service password-encryption as a baseline: service password-encryption.",  # noqa: E501',
            '"Replace all type-0 (clear-text) passwords with strongly hashed equivalents (type 5, 8, or 9).\\nEnable service password-encryption as a baseline protection:\\n\\n```\\nservice password-encryption\\n```",  # noqa: E501',
        ),
        (
            '"Replace all type-7 passwords with strongly hashed passwords (type 5, 8, or 9). Avoid reuse of any password previously encrypted as type 7.",  # noqa: E501',
            '"Replace all type-7 passwords with strongly hashed equivalents (type 5, 8, or 9).\\nAvoid reusing any password that was previously encrypted as type 7 since it may have been compromised.",  # noqa: E501',
        ),
        (
            '"Migrate type-5 (MD5) passwords to type 8 (PBKDF2) or type 9 (scrypt) where supported by the IOS version: username <name> algorithm-type sha256 secret <pass>.",  # noqa: E501',
            '"Migrate type-5 (**MD5**) passwords to type 8 (PBKDF2) or type 9 (scrypt) where the IOS version supports it:\\n\\n```\\nusername <name> algorithm-type sha256 secret <pass>\\n```",  # noqa: E501',
        ),
    ],

    # -----------------------------------------------------------------------
    # cdp_lldp_plugin.py
    # -----------------------------------------------------------------------
    'cdp_lldp_plugin.py': [
        (
            '"Disable CDP globally: no cdp run. If CDP is required on specific interfaces, disable it on all untrusted interfaces: interface <type> <number>, no cdp enable.",  # noqa: E501',
            '"Disable CDP globally, or at minimum disable it on all untrusted interfaces:\\n\\n```\\nno cdp run\\n```\\n\\nOr per interface on untrusted segments:\\n\\n```\\ninterface <type> <number>\\n no cdp enable\\n```",  # noqa: E501',
        ),
        (
            '"Disable CDP on all interfaces where it is not strictly required, particularly all externally facing or untrusted interfaces: interface <type> <number>, no cdp enable.",  # noqa: E501',
            '"Disable CDP on all interfaces where it is not strictly required, particularly external or untrusted interfaces:\\n\\n```\\ninterface <type> <number>\\n no cdp enable\\n```",  # noqa: E501',
        ),
        (
            '"Disable LLDP globally: no lldp run. If LLDP is required, disable it on all untrusted interfaces: interface <type> <number>, no lldp transmit, no lldp receive.",  # noqa: E501',
            '"Disable LLDP globally, or disable it on all untrusted interfaces:\\n\\n```\\nno lldp run\\n```\\n\\nOr per interface on untrusted segments:\\n\\n```\\ninterface <type> <number>\\n no lldp transmit\\n no lldp receive\\n```",  # noqa: E501',
        ),
    ],
}


def apply_replacements():
    total = 0
    for fname, replacements in REPLACEMENTS.items():
        path = os.path.join(PLUGIN_DIR, fname)
        if not os.path.isfile(path):
            print(f'  SKIP (not found): {fname}')
            continue

        with open(path) as f:
            content = f.read()

        count = 0
        for old, new in replacements:
            if old in content:
                content = content.replace(old, new, 1)
                count += 1
            else:
                print(f'  WARNING: pattern not found in {fname}:')
                print(f'    {old[:80]}...')

        if count:
            with open(path, 'w') as f:
                f.write(content)
            print(f'  {fname}: {count} recommendation(s) updated')
            total += count

    print(f'\nTotal Markdown recommendation updates: {total}')


if __name__ == '__main__':
    print(f'Applying Markdown recommendations in: {PLUGIN_DIR}\n')
    apply_replacements()
