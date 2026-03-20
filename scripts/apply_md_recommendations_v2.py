#!/usr/bin/env python3
"""
Second-pass Markdown formatting for plugin recommendation strings.
Uses the exact recommendation strings extracted from the files after CIS injection.
"""

import os

PLUGIN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'src', 'analyze', 'cisco', 'ios', 'plugins'
)

REPLACEMENTS = {

    'service_plugin.py': [
        (
            'Disable the PAD service: no service pad.',
            'Disable the PAD service:\n\n```\nno service pad\n```',
        ),
        (
            'Disable UDP small servers: no service udp-small-servers.',
            'Disable UDP small servers:\n\n```\nno service udp-small-servers\n```',
        ),
        (
            'Disable TCP small servers: no service tcp-small-servers.',
            'Disable TCP small servers:\n\n```\nno service tcp-small-servers\n```',
        ),
        (
            'Disable the BOOTP server: no ip bootp server.',
            'Disable the BOOTP server:\n\n```\nno ip bootp server\n```',
        ),
        (
            'Disable the Finger service: no ip finger (or no service finger on older IOS).',
            'Disable the Finger service:\n\n```\nno ip finger\n```',
        ),
        (
            'Disable identd: no ip identd.',
            'Disable identd:\n\n```\nno ip identd\n```',
        ),
        (
            'Disable automatic configuration loading from the network: no service config.',
            'Disable automatic configuration loading from the network:\n\n```\nno service config\n```',
        ),
        (
            'Enable TCP keepalives in both directions: service tcp-keepalives-in, service tcp-keepalives-out.',
            'Enable TCP keepalives in both directions:\n\n```\nservice tcp-keepalives-in\nservice tcp-keepalives-out\n```',
        ),
        (
            'Set the TCP SYN wait time to 10 seconds or less: ip tcp synwait-time 10.',
            'Set the TCP SYN wait time to 10 seconds or less:\n\n```\nip tcp synwait-time 10\n```',
        ),
        (
            'Reduce the TCP SYN wait time: ip tcp synwait-time 10.',
            'Reduce the TCP SYN wait time:\n\n```\nip tcp synwait-time 10\n```',
        ),
        (
            'Disable MOP on all Ethernet interfaces: interface <type> <number>, no mop enabled.',
            'Disable MOP on all Ethernet interfaces:\n\n```\ninterface <type> <number>\n no mop enabled\n```',
        ),
        (
            'Suppress gratuitous ARP responses: no ip gratuitous-arps.',
            'Suppress gratuitous ARP on all interfaces:\n\n```\nno ip gratuitous-arps\n```',
        ),
    ],

    'ssh_plugin.py': [
        (
            'Enforce SSHv2 only: ip ssh version 2.',
            'Enforce **SSHv2** only:\n\n```\nip ssh version 2\n```',
        ),
        (
            'Set SSH authentication retries to 3 or fewer: ip ssh authentication-retries 3.',
            'Set SSH authentication retries to 3 or fewer:\n\n```\nip ssh authentication-retries 3\n```',
        ),
        (
            'Reduce SSH authentication retries: ip ssh authentication-retries 3.',
            'Reduce SSH authentication retries to 3 or fewer:\n\n```\nip ssh authentication-retries 3\n```',
        ),
        (
            'Set the SSH negotiation timeout to 60 seconds or less: ip ssh time-out 60.',
            'Set the SSH negotiation timeout to 60 seconds or less:\n\n```\nip ssh time-out 60\n```',
        ),
        (
            'Reduce the SSH timeout: ip ssh time-out 60.',
            'Reduce the SSH timeout to 60 seconds or less:\n\n```\nip ssh time-out 60\n```',
        ),
        (
            'Bind SSH to a specific management interface (e.g., Loopback0): ip ssh source-interface Loopback0.',
            'Bind SSH to a stable management interface:\n\n```\nip ssh source-interface Loopback0\n```',
        ),
        (
            'Generate a new RSA key pair with at least 2048 bits: crypto key generate rsa modulus 2048.',
            'Generate a new RSA key pair with at least 2048 bits to support **SSHv2**:\n\n```\ncrypto key generate rsa modulus 2048\n```',
        ),
    ],

    'snmp_plugin.py': [
        (
            'Remove all SNMPv1/v2c community strings: no snmp-server community <string>. Migrate to SNMPv3 with authPriv.',
            'Remove all SNMPv1/v2c community strings and migrate to **SNMPv3** with authPriv:\n\n```\nno snmp-server community <string>\nsnmp-server group <group> v3 priv\nsnmp-server user <user> <group> v3 auth sha <auth-key> priv aes 128 <priv-key>\n```',
        ),
        (
            'Remove default community strings immediately: no snmp-server community public, no snmp-server community private. Configure SNMPv3 with unique credentials.',
            'Remove the default SNMP community strings immediately:\n\n```\nno snmp-server community public\nno snmp-server community private\n```\n\nThen configure **SNMPv3** with unique credentials.',
        ),
        (
            'Configure SNMPv3 with authPriv: snmp-server group <group> v3 priv, snmp-server user <user> <group> v3 auth sha <auth-key> priv aes 128 <priv-key>.',
            'Configure **SNMPv3** with authentication and privacy (authPriv):\n\n```\nsnmp-server group <group> v3 priv\nsnmp-server user <user> <group> v3 auth sha <auth-key> priv aes 128 <priv-key>\n```',
        ),
        (
            'Apply an ACL to each SNMP community or SNMPv3 group: snmp-server community <string> RO <acl>, snmp-server group <group> v3 priv access <acl>.',
            'Apply an ACL to restrict SNMP access to authorised management hosts:\n\n```\nsnmp-server community <string> RO <acl-number>\nsnmp-server group <group> v3 priv access <acl-number>\n```',
        ),
        (
            'Enable SNMP traps and configure a trap receiver using SNMPv3: snmp-server enable traps, snmp-server host <ip> version 3 priv <user>.',
            'Enable SNMP traps and configure a **SNMPv3** trap receiver:\n\n```\nsnmp-server enable traps\nsnmp-server host <ip> version 3 priv <user>\n```',
        ),
    ],

    'ntp_plugin.py': [
        (
            'Configure at least two NTP servers for redundancy: ntp server <ip-address> [prefer]. Use version 4 and enable NTP authentication.',
            'Configure at least two NTP servers for redundancy:\n\n```\nntp server <primary-ip> prefer\nntp server <secondary-ip>\n```',
        ),
        (
            'Enable NTP MD5 authentication: ntp authenticate, ntp authentication-key <id> md5 <key>, ntp trusted-key <id>. Reference the key on each NTP server: ntp server <ip> key <id>.',
            'Enable NTP **MD5** authentication and reference the key on each server:\n\n```\nntp authenticate\nntp authentication-key <id> md5 <key>\nntp trusted-key <id>\nntp server <ip> key <id>\n```',
        ),
        (
            'Restrict NTP access: ntp access-group peer <acl>, ntp access-group serve-only <acl>.',
            'Restrict NTP access with access groups:\n\n```\nntp access-group peer <acl-number>\nntp access-group serve-only <acl-number>\n```',
        ),
    ],

    'telnet_plugin.py': [
        (
            'Disable Telnet on all VTY lines and allow only SSH: line vty 0 4, transport input ssh.',
            'Disable Telnet and allow only SSH on all VTY lines:\n\n```\nline vty 0 4\n transport input ssh\n```',
        ),
    ],

    'dns_plugin.py': [
        (
            'Either disable DNS lookups to prevent broadcast queries: no ip domain-lookup, or configure a specific trusted DNS server: ip name-server <ip>.',
            'Disable DNS lookups to prevent broadcast queries:\n\n```\nno ip domain-lookup\n```\n\nOr if DNS is required, configure only trusted resolvers:\n\n```\nip name-server <trusted-ip>\n```',
        ),
    ],

    'http_plugin.py': [
        (
            'Disable the HTTP service: no ip http server. Use HTTPS (ip http secure-server) or SSH for management.',
            'Disable the HTTP service. Use HTTPS or SSH for management access:\n\n```\nno ip http server\n```',
        ),
        (
            'Restrict HTTP/HTTPS management access with an ACL: ip http access-class <acl-number>.',
            'Restrict HTTP/HTTPS management access to authorised hosts:\n\n```\nip http access-class <acl-number>\n```',
        ),
        (
            'Configure a strong authentication method for the HTTP service: ip http authentication aaa (or local).',
            'Configure authentication for the HTTP management service:\n\n```\nip http authentication aaa\n```',
        ),
    ],

    'banner_plugin.py': [
        (
            'Configure a login banner with an appropriate legal disclaimer: banner login #\\n<WARNING TEXT>\\n#',
            'Configure a login banner with an appropriate legal disclaimer:\n\n```\nbanner login ^\nUnauthorized access is prohibited. All activities are monitored and logged.\n^\n```',
        ),
        (
            'Configure an MOTD banner: banner motd #\\n<WARNING TEXT>\\n#',
            'Configure a message-of-the-day banner with a legal disclaimer:\n\n```\nbanner motd ^\nUnauthorized access is prohibited. All activities are monitored and logged.\n^\n```',
        ),
        (
            'Configure the WebAuth banner: ip admission auth-proxy-banner http <banner-text | file-path>.',
            'Configure a WebAuth banner with a legal notice:\n\n```\nip admission auth-proxy-banner http ^Unauthorized access is prohibited.^\n```',
        ),
    ],

    'username_plugin.py': [
        (
            'Enable service password encryption: service password-encryption. Note: this uses type-7 (reversible) encryption and is a minimum control — prefer type-8 or type-9 hashing.',
            'Enable service password-encryption as a baseline (type-7 — reversible). Prefer type-8 or type-9 hashing for all passwords:\n\n```\nservice password-encryption\n```',
        ),
        (
            'Replace all type-0 username passwords with type-8 (PBKDF2-SHA256) or type-9 (scrypt) hashed passwords: username <name> algorithm-type sha256 secret <pass>.',
            'Replace all type-0 (clear-text) passwords with type-8 (PBKDF2-SHA256) or type-9 (scrypt) hashed passwords:\n\n```\nusername <name> algorithm-type sha256 secret <pass>\n```',
        ),
        (
            'Replace all type-7 username passwords with type-8 or type-9: username <name> algorithm-type sha256 secret <pass>.',
            'Replace all type-7 (reversible) passwords with type-8 or type-9 hashed passwords:\n\n```\nusername <name> algorithm-type sha256 secret <pass>\n```',
        ),
        (
            'Upgrade to type-8 (PBKDF2-SHA256) or type-9 (scrypt): username <name> algorithm-type sha256 secret <pass>.',
            'Upgrade type-5 (**MD5**) passwords to type-8 (PBKDF2-SHA256) or type-9 (scrypt):\n\n```\nusername <name> algorithm-type sha256 secret <pass>\n```',
        ),
    ],

    'cdp_lldp_plugin.py': [
        (
            'If CDP is not required for network management, disable it globally: no cdp run. If required selectively, disable it on untrusted interfaces: interface <type> <number>, no cdp enable.',
            'If CDP is not required, disable it globally. Otherwise disable it on all untrusted interfaces:\n\n```\nno cdp run\n```\n\nOr per untrusted interface:\n\n```\ninterface <type> <number>\n no cdp enable\n```',
        ),
        (
            'Disable CDP on all interfaces except those explicitly requiring it (such as toward network management systems): interface <type> <number>, no cdp enable.',
            'Disable CDP on all interfaces that do not explicitly require it:\n\n```\ninterface <type> <number>\n no cdp enable\n```',
        ),
        (
            'If LLDP is not required, disable it globally: no lldp run. If required on specific interfaces, disable transmit and receive on untrusted segments: interface <type>, no lldp transmit, no lldp receive.',
            'If LLDP is not required, disable it globally. Otherwise disable it on untrusted interfaces:\n\n```\nno lldp run\n```\n\nOr per untrusted interface:\n\n```\ninterface <type> <number>\n no lldp transmit\n no lldp receive\n```',
        ),
    ],

    'routing_plugin.py': [
        (
            'Disable IP source routing globally: no ip source-route.',
            'Disable IP source routing globally:\n\n```\nno ip source-route\n```',
        ),
        (
            'Disable Proxy ARP on all interfaces: interface <name>, no ip proxy-arp.',
            'Disable Proxy ARP on all interfaces where it is not required:\n\n```\ninterface <type> <number>\n no ip proxy-arp\n```',
        ),
        (
            'Remove any unnecessary tunnel interfaces: no interface tunnel <n>. If tunnels are required, apply ACLs, authentication, and encryption.',
            'Remove unnecessary tunnel interfaces. If tunnels are required, apply ACLs, authentication, and encryption:\n\n```\nno interface tunnel <n>\n```',
        ),
        (
            'Enable strict uRPF on all external or high-risk interfaces: interface <name>, ip verify unicast source reachable-via rx.',
            'Enable strict uRPF on all external-facing or high-risk interfaces:\n\n```\ninterface <type> <number>\n ip verify unicast source reachable-via rx\n```',
        ),
    ],

    'aaa_plugin.py': [
        (
            'Configure AAA authorization for EXEC sessions: aaa authorization exec default group tacacs+ local.',
            'Configure **AAA** authorization for EXEC sessions:\n\n```\naaa authorization exec default group tacacs+ local\n```',
        ),
        (
            'Configure AAA network authorization: aaa authorization network default group tacacs+ local.',
            'Configure **AAA** network authorization:\n\n```\naaa authorization network default group tacacs+ local\n```',
        ),
        (
            'Configure AAA command accounting for privilege-15 commands: aaa accounting commands 15 default start-stop group tacacs+.',
            'Configure **AAA** command accounting for privilege-15 commands:\n\n```\naaa accounting commands 15 default start-stop group tacacs+\n```',
        ),
        (
            'Configure AAA exec accounting: aaa accounting exec default start-stop group tacacs+.',
            'Configure **AAA** exec accounting:\n\n```\naaa accounting exec default start-stop group tacacs+\n```',
        ),
        (
            'Configure AAA connection accounting: aaa accounting connection default start-stop group tacacs+.',
            'Configure **AAA** connection accounting:\n\n```\naaa accounting connection default start-stop group tacacs+\n```',
        ),
    ],
}


def apply_replacements():
    total = 0
    warnings = 0
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
                print(f'  WARN [{fname}]: pattern not found: {old[:60]}...')
                warnings += 1

        if count:
            with open(path, 'w') as f:
                f.write(content)
            print(f'  {fname}: {count} updated')
            total += count

    print(f'\nTotal: {total} updates, {warnings} warnings')


if __name__ == '__main__':
    print(f'Applying Markdown (pass 2) in: {PLUGIN_DIR}\n')
    apply_replacements()
