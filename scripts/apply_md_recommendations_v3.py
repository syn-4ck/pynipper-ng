#!/usr/bin/env python3
"""Final pass: fixes remaining plain-text recommendations using exact current strings."""

import os

PLUGIN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'src', 'analyze', 'cisco', 'ios', 'plugins'
)

REPLACEMENTS = {
    'snmp_plugin.py': [
        (
            'Apply an ACL to each SNMP community or SNMPv3 group: snmp-server community <string> ro <acl> or snmp-server group <group> v3 priv access <acl>.',
            'Apply an ACL to restrict SNMP access to authorised management hosts:\n\n```\nsnmp-server community <string> RO <acl-number>\nsnmp-server group <group> v3 priv access <acl-number>\n```',
        ),
    ],
    'dns_plugin.py': [
        (
            'Either disable DNS lookups to prevent broadcast queries: no ip domain-lookup, or configure explicit trusted name servers: ip name-server <ip>.',
            'Disable DNS lookups to prevent broadcast queries:\n\n```\nno ip domain-lookup\n```\n\nOr if DNS is required, configure only trusted resolvers:\n\n```\nip name-server <trusted-ip>\n```',
        ),
    ],
    'http_plugin.py': [
        (
            'Disable the HTTP service: no ip http server. Use HTTPS (ip http secure-server) or SSH for encrypted management access.',
            'Disable the HTTP service. Use HTTPS or SSH for management access:\n\n```\nno ip http server\n```',
        ),
        (
            'Restrict HTTP/HTTPS management access with an ACL: ip http access-class <acl-number-or-name>.',
            'Restrict HTTP/HTTPS management access to authorised hosts:\n\n```\nip http access-class <acl-number>\n```',
        ),
        (
            'Configure a strong authentication method for the HTTP service: ip http authentication local or ip http authentication aaa.',
            'Configure authentication for the HTTP management service:\n\n```\nip http authentication aaa\n```',
        ),
    ],
    'banner_plugin.py': [
        (
            'Configure the WebAuth banner: ip admission auth-proxy-banner http <banner-text | filepath>',
            'Configure the WebAuth banner with a legal notice:\n\n```\nip admission auth-proxy-banner http ^Unauthorized access is prohibited.^',
        ),
    ],
    'username_plugin.py': [
        (
            'Enable service password encryption: service password-encryption. Note: this uses type-7 (weak reversible) encryption — prefer type-8 (PBKDF2-SHA256) or type-9 (scrypt) password hashing.',
            'Enable service password-encryption as a baseline (type-7 — reversible). Prefer type-8 or type-9 hashing for all passwords:\n\n```\nservice password-encryption\n```',
        ),
        (
            'Replace all type-0 username passwords with type-8 (PBKDF2-SHA256) or type-9 (scrypt): username <name> algorithm-type sha256 secret <pass>.',
            'Replace all type-0 (clear-text) passwords with type-8 or type-9 hashed passwords:\n\n```\nusername <name> algorithm-type sha256 secret <pass>\n```',
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
            'If CDP is not required for network management, disable it globally: no cdp run. If CDP is required on specific management interfaces, disable it on all other interfaces.',
            'If CDP is not required, disable it globally. Otherwise disable it on all untrusted interfaces:\n\n```\nno cdp run\n```\n\nOr per untrusted interface:\n\n```\ninterface <type> <number>\n no cdp enable\n```',
        ),
        (
            'Disable CDP on all interfaces except those explicitly requiring it (such as towards trusted network management systems).',
            'Disable CDP on all interfaces that do not explicitly require it:\n\n```\ninterface <type> <number>\n no cdp enable\n```',
        ),
        (
            'If LLDP is not required, disable it globally: no lldp run. If required on specific interfaces, disable receive and transmit on untrusted segments.',
            'If LLDP is not required, disable it globally. Otherwise disable it on untrusted interfaces:\n\n```\nno lldp run\n```\n\nOr per untrusted interface:\n\n```\ninterface <type> <number>\n no lldp transmit\n no lldp receive\n```',
        ),
    ],
    'routing_plugin.py': [
        (
            'Remove any unnecessary tunnel interfaces: no interface tunnel <n>. If tunnels are required, ensure they are secured with proper authentication and encryption.',
            'Remove unnecessary tunnel interfaces. If tunnels are required, secure them with authentication and encryption:\n\n```\nno interface tunnel <n>\n```',
        ),
    ],
    'aaa_plugin.py': [
        (
            'Configure AAA exec authorization: aaa authorization exec default group tacacs+ local.',
            'Configure **AAA** exec authorization:\n\n```\naaa authorization exec default group tacacs+ local\n```',
        ),
        (
            'Configure privilege-15 command accounting: aaa accounting commands 15 default start-stop group tacacs+.',
            'Configure **AAA** privilege-15 command accounting:\n\n```\naaa accounting commands 15 default start-stop group tacacs+\n```',
        ),
        (
            'Configure connection accounting: aaa accounting connection default start-stop group tacacs+.',
            'Configure **AAA** connection accounting:\n\n```\naaa accounting connection default start-stop group tacacs+\n```',
        ),
    ],
}


def apply():
    total, warnings = 0, 0
    for fname, replacements in REPLACEMENTS.items():
        path = os.path.join(PLUGIN_DIR, fname)
        with open(path) as f:
            content = f.read()
        count = 0
        for old, new in replacements:
            if old in content:
                content = content.replace(old, new, 1)
                count += 1
            else:
                print(f'  WARN [{fname}]: {old[:70]}')
                warnings += 1
        if count:
            with open(path, 'w') as f:
                f.write(content)
            print(f'  {fname}: {count} updated')
            total += count
    print(f'\nTotal: {total} updates, {warnings} warnings')


if __name__ == '__main__':
    print(f'Applying Markdown (pass 3) in: {PLUGIN_DIR}\n')
    apply()
