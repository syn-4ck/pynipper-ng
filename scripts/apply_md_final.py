#!/usr/bin/env python3
import os

p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 'src', 'analyze', 'cisco', 'ios', 'plugins')

fixes = {
    'dns_plugin.py': [
        ('Either disable DNS lookups to prevent broadcast queries: no ip domain-lookup, or configure explicit DNS servers: ip name-server <ip-address>.',
         'Disable DNS lookups to prevent broadcast queries:\n\n```\nno ip domain-lookup\n```\n\nOr if DNS is required, configure only trusted resolvers:\n\n```\nip name-server <trusted-ip>\n```'),
    ],
    'http_plugin.py': [
        ('Configure a strong authentication method for the HTTP service: ip http authentication local or ip http authentication aaa login-authentication <list>.',
         'Configure authentication for the HTTP management service:\n\n```\nip http authentication aaa\n```'),
    ],
    'username_plugin.py': [
        ("Enable service password encryption: service password-encryption. Note: this uses type-7 (weak reversible cipher). Always prefer 'enable secret' and 'username secret' over 'enable password' and 'username password'.",
         "Enable service password-encryption (type-7 reversible). Prefer `enable secret` and `username secret` over `enable password` / `username password`:\n\n```\nservice password-encryption\n```"),
        ('Replace all type-0 username passwords with type-8 (PBKDF2-SHA256) or type-9 (scrypt): username <name> algorithm-type sha256 secret <password>.',
         'Replace all type-0 (clear-text) passwords with type-8 or type-9 hashed passwords:\n\n```\nusername <name> algorithm-type sha256 secret <password>\n```'),
        ('Replace all type-7 username passwords with type-8 or type-9: username <name> algorithm-type sha256 secret <password>.',
         'Replace all type-7 (reversible) passwords with type-8 or type-9 hashed passwords:\n\n```\nusername <name> algorithm-type sha256 secret <password>\n```'),
        ('Upgrade to type-8 (PBKDF2-SHA256) or type-9 (scrypt): username <name> algorithm-type sha256 secret <password> or username <name> algorithm-type scrypt secret <password>.',
         'Upgrade type-5 (MD5) passwords to type-8 (PBKDF2-SHA256) or type-9 (scrypt):\n\n```\nusername <name> algorithm-type sha256 secret <password>\n```'),
    ],
    'cdp_lldp_plugin.py': [
        ('If CDP is not required for network management, disable it globally: no cdp run. If CDP is required on specific interfaces (e.g., towards IP phones or WAN links), disable it selectively on all other interfaces: no cdp enable (per interface).',
         'If CDP is not required, disable it globally. Otherwise disable it on all untrusted interfaces:\n\n```\nno cdp run\n```\n\nOr per untrusted interface:\n\n```\ninterface <type> <number>\n no cdp enable\n```'),
        ('Disable CDP on all interfaces except those explicitly requiring it (such as towards trusted network management equipment): no cdp enable (per interface).',
         'Disable CDP on all interfaces that do not explicitly require it:\n\n```\ninterface <type> <number>\n no cdp enable\n```'),
        ('If LLDP is not required, disable it globally: no lldp run. If required on specific interfaces, disable sending and receiving selectively: no lldp transmit, no lldp receive (per interface).',
         'If LLDP is not required, disable it globally. Otherwise disable it on untrusted interfaces:\n\n```\nno lldp run\n```\n\nOr per untrusted interface:\n\n```\ninterface <type> <number>\n no lldp transmit\n no lldp receive\n```'),
    ],
    'routing_plugin.py': [
        ('Remove any unnecessary tunnel interfaces: no interface tunnel <n>. If tunnels are required, ensure they are documented, authenticated with IPsec, and reviewed regularly.',
         'Remove unnecessary tunnel interfaces. If tunnels are required, document, authenticate with IPsec, and review regularly:\n\n```\nno interface tunnel <n>\n```'),
    ],
}

total, warns = 0, 0
for fname, reps in fixes.items():
    path = os.path.join(p, fname)
    with open(path) as f:
        c = f.read()
    count = 0
    for old, new in reps:
        if old in c:
            c = c.replace(old, new, 1)
            count += 1
        else:
            print(f'WARN [{fname}]: {old[:60]}')
            warns += 1
    if count:
        with open(path, 'w') as f:
            f.write(c)
        print(f'  {fname}: {count} updated')
    total += count
print(f'\nTotal: {total} updates, {warns} warnings')
