#!/usr/bin/env python3
"""
Adds cis_section as the 6th argument to every Issue() constructor call
in all Cisco IOS plugin files, using the nearest preceding # CIS X.Y.Z comment
to determine the correct section string.

Run from repository root:
    python3 scripts/add_cis_sections.py
"""

import re
import os

PLUGIN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'src', 'analyze', 'cisco', 'ios', 'plugins'
)

# Regex to match method-level CIS comments: "    # CIS 1.4.1 - ..."
CIS_COMMENT_RE = re.compile(r'^\s+# CIS (\d+\.\d+(?:\.\d+)?)\b')


def process_file(filepath: str) -> str:
    with open(filepath) as f:
        text = f.read()

    lines = text.splitlines(keepends=True)
    result = []
    current_cis = None
    i = 0

    while i < len(lines):
        line = lines[i]

        # Track CIS section from method-level comments
        m = CIS_COMMENT_RE.match(line)
        if m:
            current_cis = 'CIS ' + m.group(1)

        # Detect start of "return Issue(" call
        if re.search(r'\breturn Issue\(', line):
            # Collect the full Issue(...) block by counting balanced parens
            block = [line]
            depth = line.count('(') - line.count(')')
            j = i + 1
            while depth > 0 and j < len(lines):
                block.append(lines[j])
                depth += lines[j].count('(') - lines[j].count(')')
                j += 1

            # Only inject if CIS section known and not already present
            block_text = ''.join(block)
            if current_cis and '"CIS ' not in block_text and "'CIS " not in block_text:
                block = inject_cis(block, current_cis)

            result.extend(block)
            i = j
            continue

        result.append(line)
        i += 1

    return ''.join(result)


def inject_cis(block: list, cis_section: str) -> list:
    """Add cis_section as the last argument of the Issue() block."""
    # Find closing paren line (first line that is just whitespace + ')')
    close_idx = None
    for k in range(len(block) - 1, -1, -1):
        if re.match(r'^\s+\)\s*$', block[k]):
            close_idx = k
            break

    if close_idx is None:
        return block  # Unexpected format – leave untouched

    # Find the last non-blank argument line before the closing paren
    last_arg_idx = close_idx - 1
    while last_arg_idx >= 0 and not block[last_arg_idx].strip():
        last_arg_idx -= 1

    if last_arg_idx < 0:
        return block

    last_arg = block[last_arg_idx]

    # Add comma after the string argument (before any # noqa comment)
    noqa_m = re.search(r'(\s+#\s*noqa[^\n]*)', last_arg)
    if noqa_m:
        base = last_arg[:noqa_m.start()].rstrip()
        new_last_arg = base + ',  # noqa: E501\n'
    else:
        # Remove trailing whitespace/newline and add comma
        new_last_arg = last_arg.rstrip() + ',\n'

    # Preserve the same indentation for the CIS line
    indent = ' ' * (len(last_arg) - len(last_arg.lstrip()))
    cis_line = f'{indent}"{cis_section}"\n'

    return block[:last_arg_idx] + [new_last_arg, cis_line] + block[close_idx:]


def main():
    plugin_files = sorted(
        f for f in os.listdir(PLUGIN_DIR)
        if f.endswith('.py') and f != '__init__.py'
    )
    for fname in plugin_files:
        path = os.path.join(PLUGIN_DIR, fname)
        original = open(path).read()
        new_content = process_file(path)
        if new_content != original:
            with open(path, 'w') as f:
                f.write(new_content)
            # Count how many CIS injections were done
            count = new_content.count('"CIS ') - original.count('"CIS ')
            print(f'  {fname}: +{count} CIS section(s) added')
        else:
            print(f'  {fname}: no changes')


if __name__ == '__main__':
    print(f'Processing plugins in: {PLUGIN_DIR}')
    main()
    print('Done.')
