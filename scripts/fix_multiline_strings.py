#!/usr/bin/env python3
"""
Fix syntax errors in plugin files caused by literal newlines inside regular
(non-triple-quoted) string literals.  Replaces each literal newline found
inside a "..." or '...' string with the two-character escape sequence \n.
"""
import os, sys

PLUGIN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'src', 'analyze', 'cisco', 'ios', 'plugins'
)


def fix_content(src: str) -> str:
    """Scan src and escape literal newlines found inside regular string literals."""
    out = []
    i = 0
    n = len(src)

    while i < n:
        c = src[i]

        # ---- triple-quoted string: pass through unchanged ----
        if (c in ('"', "'")) and src[i:i+3] in ('"""', "'''"):
            close = src[i:i+3]
            j = src.find(close, i + 3)
            if j < 0:
                j = n - 3
            out.append(src[i:j + 3])
            i = j + 3
            continue

        # ---- regular string (optionally prefixed with r/b/f) ----
        if c in ('"', "'"):
            quote = c
            out.append(c)
            i += 1
            while i < n:
                sc = src[i]
                if sc == '\\':          # explicit escape – keep both chars
                    out.append(sc)
                    i += 1
                    if i < n:
                        out.append(src[i])
                        i += 1
                elif sc == quote:       # closing delimiter
                    out.append(sc)
                    i += 1
                    break
                elif sc == '\n':        # literal newline inside string → escape
                    out.append('\\n')
                    i += 1
                else:
                    out.append(sc)
                    i += 1
            continue

        # ---- everything else (code, comments) – pass through ----
        out.append(c)
        i += 1

    return ''.join(out)


def main():
    import ast
    fixed = 0
    for fname in sorted(os.listdir(PLUGIN_DIR)):
        if not fname.endswith('.py'):
            continue
        path = os.path.join(PLUGIN_DIR, fname)
        src = open(path).read()

        # Does it actually have a syntax error?
        try:
            ast.parse(src)
            continue  # already valid – skip
        except SyntaxError:
            pass

        new_src = fix_content(src)
        try:
            ast.parse(new_src)
        except SyntaxError as e:
            print(f'  STILL BROKEN after fix ({fname}): {e}')
            continue

        with open(path, 'w') as f:
            f.write(new_src)
        print(f'  Fixed: {fname}')
        fixed += 1

    print(f'\nFixed {fixed} file(s).')


if __name__ == '__main__':
    main()
