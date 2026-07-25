#!/usr/bin/env python3
"""
Compare two Java files ignoring comments, javadoc and whitespace.

Exit 0 if the code content is identical (i.e. the files differ in comments/javadoc/
formatting only), 1 if the code differs. With --emit, print the normalized code of a
single file instead (useful for debugging a surprising result).

Why a state machine and not a regex: a regex that treats "//" as a comment start will
eat the tail of any string literal containing one. "https://..." is everywhere in this
tree, so a changed URL inside a string literal would be silently misreported as a
comment-only change. This walks the file tracking normal / string / char / line-comment
/ block-comment state, and handles escapes and text blocks.

Self-test with --selftest before trusting a run.
"""
import sys

NORMAL, IN_STR, IN_CHAR, IN_LINE, IN_BLOCK = range(5)


def code_only(src: str) -> str:
    out = []
    st = NORMAL
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ''
        if st == NORMAL:
            if c == '/' and nxt == '/':
                st = IN_LINE
                i += 2
                continue
            if c == '/' and nxt == '*':
                st = IN_BLOCK
                i += 2
                continue
            if c == '"':
                if src[i:i + 3] == '"""':          # text block
                    out.append('"""')
                    i += 3
                    while i < n and src[i:i + 3] != '"""':
                        out.append(src[i])
                        i += 1
                    out.append('"""')
                    i += 3
                    continue
                st = IN_STR
                out.append(c)
                i += 1
                continue
            if c == "'":
                st = IN_CHAR
                out.append(c)
                i += 1
                continue
            out.append(c)
            i += 1
            continue
        if st == IN_LINE:
            if c == '\n':
                st = NORMAL
                out.append('\n')
            i += 1
            continue
        if st == IN_BLOCK:
            if c == '*' and nxt == '/':
                st = NORMAL
                i += 2
                out.append(' ')
                continue
            i += 1
            continue
        if st in (IN_STR, IN_CHAR):
            out.append(c)
            if c == '\\':                          # keep the escaped char so \" is not a terminator
                if i + 1 < n:
                    out.append(src[i + 1])
                i += 2
                continue
            if (st == IN_STR and c == '"') or (st == IN_CHAR and c == "'"):
                st = NORMAL                        # opening quote was consumed in NORMAL
            i += 1
            continue
    return ' '.join(''.join(out).split())


def read(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read()


def selftest():
    cases = [
        ("javadoc only", '/** old */\nint a=1;', '/** NEW */\nint a=1;', True),
        ("line comment only", 'int a=1; // old\n', 'int a=1; // new\n', True),
        ("code change", 'int a=1;', 'int a=2;', False),
        ("url in string changed", 'String u="http://a/x";', 'String u="https://a/x";', False),
        ("url same doc differs", '/** a */\nString u="https://a/b//c";',
         '/** b */\nString u="https://a/b//c";', True),
        ("block-open in string", 'String s="/* x */"; int a=1;', 'String s="/* x */"; int a=2;', False),
        ("escaped quote same", 'String s="he \\"hi\\" // x"; int a=1;',
         'String s="he \\"hi\\" // x"; int a=1;', True),
        ("escaped quote differs", 'String s="a\\"b";', 'String s="a\\"c";', False),
        ("char literal", "char c='\\''; int a=1;", "char c='\\''; int a=2;", False),
        ("apostrophe in comment", "// it's fine\nint a=1;", "// other\nint a=1;", True),
        ("apostrophe in comment, code differs", "// it's fine\nint a=1;", "// other\nint a=2;", False),
        ("reformat only", 'int  a\n=\n1;', 'int a = 1;', True),
        ("annotation is code", '@Deprecated\nint a=1;', 'int a=1;', False),
        ("javadoc deprecated tag", '/** @deprecated x */\nint a=1;', '/** */\nint a=1;', True),
    ]
    bad = 0
    for name, a, b, expect in cases:
        got = code_only(a) == code_only(b)
        ok = got == expect
        print(("PASS  " if ok else "FAIL  ") + name)
        if not ok:
            bad += 1
    print("%d/%d passed" % (len(cases) - bad, len(cases)))
    return 1 if bad else 0


if __name__ == '__main__':
    if '--selftest' in sys.argv:
        sys.exit(selftest())
    if sys.argv[1] == '--emit':
        print(code_only(read(sys.argv[2])))
        sys.exit(0)
    sys.exit(0 if code_only(read(sys.argv[1])) == code_only(read(sys.argv[2])) else 1)
