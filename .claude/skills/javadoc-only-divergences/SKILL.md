---
name: javadoc-only-divergences
description: Find files in the bc-java divergence list that differ from upstream in comments/javadoc only, and adopt them verbatim. Use when asked to "copy across the javadoc-only changes", "find comment-only divergences", "which divergences are just docs", or to cheaply shrink the check-indexes mismatch list without behavioural risk.
---

# Adopt comment/javadoc-only divergences

A large slice of the `check-indexes.sh` divergence list is usually files where upstream **only** added or
reworded javadoc. Those can be adopted verbatim with zero behavioural risk, which shrinks the review backlog
so the remaining entries are genuine code divergence. In the 2026-07-25 run this took the list from 125 to 91
files in one pass (pkix 73→47, almost all of it the TSP/ERS tree).

This is the cheap first pass. It is **not** a substitute for `reconcile-residuals` — that one handles the
hidden stale-source class (`recorded == upstream` but local source behind) and needs real triage. This skill
handles only the subset that is provably semantics-free.

Upstream checkout: `../../bc-java` (resolve the real path if that's a symlink). Modules:
`core util prov pkix pg tls mail`.

## 1. Validate the detector first

`scripts/codeonly.py` compares two Java files ignoring comments, javadoc and whitespace. **Run its self-test
before trusting a sweep** — a broken stripper silently misclassifies real code changes as documentation:

```bash
python3 .claude/skills/javadoc-only-divergences/scripts/codeonly.py --selftest   # expect 14/14
```

Do **not** replace it with a `sed`/`grep` one-liner. A regex that treats `//` as a comment start eats the tail
of any string literal containing one, and `"https://..."` is everywhere in this tree (the `nohttp` plugin
guarantees URLs are present in sources). A changed URL inside a string literal would then be reported as a
comment-only change and adopted blind. The script is a state machine over
normal / string / char / line-comment / block-comment, and handles escapes and text blocks.

## 2. Build the divergence list and classify

```bash
BC=../../bc-java
CO=.claude/skills/javadoc-only-divergences/scripts/codeonly.py
./check-indexes.sh $BC 2>/dev/null > /tmp/div.txt
: > /tmp/comment-only.txt; : > /tmp/code-changed.txt
mod=""
while read -r line; do
  case "$line" in "checking "*) mod=${line#checking }; continue;; esac
  case "$line" in *.java) ;; *) continue;; esac
  f=$line; up="$f"
  # core-only: the 13 asn1 OID subpackages live under util/ in LTS but core/ upstream
  if [ "$mod" = core ]; then
    case "$f" in *org/bouncycastle/asn1/cryptlib/*|*org/bouncycastle/asn1/edec/*|*org/bouncycastle/asn1/gnu/*|\
*org/bouncycastle/asn1/isara/*|*org/bouncycastle/asn1/iso/*|*org/bouncycastle/asn1/kisa/*|\
*org/bouncycastle/asn1/microsoft/*|*org/bouncycastle/asn1/misc/*|*org/bouncycastle/asn1/mozilla/*|\
*org/bouncycastle/asn1/nsri/*|*org/bouncycastle/asn1/ntt/*|*org/bouncycastle/asn1/oiw/*|\
*org/bouncycastle/asn1/rosstandart/*) up=$(printf '%s' "$f" | sed -e 's/core/util/');; esac
  fi
  [ -f "$f" ] && [ -f "$BC/$up" ] || continue
  if python3 $CO "$f" "$BC/$up"; then printf '%s\t%s\n' "$mod" "$f" >> /tmp/comment-only.txt
  else printf '%s\t%s\n' "$mod" "$f" >> /tmp/code-changed.txt; fi
done < /tmp/div.txt
wc -l /tmp/comment-only.txt /tmp/code-changed.txt
```

Spot-check two or three of the largest candidates with a real `diff -u $BC/<f> <f>` before copying — cheap
insurance that the tool is behaving on actual files, not just its self-test.

## 3. Copy across, then prove it is semantics-free

```bash
while IFS=$'\t' read -r mod f; do cp "$BC/$f" "$f"; done < /tmp/comment-only.txt
```

**The decisive check — compare compiled bytecode, do not just eyeball diffs.** Extract the pre-change version
from git, compile both against the same classpath, and compare class files. Note `-g:none`: javadoc shifts
line numbers, so `LineNumberTable`/`SourceFile` debug attributes differ even for a pure comment change. Without
`-g:none` you get differences on every file and no signal.

```bash
rm -rf /tmp/oldsrc /tmp/oldng /tmp/newng; mkdir -p /tmp/oldsrc /tmp/oldng /tmp/newng
while IFS=$'\t' read -r mod f; do
  mkdir -p "/tmp/oldsrc/$(dirname "$f")"; git show "HEAD:$f" > "/tmp/oldsrc/$f"
done < /tmp/comment-only.txt
JUNIT=$(find ~/.gradle/caches -name "junit-4.13.2.jar" | head -1)
HAM=$(find ~/.gradle/caches -name "hamcrest-core-1.3.jar" | head -1)
CP=core/build/classes/java/main:util/build/classes/java/main:prov/build/classes/java/main:\
pkix/build/classes/java/main:pg/build/classes/java/main:core/build/classes/java/test:\
pg/build/classes/java/test:$JUNIT:$HAM
javac -nowarn -proc:none -g:none -cp "$CP" -d /tmp/oldng $(find /tmp/oldsrc -name '*.java')
javac -nowarn -proc:none -g:none -cp "$CP" -d /tmp/newng $(awk -F'\t' '{print $2}' /tmp/comment-only.txt)
diff -r /tmp/oldng /tmp/newng && echo "IDENTICAL - change carries no semantics"
```

Any surviving difference means a candidate was misclassified: find it, drop it from the list, restore it with
`git checkout -- <f>`, and investigate the stripper before continuing.

Requires the modules to have been compiled already (`./gradlew :<mod>:compileJava`) so the classpath resolves.
Add module jars for anything outside core/util/prov/pkix/pg.

## 4. Remaining gates

- **`nohttp`**: new javadoc can carry a non-HTTPS URL, which fails a task separate from checkstyle.
  `grep -l "http://"` the copied files, and run `./gradlew checkstyleNohttp`.
- **checkstyle**: `./gradlew :<mod>:checkstyleMain` per touched module (main sources only).
- **Tests**: run the suites owning the touched packages. Bytecode equality makes behavioural regression
  impossible, so this is a cheap confirmation, not the real gate.
- **japi**: expect 100% / 0 problems for every touched lib. Anything else means a misclassification slipped
  through — see [japi gate in CLAUDE.md](../../../CLAUDE.md).

## 5. Bump the indexes

The files now match upstream exactly, so bump each reviewed entry:

```bash
for m in core util prov pkix pg tls mail; do
  files=$(awk -F'\t' -v M=$m '$1==M {printf "%s ", $2}' /tmp/comment-only.txt)
  [ -n "$files" ] && sh index-update.sh $m $files
done
```

Then confirm no duplicate paths were introduced and that line counts are unchanged (pure substitutions):

```bash
for m in core pkix pg; do
  echo "$m: $(wc -l < indexes/bc-java.$m.index) lines, dupes=[$(awk '{print $2}' indexes/bc-java.$m.index | sort | uniq -d)]"
done
./check-indexes.sh $BC 2>/dev/null | grep -c '\.java$'   # should drop by exactly the adopted count
```

## Gotchas

- `index-update.sh` is not executable — invoke it with `sh`, and it needs a `<hex>␣␣<path>` line to already
  exist. A file with no upstream counterpart gets no entry; confirm with the maintainer rather than inventing
  a hash.
- Whitespace is collapsed in the comparison, so a pure reformat also classifies as comment-only. That is safe
  (bytecode equality still holds) but means the diff you commit may include indentation churn.
- A javadoc `@deprecated` tag is a comment; the `@Deprecated` annotation is code. The self-test covers both.
- Test files are legitimate candidates and appear in the list alongside main sources.
