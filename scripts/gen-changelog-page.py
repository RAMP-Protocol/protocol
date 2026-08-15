#!/usr/bin/env python3
"""Render the published changelog page from proto/CHANGELOG.md.

The changelog used to exist twice: proto/CHANGELOG.md beside the schema, and a
hand-copied body inside website/src/content/docs/reference/changelog.mdx. Nothing
connected them, so every new entry had to be written twice and only the author's
memory kept them equal. They did not stay equal — by the time this script was
written the two bodies differed by 436 lines, and one whole entry existed only in
the file, never reaching the page an integrator reads.

So the page is generated. The file beside the schema is the source: it is the one
a schema change is written next to, and the one a reviewer reads in a proto diff.
The page is that file with Starlight frontmatter in place of the H1 title.

WHY THIS IS SAFE AS PLAIN COPY. MDX is stricter than Markdown — a bare `<` or `{`
outside a code span is parsed as JSX and fails the build. assert_mdx_safe below
refuses to write a page that would break that way, so the failure surfaces here,
naming the line, rather than as a Vite stack trace during the site build. The
page body uses no MDX-only syntax of its own (no imports, no directives, no
components), which is what makes the copy total rather than a merge.

Run by scripts/ci-local.sh, which then gates on `git diff` exactly like gen/ and
the validation corpus: regenerate, and fail if the committed page moved.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "proto" / "CHANGELOG.md"
PAGE = ROOT / "website" / "src" / "content" / "docs" / "reference" / "changelog.mdx"

FRONTMATTER = (
    "---\n"
    'title: "Changelog"\n'
    'description: "RAMP protocol changelog"\n'
    "---\n"
    "\n"
    "{/* GENERATED FILE — do not edit. Source: proto/CHANGELOG.md.\n"
    "    Edit that, then run scripts/gen-changelog-page.py. ci-local.sh gates the drift. */}\n"
)

# A `<` or `{` that is not inside a code span. Code spans are stripped first, so
# what remains is prose, where MDX would try to parse either character as JSX.
CODE_SPAN = re.compile(r"`[^`]*`")
MDX_HOSTILE = re.compile(r"[<{]")


def assert_mdx_safe(body: str) -> None:
    bad = []
    for n, line in enumerate(body.split("\n"), start=1):
        if MDX_HOSTILE.search(CODE_SPAN.sub("", line)):
            bad.append((n, line.strip()))
    if bad:
        for n, line in bad[:10]:
            print(f"{SOURCE}:{n}: bare '<' or '{{' outside a code span: {line}", file=sys.stderr)
        print(
            f"\n{len(bad)} line(s) would break the MDX build. Wrap the character in a "
            "code span, or write it as an entity.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def main() -> None:
    text = SOURCE.read_text()

    # Drop the H1 — the page's title comes from frontmatter, and two titles would
    # render one above the other.
    body = re.sub(r"\A#[^\n]*\n+", "", text, count=1)
    assert_mdx_safe(body)

    page = FRONTMATTER + "\n" + body
    if not page.endswith("\n"):
        page += "\n"

    if PAGE.exists() and PAGE.read_text() == page:
        print(f"changelog page already current -> {PAGE.relative_to(ROOT)}")
        return
    PAGE.write_text(page)
    print(f"wrote changelog page -> {PAGE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
