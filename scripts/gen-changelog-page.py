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

LINKS ARE THE OTHER THING A PLAIN COPY GETS WRONG. A link in the source file is
written for a reader browsing the repository, so it is relative to proto/ —
`../docs/design-history.md` reaches the file from there. Copied verbatim onto the
page it reaches nothing, and starlight-links-validator fails the site build with
a message that names the generated page rather than the source line that caused
it. So repo-relative links are rewritten to absolute URLs against the published
repository, and the rewrite is fail-closed twice over: the target must exist on
disk, and any relative link left after the rewrite stops the run. Both failures
name the line in proto/CHANGELOG.md, which is the file an author can act on.

Run by scripts/ci-local.sh, which then gates on `git diff` exactly like gen/ and
the validation corpus: regenerate, and fail if the committed page moved.
"""

import pathlib
import posixpath
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "proto" / "CHANGELOG.md"
PAGE = ROOT / "website" / "src" / "content" / "docs" / "reference" / "changelog.mdx"

# Links in the source are relative to its own directory, proto/.
SOURCE_DIR = "proto"

# Where a repo-relative link is republished. The page is served from the docs
# site, which does not carry the repository tree, so the only address that works
# for both audiences is the file on the published repository.
REPO_BLOB = "https://github.com/RAMP-Protocol/protocol/blob/main/"

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


def assert_mdx_safe(body: str, line_offset: int = 0) -> None:
    bad = []
    for n, line in enumerate(body.split("\n"), start=1 + line_offset):
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


# A markdown inline link target. Anchors (#x), site-absolute paths (/x), and
# anything with a scheme (https:, mailto:) are already valid on the page; every
# other target is relative to proto/ and has to be rewritten.
MD_LINK = re.compile(r"\]\(([^)\s]+)\)")
ALREADY_ABSOLUTE = re.compile(r"\A(?:[a-zA-Z][a-zA-Z0-9+.-]*:|/|#)")


def absolutize_links(body: str, line_offset: int = 0) -> str:
    """Rewrite repo-relative link targets to absolute URLs on the published repo.

    Fail-closed in both directions: a target that does not resolve to a file in
    this repository stops the run, and so does any relative target still present
    afterwards. A dead link is easier to fix at the line that wrote it than in a
    site build log that only names the generated page.
    """
    missing = []
    out_lines = []

    # Line by line, so both diagnostics can name the source line. A position an
    # author cannot find in the file they edit is barely better than none.
    for n, line in enumerate(body.split("\n"), start=1 + line_offset):

        def rewrite(m: "re.Match[str]", n: int = n) -> str:
            target = m.group(1)
            if ALREADY_ABSOLUTE.match(target):
                return m.group(0)
            path, _, fragment = target.partition("#")
            repo_path = posixpath.normpath(posixpath.join(SOURCE_DIR, path))
            if repo_path.startswith("..") or not (ROOT / repo_path).exists():
                missing.append((n, target, repo_path))
                return m.group(0)
            return "](" + REPO_BLOB + repo_path + (("#" + fragment) if fragment else "") + ")"

        out_lines.append(MD_LINK.sub(rewrite, line))

    if missing:
        for n, target, repo_path in missing[:10]:
            print(f"{SOURCE}:{n}: link target {target!r} resolves to {repo_path!r}, "
                  "which is not a file in this repository", file=sys.stderr)
        print(f"\n{len(missing)} unresolvable relative link(s). Point them at a real path, "
              "or write an absolute URL.", file=sys.stderr)
        raise SystemExit(1)

    # Belt and braces: nothing relative may reach the page, whatever shape it had.
    for n, line in enumerate(out_lines, start=1 + line_offset):
        for target in MD_LINK.findall(line):
            if not ALREADY_ABSOLUTE.match(target):
                print(f"{SOURCE}:{n}: relative link {target!r} would not resolve on the "
                      "docs site", file=sys.stderr)
                raise SystemExit(1)
    return "\n".join(out_lines)


def main() -> None:
    text = SOURCE.read_text()

    # Drop the H1 — the page's title comes from frontmatter, and two titles would
    # render one above the other. Every diagnostic below counts lines in the
    # STRIPPED body, so carry the offset and report positions in the source file:
    # a line number an author cannot find in the file they edit is worse than no
    # line number.
    body, n_subs = re.subn(r"\A#[^\n]*\n+", "", text, count=1)
    line_offset = (len(text) - len(body)) and text[: len(text) - len(body)].count("\n")
    if not n_subs:
        line_offset = 0

    body = absolutize_links(body, line_offset)
    assert_mdx_safe(body, line_offset)

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
