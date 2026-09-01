"""A proto comment's FIRST paragraph must survive into the generated clients.

protoschema splits a multi-paragraph proto comment: paragraph one becomes the JSON
Schema `title`, the remainder becomes `description`. The merge step used to remove every
key named `title` from the intermediate document, which cost two different things:

  * the head of every multi-paragraph comment. `Offer.signature` reached Pydantic and Zod
    describing the canonical-signing rules without ever saying the field IS the signature
    or that it is required. Go was unaffected — ramp.pb.go carries the whole comment — so
    the loss was visible only in these two clients.
  * three whole FIELDS. `Offer.title`, `ResourceEntry.title` and `UsageAsset.title` are
    proto fields whose NAME is `title`, so a blanket key-strip deleted them from
    `properties` outright. No corpus case populates any of them, so the canonical
    round-trip gate saw nothing to lose and stayed green.

merge_schema.assert_no_surviving_titles is the structural guard: it fails the build when
a title reaches the write, so a site the resolver does not reach can no longer ship. This
file is the behavioral half, over the COMMITTED output a consumer actually installs.
Titles that merely restate the field's own enum or message type carry nothing the comment
said and are still dropped; that is asserted too, so a fix cannot over-correct into noise.

Run:  PYTHONPATH=gen/python python3 -m pytest gen/python/tests/test_comment_first_paragraph.py -q
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wire import models  # noqa: E402

# gen/python/tests -> gen/python -> gen -> <repo root>
_REPO_ROOT = Path(__file__).resolve().parents[3]
_ZOD = _REPO_ROOT / "gen" / "ts" / "wire" / "schemas.ts"

#: Fields whose NAME is `title`. Present in the proto, and absent from both clients until
#: the strip was replaced. One entry per message that declares one.
TITLE_FIELDS = ("Offer", "ResourceEntry", "UsageAsset")

#: (model, field, the comment head that must open the generated description). Each is a
#: field whose proto comment carries a blank line, so protoschema routed its first
#: paragraph into `title`. Spot checks, not the whole set — the build-time guard owns
#: completeness; these name the cases a reader can check against the .proto by eye.
FIRST_PARAGRAPH_HEADS = (
    ("Offer", "signature", "REQUIRED. Hex-encoded detached Ed25519 signature over the canonical"),
    ("Requester", "scopes", "Entitlement scopes. Declare what the requester can access."),
    ("License", "uri", "Canonical identity of the license document (RFC 3986)."),
    ("ResourceQuery", "supported_profiles", "Domain extension profiles the caller understands."),
    ("Pricing", "unit", 'Metering basis — the "per what" of PER_UNIT pricing.'),
)

#: (model, field, the type-derived title that must NOT appear). protoschema fills `title`
#: in from the field's enum type when the comment is a single paragraph, so prepending it
#: would inject the type's name into a field whose comment lost nothing.
TYPE_DERIVED_TITLES = (
    ("DisputeRequest", "reason", "Dispute Reason"),
    ("Pricing", "model", "Pricing Model"),
    ("WellKnownManifest", "role", "Role"),
    ("ResourceIdentity", "c2pa_status", "C2PA Status"),
)


def _description(model_name: str, field_name: str) -> str:
    cls = getattr(models, model_name)
    field = cls.model_fields[field_name]
    assert field.description is not None, f"{model_name}.{field_name} carries no description"
    return field.description


def _collapsed(text: str) -> str:
    """Whitespace-insensitive form. A proto comment wraps across `//` lines, so the
    generated description carries the author's line breaks; only the words are the rule."""
    return re.sub(r"\s+", " ", text).strip()


def _zod_schema_of(source: str, message: str) -> str:
    """One generated Zod schema. json-schema-to-zod emits each on a single line."""
    marker = f"export const {message}Schema = "
    start = source.index(marker)
    return source[start : source.index("\n", start)]


def test_fields_named_title_reach_the_generated_models():
    missing = [m for m in TITLE_FIELDS if "title" not in getattr(models, m).model_fields]
    assert not missing, (
        "proto field `title` is absent from the generated Pydantic models "
        f"({missing}) — a key-strip is deleting the field, not a JSON-Schema keyword"
    )


def test_fields_named_title_reach_the_generated_zod_schemas():
    source = _ZOD.read_text(encoding="utf-8")
    missing = [m for m in TITLE_FIELDS if '"title"' not in _zod_schema_of(source, m)]
    assert not missing, (
        "proto field `title` is absent from the generated Zod schemas "
        f"({missing}) — a key-strip is deleting the field, not a JSON-Schema keyword"
    )


def test_first_comment_paragraph_opens_the_generated_description():
    for model_name, field_name, head in FIRST_PARAGRAPH_HEADS:
        description = _collapsed(_description(model_name, field_name))
        assert description.startswith(_collapsed(head)), (
            f"{model_name}.{field_name} description does not open with its comment's "
            f"first paragraph — got {description[:80]!r}"
        )


def test_type_derived_titles_are_not_prepended():
    for model_name, field_name, type_title in TYPE_DERIVED_TITLES:
        description = _description(model_name, field_name)
        # The RAW description, and the paragraph break, are both load-bearing here: a
        # carried title is prepended as its own paragraph, so that is the shape to refuse.
        # A collapsed comparison would fire on WellKnownManifest.role, whose genuine
        # comment legitimately opens with the word "Role".
        assert not description.startswith(f"{type_title}\n\n"), (
            f"{model_name}.{field_name} description opens with its own TYPE name "
            f"({type_title!r}) as a carried paragraph — a title protoschema derived from "
            "the type restates the type and must stay dropped"
        )
        assert description.strip() != type_title, (
            f"{model_name}.{field_name} description IS its own type name ({type_title!r})"
        )


def test_message_comment_first_paragraph_reaches_the_zod_schemas():
    """The message-level half, which only the Zod export renders.

    datamodel-code-generator emits no class docstring, so a message's description is
    invisible in models.py; json-schema-to-zod emits it as the schema's own .describe(),
    where the loss was observable.
    """
    source = _ZOD.read_text(encoding="utf-8")
    for head in (
        "Offer — A single resource offer from an Exchange.",
        "LicenseTerm — Universal licensing unit.",
        "Requester — Universal identity for any RAMP client.",
    ):
        assert head in source, (
            f"message comment head {head!r} is missing from the generated Zod schemas"
        )
