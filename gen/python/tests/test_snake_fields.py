"""Every generated Pydantic model field name must be snake_case — the wire is
snake_case proto-JSON, no exceptions. The proto source is snake by buf lint
(FIELD_LOWER_SNAKE_CASE), the corpus by protojson UseProtoNames, and the docs by the
Go TestDocExamplesAreSnakeCase gate; this is the direct guard on the CLIENT layer, so a
pipeline regression that consumed the camelCase json-name schema variant fails loudly
here rather than as a cryptic parity mismatch."""

import inspect
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wire import models  # noqa: E402
from wire.base import WireModel  # noqa: E402

SNAKE = re.compile(r"^[a-z][a-z0-9_]*$")


def test_all_generated_model_fields_are_snake_case():
    offenders = []
    for _, cls in inspect.getmembers(models, inspect.isclass):
        if not (issubclass(cls, WireModel) and cls is not WireModel):
            continue
        for field_name in cls.model_fields:
            if not SNAKE.match(field_name):
                offenders.append(f"{cls.__name__}.{field_name}")
    assert not offenders, (
        "camelCase (or otherwise non-snake_case) field names in generated Pydantic "
        f"models — the wire is snake_case proto-JSON: {sorted(offenders)}"
    )
