#!/usr/bin/env python3
# Canonical proto-JSON round-trip emitter (Pydantic side).
#
# For every VALID corpus case, parse it into the generated model and re-serialize
# it. The output [{id, message, json}] is fed to the Go conformance test
# (TestCanonicalRoundTrip), which asserts the re-emitted JSON decodes — through Go
# protojson — to the same proto message as the original. Run via
# scripts/check-canonical.sh.
import json
import sys

import wire.models as models


def main(corpus_path: str) -> None:
    cases = json.loads(open(corpus_path).read())
    out = []
    for c in cases:
        if not c["valid"]:
            continue
        cls = getattr(models, c["message"])
        obj = cls.model_validate(c["json"])
        # model_dump_json applies the WireModel dump policy (the client's real wire
        # output); re-parse to a plain object so the Go side reads canonical JSON.
        out.append({"id": c["id"], "message": c["message"], "json": json.loads(obj.model_dump_json())})
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main(sys.argv[1])
