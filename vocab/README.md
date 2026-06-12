# RAMP Vocabulary Registry

Canonical token values for `Restriction.permitted/prohibited` and `Quota.metric` fields in the RAMP protocol.

---

## Purpose

`Restriction` and `Quota` messages carry **open string vocabularies** — the protocol does not enumerate every possible token in the proto file. This registry defines the canonical tokens, their sources, and their aliases. It is the interoperability contract between publishers and agents.

Two boundaries enforce vocabulary discipline:

- **Build-time (`make quality`, hard FAIL):** scans committed fixtures. An unregistered bare token in our own fixtures is a typo to fix or a registry PR.
- **Ingestion-time (`PushResources` validation, WARN):** scans third-party publisher data. Unregistered bare tokens generate `PushResourcesResponse.warnings[]` with edit-distance suggestions.

**Namespacing:** bare token = canonical registry (`ai-train`); `vendor:token` = deliberate custom (`acme:proprietary-use`). The linter warns on unregistered bare tokens; namespaced tokens pass silently.

---

## File layout

```
vocab/
  restriction-values/
    function.json     — RESTRICTION_KIND_FUNCTION permitted/prohibited values
    geography.json    — RESTRICTION_KIND_GEOGRAPHY permitted/prohibited values
    user-type.json    — RESTRICTION_KIND_USER_TYPE permitted/prohibited values
  quota-metrics.json  — Quota.metric values
```

---

## Registry entry format

### Restriction values

```json
{
  "version": "1.0.0",
  "kind": "restriction-values",
  "axis": "<function|geography|user-type>",
  "description": "...",
  "tokens": [
    {
      "token": "canonical-token",     // exact string used on the wire
      "description": "...",           // normative, one paragraph
      "source": "...",                // RSL-1.0 | IETF-AIPREF | CC | copyright-law | RAMP | ...
      "aliases": ["other-standard"],  // equivalent tokens from other standards; not canonical
      "notes": "..."                  // optional: edge cases, interactions, warnings
    }
  ]
}
```

### Quota metrics

```json
{
  "version": "1.0.0",
  "kind": "quota-metrics",
  "description": "...",
  "metrics": [
    {
      "metric": "canonical-metric",   // exact string used on the wire
      "description": "...",
      "unit": "...",                  // human-readable unit label
      "source": "...",
      "notes": "..."
    }
  ]
}
```

---

## Contributing

1. Open a PR against this file.
2. Add the token under the appropriate file with all required fields.
3. If the token is an alias of an existing standard (RSL, AIPREF, CC, ISO), reference the source.
4. If promoting an `OTHER` token that appears frequently in publisher data, include evidence (push logs, publisher count) in the PR description.
5. `make buf-lint` and `make quality` must pass.
