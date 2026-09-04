"""The account-setup verbs, on both faces.

They route like a usage report, not like discovery: the destination is read off the
request's own ``exchange`` field and resolved through that Exchange's own manifest.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import threading
from typing import Any

import httpx
import pytest
from test_client import FACES, _IDS, Face, Recorder, _config  # noqa: PLC2701

from ramp_sdk.client import CallError, CallErrorKind
from ramp_sdk.regschema import compile_registration_schema
from ramp_sdk.resolvers import (
    DirectoryUnavailableError,
    ExchangeNotPermittedError,
    ManifestNotExchangeError,
    RegistrationRequirements,
    WellKnownRequirementsReader,
)

_ENDPOINT = "https://exchange.test"
_DIGEST = "sha256:" + "ab" * 32
_SCHEMA = (
    b'{"type":"object","required":["legal_entity"],'
    b'"properties":{"legal_entity":{"type":"string"}}}'
)


class _Resolver:
    def resolve_endpoint(self, _host: str) -> str:
        return _ENDPOINT


class _Requirements:
    """A reader that answers a fixed set of requirements, or raises."""

    def __init__(self, reqs: RegistrationRequirements | Exception) -> None:
        self._reqs = reqs
        self.calls = 0

    def resolve_registration_requirements(self, _exchange: str) -> RegistrationRequirements:
        self.calls += 1
        if isinstance(self._reqs, Exception):
            raise self._reqs
        return self._reqs


def _account_config(reqs: Any = None, **overrides: Any) -> Any:
    return _config(
        endpoint_resolver=_Resolver(),
        registration_requirements=reqs if reqs is not None else _Requirements(
            RegistrationRequirements()
        ),
        **overrides,
    )


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_register_addresses_the_rpc_and_stamps_ver(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "billing_ref": "acct-1", "active": True})
    client = face.client(_account_config(), rec)
    resp = face.run(
        client.register(
            {"exchange": "exchange.test", "registration_data": {"legal_entity": "Acme"}}
        )
    )
    assert resp.billing_ref == "acct-1"
    assert rec.seen[0].url.path == "/ramp.v1.ExchangeService/Register"
    body = rec.body()
    assert body["ver"] == "1.0"
    assert body["exchange"] == "exchange.test"
    # No idempotency key is minted: the message carries none.
    assert "idempotency_key" not in body


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_register_echoes_the_freshly_fetched_digest(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "billing_ref": "acct-1"})
    reqs = _Requirements(RegistrationRequirements(terms_digest=_DIGEST))
    request: dict[str, Any] = {"exchange": "exchange.test"}
    face.run(face.client(_account_config(reqs), rec).register(request))
    assert rec.body()["terms_digest"] == _DIGEST
    assert reqs.calls == 1
    # The caller's message crossed a boundary as an argument, not as a buffer to fill.
    assert "terms_digest" not in request


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_register_a_caller_supplied_digest_suppresses_the_read(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "billing_ref": "acct-1"})
    # The reader raises if it is consulted at all, which is how this asserts the read
    # does not happen.
    reqs = _Requirements(AssertionError("the requirements read must not happen"))
    mine = "sha256:" + "cd" * 32
    face.run(
        face.client(_account_config(reqs), rec).register(
            {"exchange": "exchange.test", "terms_digest": mine}
        )
    )
    assert rec.body()["terms_digest"] == mine
    assert reqs.calls == 0


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_register_pre_checks_the_published_schema(face: Face) -> None:
    schema, verdict = compile_registration_schema(_SCHEMA)
    assert verdict == "accepted"
    reqs = _Requirements(RegistrationRequirements(schema=schema, verdict=verdict))
    rec = Recorder({"ver": "1.0", "billing_ref": "acct-1"})

    with pytest.raises(CallError) as caught:
        face.run(
            face.client(_account_config(reqs), rec).register(
                {"exchange": "exchange.test", "registration_data": {"trading_name": "Acme"}}
            )
        )
    assert caught.value.kind is CallErrorKind.MALFORMED
    assert "legal_entity" in str(caught.value)
    assert rec.seen == []

    # The conforming payload goes through against the same schema.
    face.run(
        face.client(_account_config(reqs), rec).register(
            {"exchange": "exchange.test", "registration_data": {"legal_entity": "Acme"}}
        )
    )
    assert len(rec.seen) == 1


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_register_an_unusable_schema_does_not_block_the_send(face: Face) -> None:
    """Refusing locally would turn a rule about reading a third party's document into a
    denial of service against the caller's own user."""
    schema, verdict = compile_registration_schema(
        b'{"$schema":"https://json-schema.org/draft/2019-09/schema","type":"object"}'
    )
    assert schema is None
    assert verdict == "wrong_dialect"
    rec = Recorder({"ver": "1.0", "billing_ref": "acct-1"})
    reqs = _Requirements(RegistrationRequirements(schema=schema, verdict=verdict))
    face.run(
        face.client(_account_config(reqs), rec).register(
            {"exchange": "exchange.test", "registration_data": {"anything": "goes"}}
        )
    )
    assert len(rec.seen) == 1


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_register_refuses_an_out_of_bounds_payload_before_the_read(face: Face) -> None:
    """A limit that exists to stop work runs before the work it would stop."""
    rec = Recorder({})
    reqs = _Requirements(AssertionError("the bound must run before the read"))
    too_many = {f"m{i}": "v" for i in range(65)}
    with pytest.raises(CallError) as caught:
        face.run(
            face.client(_account_config(reqs), rec).register(
                {"exchange": "exchange.test", "registration_data": too_many}
            )
        )
    assert caught.value.kind is CallErrorKind.MALFORMED
    assert rec.seen == []
    assert reqs.calls == 0


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_register_classifies_a_refused_requirements_read_as_final(face: Face) -> None:
    rec = Recorder({})
    for raised, kind in (
        (ExchangeNotPermittedError("blocked"), CallErrorKind.NOT_SENT),
        (ManifestNotExchangeError("wrong role"), CallErrorKind.NOT_SENT),
        (RuntimeError("connection reset"), CallErrorKind.UNREACHABLE),
    ):
        with pytest.raises(CallError) as caught:
            face.run(
                face.client(_account_config(_Requirements(raised)), rec).register(
                    {"exchange": "exchange.test"}
                )
            )
        assert caught.value.kind is kind, raised
    assert rec.seen == []


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_get_account_status_reads_an_accountless_answer_as_normal(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "billing_ref": "", "active": False})
    resp = face.run(
        face.client(_account_config(), rec).get_account_status({"exchange": "exchange.test"})
    )
    assert resp.billing_ref == ""
    assert resp.active is False
    assert rec.seen[0].url.path == "/ramp.v1.ExchangeService/GetAccountStatus"
    assert rec.body()["ver"] == "1.0"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_account_verbs_refuse_an_unaddressed_request(face: Face) -> None:
    rec = Recorder({})
    client = face.client(_account_config(), rec)
    for exchange in ("", "https://exchange.test", "exchange.test/path", "ex_change.test"):
        for call in (
            lambda e=exchange: client.register({"exchange": e}),
            lambda e=exchange: client.get_account_status({"exchange": e}),
        ):
            with pytest.raises(CallError) as caught:
                face.run(call())
            assert caught.value.kind is CallErrorKind.NOT_SENT, exchange
            assert caught.value.status is None
    assert rec.seen == []


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_account_verbs_caller_ver_wins(face: Face) -> None:
    rec = Recorder({"ver": "1.0", "billing_ref": "acct-1"})
    client = face.client(_account_config(), rec)
    face.run(client.register({"exchange": "exchange.test", "ver": "9.9"}))
    assert rec.body(0)["ver"] == "9.9"
    face.run(client.get_account_status({"exchange": "exchange.test", "ver": "9.9"}))
    assert rec.body(1)["ver"] == "9.9"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_peer_message_carries_the_typed_reason_and_nothing_else(face: Face) -> None:
    """The peer's own sentence reaches a caller as a VALUE, and only when the answer
    carried a typed reason: transport-synthesised text is the transport's, not the
    peer's."""
    typed = Recorder(
        {
            "code": "failed_precondition",
            "message": "envelope prose",
            "details": [
                {
                    "type": "ramp.v1.ErrorDetail",
                    "debug": {
                        "domain": "ramp.v1.ExchangeService",
                        "message": "terms have moved",
                        "registrationFailure": {
                            "reason": "REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE"
                        },
                    },
                }
            ],
        },
        412,
    )
    with pytest.raises(CallError) as caught:
        face.run(face.client(_account_config(), typed).register({"exchange": "exchange.test"}))
    assert caught.value.peer_message == "terms have moved"
    # The token stays a token: prose never leaks into the field a caller branches on.
    assert " " not in (caught.value.reason or "")

    untyped = Recorder({"code": "unavailable", "message": "draining"}, 503)
    with pytest.raises(CallError) as caught:
        face.run(
            face.client(_account_config(), untyped).get_account_status(
                {"exchange": "exchange.test"}
            )
        )
    assert caught.value.peer_message == ""


# ---------------------------------------------------------------------------
# The requirements reader
# ---------------------------------------------------------------------------


def _manifest_reader(body: str) -> tuple[WellKnownRequirementsReader, list[int]]:
    hits = [0]

    def respond(_request: httpx.Request) -> httpx.Response:
        hits[0] += 1
        return httpx.Response(200, content=body.encode(), headers={"content-type": "application/json"})

    http = httpx.Client(transport=httpx.MockTransport(respond))
    return WellKnownRequirementsReader(scheme="http", http=http), hits


def _manifest(**extra: Any) -> str:
    doc: dict[str, Any] = {"role": "ROLE_EXCHANGE", "endpoint": _ENDPOINT}
    doc.update(extra)
    return json.dumps(doc)


def test_reader_fetches_afresh_on_every_read() -> None:
    reader, hits = _manifest_reader(_manifest(terms_digest=_DIGEST))
    assert reader.resolve_registration_requirements("exchange.test").terms_digest == _DIGEST
    reader.resolve_registration_requirements("exchange.test")
    assert hits[0] == 2


def test_reader_refuses_a_manifest_that_is_not_an_exchange() -> None:
    for body in (
        _manifest(role="ROLE_BROKER"),
        json.dumps({"endpoint": _ENDPOINT}),
    ):
        reader, _ = _manifest_reader(body)
        with pytest.raises(ManifestNotExchangeError):
            reader.resolve_registration_requirements("exchange.test")


def test_reader_refuses_before_dialling() -> None:
    reader, hits = _manifest_reader(_manifest())
    with pytest.raises(ValueError):
        reader.resolve_registration_requirements("exchange.test/path")
    assert hits[0] == 0

    def respond(_request: httpx.Request) -> httpx.Response:  # pragma: no cover - never called
        raise AssertionError("the allow overlay must run before the fetch")

    blocked = WellKnownRequirementsReader(
        scheme="http", http=httpx.Client(transport=httpx.MockTransport(respond)), allow=lambda _d: False
    )
    with pytest.raises(ExchangeNotPermittedError):
        blocked.resolve_registration_requirements("exchange.test")


def test_reader_measures_the_schema_over_the_served_bytes() -> None:
    """The cap is defined over the bytes AS SERVED. A schema padded past it on the wire
    that would minify under it must be refused here exactly as the Exchange refuses it,
    or a client pre-checks against a schema nobody enforces."""
    padded = '{"type":"object",' + " " * 20_000 + '"title":"x"}'
    body = '{"role":"ROLE_EXCHANGE","account_registration":{"data_schema":' + padded + "}}"
    reader, _ = _manifest_reader(body)
    got = reader.resolve_registration_requirements("exchange.test")
    assert got.verdict == "too_large"
    assert got.schema is None


# The transport default, dialled for real.
#
# The domain this reader fetches comes off a RegisterRequest, so it is chosen by the
# caller at runtime rather than by the operator at start-up. That is the provenance that
# takes the SSRF-guarded transport — the rule the Go oracle states in the options struct
# these readers mirror — and it is the same threat shape as the offer-derived legs. A
# reader that dialled a caller-named host unguarded would turn ``register`` into a blind
# GET aimed wherever that value pointed, and ``is_bare_domain`` accepts ``localhost`` and
# ``169.254.169.254`` because they are well-formed domains.
#
# Real-dial rather than a mocked transport, mirroring test_resolvers_ssrf_gate.py: a mock
# would assert which factory was referenced, and what matters is which addresses the
# process will actually connect to.
def _serve_manifest() -> tuple[http.server.ThreadingHTTPServer, int]:
    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # BaseHTTPRequestHandler contract
            body = b'{"role":"ROLE_EXCHANGE","endpoint":"https://exchange.test"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def test_reader_default_transport_refuses_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default client refuses a reserved address; an injected one reaches the same
    server, so the refusal is the guard's verdict and not an unreachable origin.

    ALLOW_INSECURE is set so the http scheme is not the refuser — the ADDRESS guard is
    what this isolates, exactly as the guarded-factory pillars do.
    """
    monkeypatch.delenv("SKIP_SSRF", raising=False)
    monkeypatch.setenv("ALLOW_INSECURE", "true")
    server, port = _serve_manifest()
    host = f"127.0.0.1:{port}"
    try:
        # The default: no client injected, so the guarded transport, which refuses a
        # reserved address at the dial seam. The guard's SsrfError is an OSError, so it
        # reaches the caller as the transport failure this face documents.
        guarded = WellKnownRequirementsReader(scheme="http")
        with pytest.raises(DirectoryUnavailableError):
            guarded.resolve_registration_requirements(host)

        # The same host, same server, through an injected client — so the refusal above
        # is the guard's verdict and not an unreachable origin.
        plain = httpx.Client()
        try:
            injected = WellKnownRequirementsReader(scheme="http", http=plain)
            assert injected.resolve_registration_requirements(host).verdict == "not_published"
        finally:
            plain.close()
    finally:
        server.shutdown()
        server.server_close()


# The default reader is built ONCE per client, and closed with it.
#
# Its transport is the SSRF-guarded one, so a reader built per call opens a connection
# pool per registration and closes none — measured before this was fixed: three calls,
# three clients, none closed. Go resolves the same default once at NewClient; both faces
# here do it in their constructor, which is the same tier.
#
# Directly observable in Python, unlike TypeScript, because the client owns the transport
# and has a close() to prove it with; the TS side pins the same invariant structurally.
def test_client_builds_one_requirements_transport_and_closes_it() -> None:
    from ramp_sdk.sync import Client as SyncClient

    cfg = _config(endpoint_resolver=_Resolver())
    assert cfg.registration_requirements is None
    client = SyncClient(cfg, http=httpx.Client(transport=httpx.MockTransport(
        lambda _r: httpx.Response(200, json={"ver": "1.0", "billing_ref": "acct-1"})
    )))
    try:
        # Filled in once, on a COPY: a caller may hold its config and reuse it.
        assert client._config.registration_requirements is not None
        assert cfg.registration_requirements is None
        owned = client._requirements_http
        assert owned is not None
        assert not owned.is_closed
    finally:
        client.close()
    assert owned.is_closed


def test_client_leaves_an_injected_reader_alone() -> None:
    """A reader the caller injected carries a transport the caller owns, so the client
    builds nothing and closes nothing — the same rule the two RPC legs follow."""
    from ramp_sdk.sync import Client as SyncClient

    injected = _Requirements(RegistrationRequirements())
    client = SyncClient(_account_config(injected), http=httpx.Client(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"ver": "1.0"}))
    ))
    try:
        assert client._requirements_http is None
        assert client._config.registration_requirements is injected
    finally:
        client.close()
