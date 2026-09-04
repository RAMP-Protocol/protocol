// Wire constants shared across the SDK — TS port of the sdk/go oracle
// (helpers/constants.go + core/requestid.go). Encoding is negotiated per hop via
// Content-Type (ADR-020): application/proto for binary, application/json for
// canonical proto-JSON. The Go layer splits RequestIDHeader across
// helpers/constants.go and core/requestid.go; the single TS module exposes all
// eight values once. Pinned to wire-constants-vectors.json.
//
// Also home to the pure receive-side rule for WellKnownManifest.ver, so the
// constant and the check that reads it sit together.

/** ContentTypeProto is the Content-Type for binary protobuf bodies. */
export const ContentTypeProto = "application/proto";
/** ContentTypeJSON is the Content-Type for canonical proto-JSON bodies. */
export const ContentTypeJSON = "application/json";
/** ConnectProtocolVersionHeader carries the Connect unary protocol version. */
export const ConnectProtocolVersionHeader = "Connect-Protocol-Version";
/** ConnectProtocolVersion is the only Connect protocol version RAMP speaks. */
export const ConnectProtocolVersion = "1";
/**
 * ProtocolVersion is the RAMP protocol version stamped on the `ver` field of
 * every RAMP message — NOT the Connect transport version above. Senders stamp
 * it from here so a protocol bump is a single edit; receivers treat `ver` as
 * advisory. The /.well-known/ramp.json document carries its own version in a
 * separate namespace, which this constant does NOT supply — that is
 * WellKnownManifestVersion.
 */
export const ProtocolVersion = "1.0";
/**
 * WellKnownManifestVersion is the version of the /.well-known/ramp.json DOCUMENT
 * layout, stamped on WellKnownManifest.ver by every party that serves one. A
 * namespace separate from ProtocolVersion and never derived from it: a change
 * to the manifest layout bumps both numbers, a protocol change that leaves the
 * manifest untouched bumps only ProtocolVersion. Both read "1.0" today because
 * neither has moved yet; neither is derived from the other. The receive-side
 * check a manifest reader applies is manifestVersionRefusal.
 */
export const WellKnownManifestVersion = "1.0";
/** RequestIDHeader correlates a request across services and the edge. */
export const RequestIDHeader = "X-Request-ID";
/** SignatureAgentHeader carries the signer's Web Bot Auth key-directory URL. */
export const SignatureAgentHeader = "Signature-Agent";

const ASCII_DIGITS = /^[0-9]+$/;

/** The MAJOR run of a MAJOR.MINOR string, or undefined when `ver` is not one.
 * Both runs must be non-empty ASCII digits joined by exactly one dot; a missing
 * minor, a patch component, a leading "v", surrounding whitespace or a non-digit
 * is not a version this rule recognises. */
function parseMajor(ver: string): string | undefined {
	const dot = ver.indexOf(".");
	if (dot < 0) return undefined;
	const major = ver.slice(0, dot);
	const minor = ver.slice(dot + 1);
	if (!ASCII_DIGITS.test(major) || !ASCII_DIGITS.test(minor)) return undefined;
	return major;
}

/**
 * The receive-side rule for WellKnownManifest.ver, as a pure verdict.
 *
 * Returns undefined when the document is accepted — its MAJOR equals the major
 * of WellKnownManifestVersion, whatever the MINOR. Otherwise returns the reason:
 * an unrecognised major, a value that is not MAJOR.MINOR, or an absent member
 * (undefined, null, or any non-string is how a missing `ver` arrives from
 * JSON.parse). Absent is refused because a document with no version is one whose
 * layout the reader cannot classify. Why a minor is accepted, and why the gate
 * runs before any other member is read and fails closed, is stated once on
 * WellKnownManifest.ver in the proto.
 *
 * The message names the value found so an operator can tell a version mismatch
 * from a network failure, clipped to MAX_ECHOED_VER characters: the body is read
 * up to 1 MiB and a refusal is never cached, so an unclipped echo would let a
 * hostile origin size every error. The three SDK languages pin this verdict to a
 * shared corpus. The error a resolver throws for a refusal is
 * ManifestVersionRefused.
 */
export function manifestVersionRefusal(ver: unknown): string | undefined {
	const acceptMajor = parseMajor(WellKnownManifestVersion);
	if (acceptMajor === undefined) {
		throw new Error(`WellKnownManifestVersion is not MAJOR.MINOR: ${WellKnownManifestVersion}`);
	}
	if (typeof ver !== "string" || ver === "") {
		return `ver is absent, accept major ${acceptMajor}`;
	}
	const major = parseMajor(ver);
	if (major === undefined) {
		return `ver ${JSON.stringify(echoVer(ver))} is not MAJOR.MINOR, accept major ${acceptMajor}`;
	}
	if (major !== acceptMajor) {
		return `ver ${JSON.stringify(echoVer(ver))} has major ${major}, accept major ${acceptMajor}`;
	}
	return undefined;
}

/** How much of a refused `ver` an error message repeats. Go and Python clip at
 * the same length, so an operator reading three SDKs' logs sees the same prefix. */
const MAX_ECHOED_VER = 64;

function echoVer(ver: string): string {
	return ver.length <= MAX_ECHOED_VER ? ver : `${ver.slice(0, MAX_ECHOED_VER)}...`;
}
