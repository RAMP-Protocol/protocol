package helpers

import "github.com/santhosh-tekuri/jsonschema/v6"

// RefusingSchemaLoaderForTest exposes the SSRF backstop to the package's external
// test binary. It is declared in a _test.go file, so it is not part of the shipped
// surface and never reaches the API-parity gate — the loader is an implementation
// detail that only a test needs to reach past the scan to exercise.
func RefusingSchemaLoaderForTest() jsonschema.URLLoader { return refusingSchemaLoader{} }

// MaxRequestAcceptanceItemsForTest exposes the canonicalization item cap so the
// external test binary can pin it to the wire rule on
// AgentRequestAcceptancePayload.items. Declared in a _test.go file, so it never
// reaches the API-parity gate.
const MaxRequestAcceptanceItemsForTest = maxRequestAcceptanceItems
