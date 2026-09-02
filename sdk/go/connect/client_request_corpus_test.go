package connect_test

// Go replay of the client-request corpus (client-request-vectors.json).
//
// The corpus is the cross-language contract for where each verb goes and what it stamps,
// so Go replays it too rather than only emitting it — a corpus its own oracle does not
// consume proves nothing about the oracle.
//
// It is a thin replay by design: the emitter next door already drives the real client
// against a recording server, so what is left to assert is that the COMMITTED record
// still describes it. That is what makes the file a contract rather than a snapshot — a
// verb that starts addressing a different method, or overwriting a caller's idempotency
// key, fails here with the case named, before the Python and TypeScript replays see it.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func TestClientRequestCorpusReplay(t *testing.T) {
	raw, err := os.ReadFile(clientRequestVectorsPath) //nolint:gosec // a committed test vector
	if err != nil {
		t.Fatalf("read %s: %v", clientRequestVectorsPath, err)
	}
	var doc struct {
		Vectors []clientRequestVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", clientRequestVectorsPath, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors — the replay would assert nothing", clientRequestVectorsPath)
	}

	fresh := buildClientRequestVectors(t)
	if len(fresh) != len(doc.Vectors) {
		t.Fatalf("the committed corpus has %d vectors and a fresh capture has %d",
			len(doc.Vectors), len(fresh))
	}
	for i, want := range doc.Vectors {
		t.Run(want.Name, func(t *testing.T) {
			got := fresh[i]
			if got != want {
				t.Errorf("captured %+v, committed %+v", got, want)
			}
			// The path is the claim "the same verbs" rests on, so it is asserted as a
			// SHAPE too, not only against the recorded string: a Connect unary path is
			// the fully-qualified service and the method, and a corpus that recorded a
			// malformed one would agree with itself forever.
			if !strings.HasPrefix(want.Path, "/ramp.v1.") || strings.Count(want.Path, "/") != 2 {
				t.Errorf("path %q is not /<fully-qualified service>/<method>", want.Path)
			}
			if want.Ver == "" {
				t.Errorf("no protocol version stamped")
			}
		})
	}
	// The version the client stamps has one owner. A vector that recorded a literal would
	// keep passing after a protocol bump moved it.
	//
	// The exception is derived from the naming convention rather than listed, so a new
	// verb's fill-when-empty case joins it without editing this test — and it is an
	// exception with its own assertion, not a hole: a "caller ver wins" vector that
	// recorded the stamped default would be proving the opposite of its name.
	const callerVerSuffix = "_caller_ver_wins"
	callerVer := 0
	for _, v := range doc.Vectors {
		if strings.HasSuffix(v.Name, callerVerSuffix) {
			callerVer++
			if v.Ver == helpers.ProtocolVersion {
				t.Errorf("%s: ver = %q, which is the value the client stamps — this case "+
					"exists to show the CALLER's own value surviving, so recording the "+
					"default makes it vacuous", v.Name, v.Ver)
			}
			continue
		}
		if v.Ver != helpers.ProtocolVersion {
			t.Errorf("%s: ver = %q, want the SDK's ProtocolVersion %q",
				v.Name, v.Ver, helpers.ProtocolVersion)
		}
	}
	if callerVer == 0 {
		t.Errorf("no %q vector — the fill-when-empty rule is unpinned in the ports, which "+
			"replay this corpus and have no other case for it", callerVerSuffix)
	}
}
