package conformance

// Drift guard: what an ErrorDetail's domain may name.
//
// `domain` is the one field of ErrorDetail the contract leaves open. It carries no
// protovalidate rule, the proto describes it only as "Stable grouping for the failing
// surface, e.g. ramp.v1.ExchangeService", and ADR-019 hedges the same way — an example,
// never a closed set. That is the right call for a field whose whole job is grouping for
// generic tooling: a rule enumerating legal values would have to move every time a tier
// does.
//
// It is not, however, a licence for anything. A grouping key groups nothing if two writers
// spell the same surface differently, or if one names a surface that does not exist, and
// both have happened. The values in the committed corpora fall into exactly two shapes,
// and the SUFFIX is what separates them:
//
//   - `<package>.<Name>Service` names an RPC service the contract DEFINES. An answer
//     carrying ramp.v1.ExchangeService came from that service.
//   - `<package>.<BareNoun>` names a TIER that is not a service and appears in no
//     descriptor — ramp.v1.Edge for a delivery edge, ramp.v1.Client for a refusal the
//     client computed before sending. Neither is a proto symbol, and neither should be:
//     the surface that refused is a real thing whether or not the contract has a message
//     for it.
//
// So the rule this holds is narrow and checkable: a Service-suffixed domain must name a
// service that exists, and a bare-noun domain must not name one. That catches the failure
// this guard was written for — a corpus fixture naming ramp.v1.RegistrationService, a
// service the contract has never defined, sitting beside two sibling vectors that use
// ramp.v1.ExchangeService for the same reason block.
//
// The values are READ from the SDK's committed vectors rather than restated here, for the
// reason ver_field_contract_test.go gives at length: nothing in conformance depends on
// sdk/, by design, since it is the guard tier BELOW the SDKs. A committed file generated
// from the real constructors, and already replayed by the Python and TypeScript parity
// suites, is a data read exactly like the corpus and the doc scans.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The committed corpora that carry an ErrorDetail domain. Every one of them is emitted by
// a Go generator from the real builders and replayed by both ports.
const (
	errorDetailVectors       = "../sdk/go/helpers/testdata/error-detail-vectors.json"
	connectErrorVectors      = "../sdk/go/connect/testdata/connect-error-vectors.json"
	synthesizedDetailVectors = "../sdk/go/connect/testdata/synthesized-detail-vectors.json"
)

// domainUse is one recorded domain and enough context to name it in a failure.
type domainUse struct {
	Corpus string
	Vector string
	Domain string
}

// recordedDomains reads every domain the corpora carry. A read or parse error is fatal
// rather than skipped: a missing file means this guard has lost its anchor, and passing
// silently would be worse than failing.
func recordedDomains(t *testing.T) []domainUse {
	t.Helper()
	var out []domainUse

	read := func(path string, into any) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if err := json.Unmarshal(b, into); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
	}

	var details struct {
		Vectors []struct{ Name, Domain string } `json:"vectors"`
	}
	read(errorDetailVectors, &details)
	for _, v := range details.Vectors {
		out = append(out, domainUse{errorDetailVectors, v.Name, v.Domain})
	}

	var envelopes struct {
		Vectors []struct {
			Name   string                  `json:"name"`
			Expect struct{ Domain string } `json:"expect"`
		} `json:"vectors"`
	}
	read(connectErrorVectors, &envelopes)
	for _, v := range envelopes.Vectors {
		out = append(out, domainUse{connectErrorVectors, v.Name, v.Expect.Domain})
	}

	var synthesized struct {
		Precheck []struct{ Name, Domain string } `json:"registration_precheck"`
		Edge     []struct{ Name, Domain string } `json:"edge_refusal"`
	}
	read(synthesizedDetailVectors, &synthesized)
	for _, v := range synthesized.Precheck {
		out = append(out, domainUse{synthesizedDetailVectors, v.Name, v.Domain})
	}
	for _, v := range synthesized.Edge {
		out = append(out, domainUse{synthesizedDetailVectors, v.Name, v.Domain})
	}
	return out
}

// contractServiceNames returns every service the contract defines, fully qualified.
// Walked from the descriptors through the one package list, so a contract package added
// there is covered without an edit here.
func contractServiceNames() map[string]bool {
	out := map[string]bool{}
	for _, fd := range ContractFiles() {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			out[string(services.Get(i).FullName())] = true
		}
	}
	return out
}

// A domain either names a service the contract defines, or names a tier that is not one —
// and the Service suffix says which, so a reader can tell them apart without a lookup.
func TestErrorDetailDomain_SuffixSaysWhetherItNamesAService(t *testing.T) {
	uses := recordedDomains(t)
	if len(uses) == 0 {
		t.Fatal("no domains were read — this guard would vacuously pass")
	}
	services := contractServiceNames()
	if len(services) == 0 {
		t.Fatal("the contract defines no services — this guard has lost its anchor")
	}

	var checked int
	for _, u := range uses {
		if u.Domain == "" {
			// Legal: a detail may carry no domain, and one vector records exactly that.
			continue
		}
		checked++
		if !inAContractPackage(u.Domain) {
			t.Errorf("%s/%s: domain %q is outside every contract package, so nothing "+
				"groups by it", u.Corpus, u.Vector, u.Domain)
			continue
		}
		named := services[u.Domain]
		switch {
		case strings.HasSuffix(u.Domain, "Service") && !named:
			t.Errorf("%s/%s: domain %q is spelled as a service and the contract defines "+
				"none by that name; either it names a real service or it drops the "+
				"suffix and names the tier that refused",
				u.Corpus, u.Vector, u.Domain)
		case !strings.HasSuffix(u.Domain, "Service") && named:
			t.Errorf("%s/%s: domain %q names a service without saying so; the suffix is "+
				"what tells a reader an RPC service refused rather than a tier",
				u.Corpus, u.Vector, u.Domain)
		}
	}
	if checked == 0 {
		t.Fatal("every recorded domain was empty — this guard would vacuously pass")
	}
}

// inAContractPackage reports whether a domain sits under one of the contract's packages.
// The tiers that are not services live there too: ramp.v1.Edge is not a proto symbol, but
// putting it anywhere else would make the namespace mean nothing.
func inAContractPackage(domain string) bool {
	for _, pkg := range ContractPackages() {
		if strings.HasPrefix(domain, pkg+".") &&
			!strings.Contains(strings.TrimPrefix(domain, pkg+"."), ".") {
			return true
		}
	}
	return false
}

// The meta-tests: the detector answers for the shapes it claims to. Without these a typo
// in the suffix check reads as a pass.
func TestErrorDetailDomain_DetectorAnswersForBothShapes(t *testing.T) {
	services := contractServiceNames()

	for _, name := range []string{"ramp.v1.ExchangeService", "ramp.v1.CatalogService"} {
		if !services[name] {
			t.Errorf("%s is not among the contract's services, so the guard's own "+
				"positive case is wrong", name)
		}
	}
	for _, name := range []string{"ramp.v1.Edge", "ramp.v1.Client", "ramp.v1.RegistrationService"} {
		if services[name] {
			t.Errorf("%s is a contract service, which this guard assumes it is not", name)
		}
	}
	for _, in := range []string{"ramp.v1.Edge", "ramp.admin.v1.AdminService"} {
		if !inAContractPackage(in) {
			t.Errorf("%q was read as outside every contract package", in)
		}
	}
	for _, out := range []string{"", "Edge", "google.rpc.ErrorInfo", "ramp.v1.a.b"} {
		if inAContractPackage(out) {
			t.Errorf("%q was read as inside a contract package", out)
		}
	}
}

// Guard against the descriptor walk quietly finding nothing, which would make every
// membership answer above vacuously false.
func TestErrorDetailDomain_ContractServicesAreReachable(t *testing.T) {
	var walked int
	for _, fd := range ContractFiles() {
		walked += fd.Services().Len()
	}
	if walked == 0 {
		t.Fatal("no services reached through ContractFiles()")
	}
}
