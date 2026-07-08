// Package conformance — reachability_test.go holds INV-4, the orphan-type guard.
//
// The contract reaches the wire through exactly three delivery channels:
//   1. RPC bodies        — every service method's input and output message
//   2. served documents  — the manifest a participant publishes at .well-known
//   3. the error envelope — ErrorDetail and the typed failure reasons it carries
//
// A message or enum that NO channel can carry is an orphan: schema that is
// defined but undeliverable — dead weight, or (worse) a wiring mistake where a
// new type was authored but never attached to a body. This guard walks the
// descriptor from the three roots and fails on any unreachable type. It is the
// opt-OUT counterpart to a hand-maintained "is everything wired?" checklist: a
// new message is covered the instant it is defined — wire it into an RPC body,
// the manifest, or the error envelope, or delete it, or this test fails.
package conformance

import (
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// outOfBandRoots are the delivery roots that are NOT an RPC input/output: served
// documents and the transport-error envelope. Each states why it is a root. The
// test proves every entry is BOTH a real top-level message AND genuinely not
// already reachable from an RPC body — so an entry that becomes RPC-reachable is
// flagged as stale instead of silently masking an orphan beneath it.
var outOfBandRoots = map[string]string{
	"WellKnownManifest": "served at /.well-known/ramp.json by every participant (capabilities, role; identity keys moved to WBAFile)",
	"WBAFile":           "served at /.well-known/http-message-signatures-directory — the pure WBA JWK Set (identity keys + revocation_url)",
	"ErrorDetail":       "the transport-error envelope; carries the seven typed failure reasons",
	"KeyRevocationList": "served key-revocation document (thumbprint list), fetched out of band from WBAFile.revocation_url",
	"AgentAcceptancePayload": "canonical signing structure for AgentAcceptance (RAMP-102 §1); never sent on the wire — the signer and verifier deterministically marshal it to derive byte-identical signed bytes",
}

// refFields visits the message/enum each of md's fields references (following the
// value side of a map, and skipping synthetic map-entry messages).
func refFields(md protoreflect.MessageDescriptor, onMsg func(protoreflect.MessageDescriptor), onEnum func(protoreflect.EnumDescriptor)) {
	visit := func(fd protoreflect.FieldDescriptor) {
		switch fd.Kind() {
		case protoreflect.MessageKind, protoreflect.GroupKind:
			onMsg(fd.Message())
		case protoreflect.EnumKind:
			onEnum(fd.Enum())
		}
	}
	fs := md.Fields()
	for i := 0; i < fs.Len(); i++ {
		fd := fs.Get(i)
		if fd.IsMap() {
			visit(fd.MapValue())
		} else {
			visit(fd)
		}
	}
}

// reachFrom computes the set of messages and enums transitively referenced from
// the given seed messages (the seeds themselves are included in reachMsg).
func reachFrom(seeds []protoreflect.MessageDescriptor) (reachMsg map[protoreflect.FullName]bool, reachEnum map[protoreflect.FullName]bool) {
	reachMsg = map[protoreflect.FullName]bool{}
	reachEnum = map[protoreflect.FullName]bool{}
	var queue []protoreflect.MessageDescriptor
	enqueue := func(md protoreflect.MessageDescriptor) {
		if md == nil || reachMsg[md.FullName()] {
			return
		}
		reachMsg[md.FullName()] = true
		queue = append(queue, md)
	}
	for _, s := range seeds {
		enqueue(s)
	}
	for len(queue) > 0 {
		md := queue[0]
		queue = queue[1:]
		refFields(md, enqueue, func(ed protoreflect.EnumDescriptor) { reachEnum[ed.FullName()] = true })
	}
	return
}

// allDefinedTypes walks the contract files and returns every message (excluding
// synthetic map-entry messages) and every enum they define, indexed by full
// name, plus a name→descriptor index of TOP-LEVEL messages for root lookup.
func allDefinedTypes() (msgs map[protoreflect.FullName]protoreflect.MessageDescriptor, enums map[protoreflect.FullName]protoreflect.EnumDescriptor, topByName map[string]protoreflect.MessageDescriptor) {
	msgs = map[protoreflect.FullName]protoreflect.MessageDescriptor{}
	enums = map[protoreflect.FullName]protoreflect.EnumDescriptor{}
	topByName = map[string]protoreflect.MessageDescriptor{}
	var walk func(protoreflect.MessageDescriptors)
	walk = func(ms protoreflect.MessageDescriptors) {
		for i := 0; i < ms.Len(); i++ {
			md := ms.Get(i)
			if !md.IsMapEntry() {
				msgs[md.FullName()] = md
			}
			es := md.Enums()
			for j := 0; j < es.Len(); j++ {
				enums[es.Get(j).FullName()] = es.Get(j)
			}
			walk(md.Messages())
		}
	}
	for _, f := range contractFiles {
		walk(f.Messages())
		for i := 0; i < f.Messages().Len(); i++ {
			md := f.Messages().Get(i)
			topByName[string(md.Name())] = md
		}
		fe := f.Enums()
		for i := 0; i < fe.Len(); i++ {
			enums[fe.Get(i).FullName()] = fe.Get(i)
		}
	}
	return
}

// rpcRootMessages collects every service method's input and output message
// across the contract files.
func rpcRootMessages() []protoreflect.MessageDescriptor {
	var roots []protoreflect.MessageDescriptor
	for _, f := range contractFiles {
		svcs := f.Services()
		for i := 0; i < svcs.Len(); i++ {
			ms := svcs.Get(i).Methods()
			for j := 0; j < ms.Len(); j++ {
				m := ms.Get(j)
				roots = append(roots, m.Input(), m.Output())
			}
		}
	}
	return roots
}

// TestEveryTypeIsReachable (INV-4) fails on any message or enum that no delivery
// channel can carry. Scope is the descriptor itself, never a hand-listed set of
// "the types we expect"; the only hand-maintained surface is outOfBandRoots,
// which the test proves is both real and necessary on every run.
func TestEveryTypeIsReachable(t *testing.T) {
	msgs, enums, topByName := allDefinedTypes()

	rpcRoots := rpcRootMessages()
	if len(rpcRoots) == 0 {
		t.Fatal("no RPC root messages found — service iteration drifted; INV-4 would be vacuous.")
	}

	// Resolve the out-of-band roots, proving each names a real top-level message.
	var seeds []protoreflect.MessageDescriptor
	seeds = append(seeds, rpcRoots...)
	for name := range outOfBandRoots {
		if strings.TrimSpace(outOfBandRoots[name]) == "" {
			t.Errorf("outOfBandRoots[%q] has an empty reason; every root must say why.", name)
		}
		md, ok := topByName[name]
		if !ok {
			t.Errorf("outOfBandRoots[%q] is stale: no top-level message by that name exists — remove or fix it.", name)
			continue
		}
		seeds = append(seeds, md)
	}

	// Self-cleaning: an out-of-band root that is ALSO reachable from RPC bodies
	// alone is an unnecessary exemption that could mask an orphan beneath it.
	rpcMsg, _ := reachFrom(rpcRoots)
	for name := range outOfBandRoots {
		if md, ok := topByName[name]; ok && rpcMsg[md.FullName()] {
			t.Errorf("outOfBandRoots[%q] is already reachable from an RPC body — remove the (now redundant) exemption.", name)
		}
	}

	reachMsg, reachEnum := reachFrom(seeds)

	var orphanM, orphanE []string
	for fn, md := range msgs {
		if !reachMsg[fn] {
			orphanM = append(orphanM, string(md.Name()))
		}
	}
	for fn, ed := range enums {
		if !reachEnum[fn] {
			orphanE = append(orphanE, string(ed.Name()))
		}
	}
	sort.Strings(orphanM)
	sort.Strings(orphanE)

	t.Logf("reachable: %d/%d messages, %d/%d enums (from %d RPC roots + %d out-of-band roots)",
		len(reachMsg), len(msgs), len(reachEnum), len(enums), len(rpcRoots), len(outOfBandRoots))

	for _, n := range orphanM {
		t.Errorf("message %s is an orphan: no RPC body, served document, or error reason references it. "+
			"Wire it into a delivery channel, or delete it, or (if it is itself a served/out-of-band root) add it to outOfBandRoots with a reason.", n)
	}
	for _, n := range orphanE {
		t.Errorf("enum %s is an orphan: no field on any reachable message uses it. "+
			"Attach it to a delivered message, or delete it.", n)
	}
}
