package helpers_test

import (
	"reflect"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

func TestNormalizeScopes(t *testing.T) {
	got := helpers.NormalizeScopes([]string{"archive.read", "news.read", "", "news.read"})
	want := []string{"archive.read", "news.read"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if helpers.NormalizeScopes(nil) != nil {
		t.Error("nil in -> nil out")
	}
	if helpers.NormalizeScopes([]string{"", ""}) != nil {
		t.Error("all-empty -> nil")
	}
}

func TestApplyScopes(t *testing.T) {
	r := &rampv1.Requester{Id: "agent"}
	helpers.ApplyScopes(r, "news.read", "archive.read", "news.read")
	if !reflect.DeepEqual(r.GetScopes(), []string{"archive.read", "news.read"}) {
		t.Errorf("scopes = %v", r.GetScopes())
	}
	helpers.ApplyScopes(nil) // must not panic
}

func TestScopesSubset(t *testing.T) {
	granted := []string{"news.read", "archive.read", "video.read"}
	if !helpers.ScopesSubset([]string{"news.read", "video.read"}, granted) {
		t.Error("valid subset should pass")
	}
	if helpers.ScopesSubset([]string{"news.write"}, granted) {
		t.Error("scope outside the grant must fail (over-broad delegation)")
	}
	if !helpers.ScopesSubset(nil, granted) {
		t.Error("empty subset is always a subset")
	}
}
