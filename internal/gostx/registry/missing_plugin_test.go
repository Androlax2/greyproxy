package registry

import (
	"context"
	"testing"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/auth"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/bypass"
)

type allowingBypass struct{}

func (allowingBypass) Contains(context.Context, string, string, ...bypass.Option) bool { return false }
func (allowingBypass) IsWhitelist() bool                                               { return false }

type acceptingAuther struct{}

func (acceptingAuther) Authenticate(context.Context, string, string, ...auth.Option) (string, bool) {
	return "client", true
}

func TestBypassBlocksEverythingWhenTheNamedPluginIsMissing(t *testing.T) {
	missingBypass := BypassRegistry().Get("bypass-never-registered")

	if !missingBypass.Contains(context.Background(), "tcp", "example.com:443") {
		t.Error("Contains = false (allowed) for an unregistered bypass, want true (blocked)")
	}
}

func TestBypassDelegatesOnceThePluginIsRegistered(t *testing.T) {
	const name = "bypass-registered-in-test"
	if err := BypassRegistry().Register(name, allowingBypass{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { BypassRegistry().Unregister(name) })

	if BypassRegistry().Get(name).Contains(context.Background(), "tcp", "example.com:443") {
		t.Error("Contains = true (blocked), want the registered plugin's answer (allowed)")
	}
}

func TestAutherRefusesEveryLoginWhenTheNamedPluginIsMissing(t *testing.T) {
	missingAuther := AutherRegistry().Get("auther-never-registered")

	if _, isAccepted := missingAuther.Authenticate(context.Background(), "opencode", "secret"); isAccepted {
		t.Error("Authenticate accepted a login with an unregistered auther, want refused")
	}
}

func TestAutherDelegatesOnceThePluginIsRegistered(t *testing.T) {
	const name = "auther-registered-in-test"
	if err := AutherRegistry().Register(name, acceptingAuther{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { AutherRegistry().Unregister(name) })

	if _, isAccepted := AutherRegistry().Get(name).Authenticate(context.Background(), "opencode", "secret"); !isAccepted {
		t.Error("Authenticate refused, want the registered plugin's answer (accepted)")
	}
}
