package plugins

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/resolver"
	xlogger "github.com/greyhavenhq/greyproxy/internal/gostx/logger"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	_ "modernc.org/sqlite"
)

const (
	testAPIPort   = 43080
	testProxyPort = 43051
)

type fakeHostResolver map[string][]net.IP

func (f fakeHostResolver) Resolve(_ context.Context, _, host string, _ ...resolver.Option) ([]net.IP, error) {
	ips, found := f[host]
	if !found {
		return nil, errors.New("no such host")
	}
	return ips, nil
}

type fakeAllowAll struct{ mode string }

func (f fakeAllowAll) IsActive() bool { return f.mode != "" }
func (f fakeAllowAll) Mode() string   { return f.mode }

// newGuardedBypass returns a Bypass over a freshly migrated database, so the
// built-in localhost allow rules are present, plus an allow-all rule for the
// public test address. Every case therefore has a matching allow rule and
// none of them waits for the approval grace period.
func newGuardedBypass(t *testing.T, allowAll AllowAllChecker) *Bypass {
	t.Helper()

	// NewBypass reads logger.Default(), which only the binary installs.
	logger.SetDefault(xlogger.Nop())

	dbFile, err := os.CreateTemp(t.TempDir(), "greyproxy_selfguard_*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = dbFile.Close()

	db, err := greyproxy.OpenDB(dbFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if _, err := greyproxy.CreateRule(db, greyproxy.RuleCreateInput{
		ContainerPattern:   "*",
		DestinationPattern: "*",
		Action:             "allow",
	}); err != nil {
		t.Fatal(err)
	}

	hostResolver := fakeHostResolver{
		"rebind.example.test": {net.ParseIP("127.0.0.1")},
		"public.example.test": {net.ParseIP("93.184.216.34")},
	}
	bus := greyproxy.NewEventBus()
	bypassPlugin := NewBypass(db, greyproxy.NewDNSCache(db), bus, greyproxy.NewWaiterTracker(bus), greyproxy.NewConnTracker(), nil, allowAll, []int{testAPIPort, testProxyPort}, hostResolver)
	bypassPlugin.selfGuard.interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.20"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	return bypassPlugin
}

func TestBypassBlocksGreyproxyOwnListeners(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"API on IPv4 loopback despite the built-in localhost rule", "127.0.0.1:43080"},
		{"API on another 127/8 address", "127.0.0.2:43080"},
		{"API on IPv6 loopback", "[::1]:43080"},
		{"API on IPv4-mapped IPv6 loopback", "[::ffff:127.0.0.1]:43080"},
		{"API via the localhost name", "localhost:43080"},
		{"API via a .localhost subdomain", "api.localhost:43080"},
		{"API via the unspecified address", "0.0.0.0:43080"},
		{"API via a hostname resolving to loopback", "rebind.example.test:43080"},
		{"API via a local interface address", "192.168.1.20:43080"},
		{"API via a hostname that does not resolve", "unknown.example.test:43080"},
		{"proxy listener on loopback", "127.0.0.1:43051"},
	}

	bypassPlugin := newGuardedBypass(t, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !bypassPlugin.Contains(context.Background(), "tcp", tt.addr) {
				t.Errorf("Contains(%q) = false (allowed), want true (blocked)", tt.addr)
			}
		})
	}
}

func TestBypassBlocksGreyproxyOwnListenersInSilentAllowMode(t *testing.T) {
	bypassPlugin := newGuardedBypass(t, fakeAllowAll{mode: greyproxy.SilentModeAllow})

	if !bypassPlugin.Contains(context.Background(), "tcp", "127.0.0.1:43080") {
		t.Error("Contains allowed the API while silent allow mode was active, want blocked")
	}
}

func TestBypassStillAllowsOtherLocalhostPortsThroughBuiltinRule(t *testing.T) {
	bypassPlugin := newGuardedBypass(t, nil)

	if bypassPlugin.Contains(context.Background(), "tcp", "127.0.0.1:8080") {
		t.Error("Contains blocked 127.0.0.1:8080, want allowed by the built-in localhost rule")
	}
}

func TestBypassAllowsRemoteHostsOnGreyproxyPortNumbers(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"public IP literal", "93.184.216.34:43080"},
		{"hostname resolving to a public IP", "public.example.test:43080"},
	}

	bypassPlugin := newGuardedBypass(t, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if bypassPlugin.Contains(context.Background(), "tcp", tt.addr) {
				t.Errorf("Contains(%q) = true (blocked), want false (allowed by rule)", tt.addr)
			}
		})
	}
}
