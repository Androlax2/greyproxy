package plugins

import (
	"context"
	"net"
	"strings"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/resolver"
)

// selfGuard stops proxied traffic from reaching greyproxy's own listeners
// (the unauthenticated management API and the proxy ports). Without it, any
// client allowed to reach loopback (the built-in localhost rules, an approved
// pending request, or allow-all mode) could rewrite the policy through the API.
// It runs before every rule and cannot be overridden from the dashboard.
type selfGuard struct {
	protectedPorts map[int]bool
	resolver       resolver.Resolver
	interfaceAddrs func() ([]net.Addr, error)
}

func newSelfGuard(ports []int, hostResolver resolver.Resolver) *selfGuard {
	protectedPorts := make(map[int]bool, len(ports))
	for _, port := range ports {
		protectedPorts[port] = true
	}
	return &selfGuard{
		protectedPorts: protectedPorts,
		resolver:       hostResolver,
		interfaceAddrs: net.InterfaceAddrs,
	}
}

// targetsSelf reports whether host:port may land on one of greyproxy's own
// listeners. When the host cannot be resolved it answers true: the destination
// cannot be proven safe, and the dial would fail anyway.
func (g *selfGuard) targetsSelf(ctx context.Context, host string, port int) bool {
	if !g.protectedPorts[port] {
		return false
	}

	normalizedHost := strings.TrimSuffix(strings.ToLower(host), ".")
	if normalizedHost == "localhost" || strings.HasSuffix(normalizedHost, ".localhost") {
		return true
	}

	if literalIP := net.ParseIP(normalizedHost); literalIP != nil {
		return g.isLocalIP(literalIP)
	}

	resolvedIPs, err := g.resolver.Resolve(ctx, "ip", normalizedHost)
	if err != nil || len(resolvedIPs) == 0 {
		return true
	}
	for _, resolvedIP := range resolvedIPs {
		if g.isLocalIP(resolvedIP) {
			return true
		}
	}
	return false
}

func (g *selfGuard) isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}

	// With `--host 0.0.0.0` the listeners also answer on every interface address.
	localAddrs, err := g.interfaceAddrs()
	if err != nil {
		return true
	}
	for _, localAddr := range localAddrs {
		if ipNet, isIPNet := localAddr.(*net.IPNet); isIPNet && ipNet.IP.Equal(ip) {
			return true
		}
	}
	return false
}
