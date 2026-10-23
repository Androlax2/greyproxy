package plugins

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	corechain "github.com/greyhavenhq/greyproxy/internal/gostcore/chain"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostx/chain"
	"github.com/greyhavenhq/greyproxy/internal/greyproxy"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func observeResolverDNS(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	if logger.Default() == nil {
		logger.SetDefault(logger.LoggerGroup())
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	queries := new(atomic.Int32)
	ready := make(chan struct{})
	server := &dns.Server{
		PacketConn:        listener,
		NotifyStartedFunc: func() { close(ready) },
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			queries.Add(1)
			response := new(dns.Msg)
			response.SetReply(request)
			for _, question := range request.Question {
				header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
				switch question.Qtype {
				case dns.TypeA:
					response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.ParseIP("127.0.0.1")})
				case dns.TypeAAAA:
					response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.ParseIP("::1")})
				}
			}
			assert.NoError(t, writer.WriteMsg(response))
		}),
	}
	stopped := make(chan error, 1)
	go func() { stopped <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		require.NoError(t, server.Shutdown())
		require.NoError(t, <-stopped)
	})
	return listener.LocalAddr().String(), queries
}

func TestResolverResolvesLiteralIPsWithoutDNS(t *testing.T) {
	for _, test := range []struct {
		network string
		host    string
		want    string
	}{
		{"ip", "192.0.2.1", "192.0.2.1"},
		{"ip4", "192.0.2.1", "192.0.2.1"},
		{"ip", "2001:db8::1", "2001:db8::1"},
		{"ip6", "2001:db8::1", "2001:db8::1"},
		{"ip", "::ffff:192.0.2.1", "192.0.2.1"},
		{"ip4", "::ffff:192.0.2.1", "192.0.2.1"},
	} {
		t.Run(test.network+"/"+test.host, func(t *testing.T) {
			server, queries := observeResolverDNS(t)
			cache := greyproxy.NewDNSCache(nil)
			resolver := NewResolver(cache, server)
			ips, err := resolver.Resolve(context.Background(), test.network, test.host)
			require.NoError(t, err)
			require.Zero(t, queries.Load(), "literal IPs must not generate DNS queries")
			require.Len(t, ips, 1)
			require.Equal(t, test.want, ips[0].String())
			require.Empty(t, cache.GetCached(test.want))
		})
	}
}

func TestResolverRejectsLiteralIPFamilyMismatchWithoutDNS(t *testing.T) {
	for _, test := range []struct{ network, host string }{
		{"ip4", "2001:db8::1"},
		{"ip6", "192.0.2.1"},
		{"ip6", "::ffff:192.0.2.1"},
	} {
		t.Run(test.network+"/"+test.host, func(t *testing.T) {
			server, queries := observeResolverDNS(t)
			resolver := NewResolver(greyproxy.NewDNSCache(nil), server)
			ips, err := resolver.Resolve(context.Background(), test.network, test.host)
			require.Zero(t, queries.Load(), "family mismatches must not generate DNS queries")
			require.Error(t, err)
			require.Empty(t, ips)
		})
	}
}

func TestResolverStillResolvesAndCachesHostnames(t *testing.T) {
	server, queries := observeResolverDNS(t)
	cache := greyproxy.NewDNSCache(nil)
	resolver := NewResolver(cache, server)
	for range 2 {
		ips, err := resolver.Resolve(context.Background(), "ip", "service.test")
		require.NoError(t, err)
		require.Len(t, ips, 2)
		require.Equal(t, "127.0.0.1", ips[0].String())
		require.Equal(t, "::1", ips[1].String())
	}
	require.EqualValues(t, 2, queries.Load(), "only the uncached A and AAAA queries should reach DNS")
	require.Equal(t, "service.test", cache.GetCached("127.0.0.1"))
	require.Equal(t, "service.test", cache.GetCached("::1"))
}

func TestRouterDialsLiteralIPWithoutDNS(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			listener, err := net.Listen("tcp", address)
			if err != nil && address == "[::1]:0" {
				t.Skipf("IPv6 loopback unavailable: %v", err)
			}
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, listener.Close()) })
			server, queries := observeResolverDNS(t)
			router := chain.NewRouter(corechain.ResolverRouterOption(NewResolver(greyproxy.NewDNSCache(nil), server)))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			connection, err := router.Dial(ctx, "tcp", listener.Addr().String())
			require.NoError(t, err)
			defer connection.Close()
			require.Equal(t, listener.Addr().String(), connection.RemoteAddr().String())
			require.Zero(t, queries.Load(), "Router dialing literal IPs must not generate DNS queries")
		})
	}
}
