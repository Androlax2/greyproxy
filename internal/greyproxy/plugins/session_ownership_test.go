package plugins

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/greyhavenhq/greyproxy/internal/gosocks5"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/bypass"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/handler"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	xctx "github.com/greyhavenhq/greyproxy/internal/gostx/ctx"
	http_handler "github.com/greyhavenhq/greyproxy/internal/gostx/handler/http"
	socks5_handler "github.com/greyhavenhq/greyproxy/internal/gostx/handler/socks/v5"
	xlogger "github.com/greyhavenhq/greyproxy/internal/gostx/logger"
	mdx "github.com/greyhavenhq/greyproxy/internal/gostx/metadata"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	"github.com/greyhavenhq/greyproxy/internal/greyproxy/api"
)

const ownershipLabel = "codex-agent-cockpit"

func newSessionBypass(t *testing.T) *Bypass {
	t.Helper()
	logger.SetDefault(xlogger.Nop())
	db, err := greyproxy.OpenDB(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	bus := greyproxy.NewEventBus()
	cache := greyproxy.NewDNSCache(nil)
	// Requests use these cached documentation IPs: no DNS or upstream traffic.
	cache.RegisterIPs("github.com", []string{"192.0.2.1"})
	cache.RegisterIPs("first.test", []string{"192.0.2.2"})
	cache.RegisterIPs("second.test", []string{"192.0.2.3"})
	return NewBypass(db, cache, bus, greyproxy.NewWaiterTracker(bus), greyproxy.NewConnTracker(), nil, nil, nil, nil)
}

func registerOwnershipSession(t *testing.T, b *Bypass, id, secret string, allowAll bool, rules ...greyproxy.SessionNetworkRule) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/sessions", api.SessionsCreateHandler(&api.Shared{DB: b.db, EncryptionKey: make([]byte, 32)}))
	body, err := json.Marshal(greyproxy.SessionCreateInput{
		SessionID: id, ContainerName: ownershipLabel, ClientSecret: secret, AllowAll: allowAll,
		NetworkRules: rules, TTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("register session: %d %s", response.Code, response.Body.String())
	}
	var result struct {
		RulesCreated int `json:"rules_created"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.RulesCreated != len(rules) {
		t.Fatalf("session %s owns %d rules, want %d", id, result.RulesCreated, len(rules))
	}
}

// Observe the real ACL decision, then block transport so no request dials out.
// Cancellation skips the UI grace period only when no rule authorizes the request.
type observeACL struct {
	plugin    *Bypass
	decisions chan aclDecision
	before    func()
}

type aclDecision struct {
	addr    string
	blocked bool
}

func (o *observeACL) IsWhitelist() bool { return false }
func (o *observeACL) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	if o.before != nil {
		o.before()
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	o.decisions <- aclDecision{addr: addr, blocked: o.plugin.Contains(ctx, network, addr, opts...)}
	return true
}

func proxyACLBlocked(t *testing.T, protocol string, b *Bypass, user, password, addr string, afterAuth func()) bool {
	t.Helper()
	observer := &observeACL{plugin: b, decisions: make(chan aclDecision, 1), before: afterAuth}
	opts := []handler.Option{
		handler.AutherOption(NewAuther(b.db, ClientSecretPolicy{AllowAnonymous: true})),
		handler.BypassOption(observer), handler.LoggerOption(xlogger.Nop()), handler.ServiceOption(protocol),
	}
	var proxyHandler handler.Handler
	if protocol == "HTTP" {
		proxyHandler = http_handler.NewHandler(opts...)
	} else {
		proxyHandler = socks5_handler.NewHandler(opts...)
	}
	if err := proxyHandler.Init(mdx.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}
	if closer, ok := proxyHandler.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}
	client, server := net.Pipe()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_ = proxyHandler.Handle(context.Background(), server)
	}()
	defer func() {
		_ = client.Close()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("proxy handler did not finish")
		}
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if protocol == "HTTP" {
		credentials := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		_, err := fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", addr, addr, credentials)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("login did not reach ACL: HTTP %d", response.StatusCode)
		}
	} else {
		if _, err := client.Write([]byte{5, 1, 2}); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 2 {
			t.Fatalf("SOCKS5 method: %v, %v", reply, err)
		}
		request := append([]byte{1, byte(len(user))}, user...)
		request = append(request, byte(len(password)))
		request = append(request, password...)
		if _, err := client.Write(request); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 0 {
			t.Fatalf("SOCKS5 login: %v, %v", reply, err)
		}
		dest := &gosocks5.Addr{}
		if err := dest.ParseFrom(addr); err != nil {
			t.Fatal(err)
		}
		if err := gosocks5.NewRequest(gosocks5.CmdConnect, dest).Write(client); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case decision := <-observer.decisions:
		return decision.blocked
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach ACL")
		return true
	}
}

func TestConcurrentSessionAuthorization(t *testing.T) {
	for _, protocol := range []string{"HTTP", "SOCKS5"} {
		t.Run(protocol, func(t *testing.T) {
			b := newSessionBypass(t)
			github := greyproxy.SessionNetworkRule{DestinationPattern: "github.com", PortPattern: "443"}
			registerOwnershipSession(t, b, "first", registeredSecret, false, github, greyproxy.SessionNetworkRule{DestinationPattern: "first.test", PortPattern: "443"})
			registerOwnershipSession(t, b, "second", secondSecret, false, github, greyproxy.SessionNetworkRule{DestinationPattern: "second.test", PortPattern: "443"})
			registerOwnershipSession(t, b, "empty", expiredSecret, false)
			for _, tt := range []struct {
				secret, addr string
				blocked      bool
			}{
				{registeredSecret, "192.0.2.1:443", false},
				{secondSecret, "192.0.2.1:443", false},
				{registeredSecret, "192.0.2.2:443", false},
				{secondSecret, "192.0.2.2:443", true},
				{registeredSecret, "192.0.2.3:443", true},
				{secondSecret, "192.0.2.3:443", false},
				{expiredSecret, "192.0.2.1:443", true},
				{registeredSecret, "192.0.2.1:80", true},
			} {
				if got := proxyACLBlocked(t, protocol, b, ownershipLabel, tt.secret, tt.addr, nil); got != tt.blocked {
					t.Errorf("%s with session secret %q: blocked = %v, want %v", tt.addr, tt.secret[:6], got, tt.blocked)
				}
			}
		})
	}
}

func TestUnidentifiedSessionGrants(t *testing.T) {
	for _, protocol := range []string{"HTTP", "SOCKS5"} {
		for _, kind := range []string{"missing", "shared"} {
			t.Run(protocol+"/"+kind, func(t *testing.T) {
				b := newSessionBypass(t)
				secret := registeredSecret
				if kind == "missing" {
					secret = ""
				}
				rule := greyproxy.SessionNetworkRule{DestinationPattern: "github.com", PortPattern: "443"}
				registerOwnershipSession(t, b, "first", secret, true, rule)
				registerOwnershipSession(t, b, "second", secret, false, rule)
				if !proxyACLBlocked(t, protocol, b, ownershipLabel, secret, "192.0.2.1:443", nil) {
					t.Error("unidentified client used session grants")
				}
				if _, err := greyproxy.CreateRule(b.db, greyproxy.RuleCreateInput{ContainerPattern: ownershipLabel, DestinationPattern: "github.com", PortPattern: "443"}); err != nil {
					t.Fatal(err)
				}
				if proxyACLBlocked(t, protocol, b, ownershipLabel, secret, "192.0.2.1:443", nil) {
					t.Error("global grant stopped working for unidentified client")
				}
			})
		}
	}
}

func TestSessionAllowAllOwnershipAndDeny(t *testing.T) {
	for _, protocol := range []string{"HTTP", "SOCKS5"} {
		t.Run(protocol, func(t *testing.T) {
			b := newSessionBypass(t)
			registerOwnershipSession(t, b, "learning", registeredSecret, true, greyproxy.SessionNetworkRule{DestinationPattern: "first.test", Action: "deny"})
			registerOwnershipSession(t, b, "restricted", secondSecret, false)
			if proxyACLBlocked(t, protocol, b, ownershipLabel, registeredSecret, "192.0.2.1:443", nil) {
				t.Error("owner's allow_all was not applied")
			}
			if !proxyACLBlocked(t, protocol, b, ownershipLabel, secondSecret, "192.0.2.1:443", nil) {
				t.Error("allow_all leaked to another session")
			}
			if !proxyACLBlocked(t, protocol, b, ownershipLabel, registeredSecret, "192.0.2.2:443", nil) {
				t.Error("allow_all bypassed a session deny")
			}
			if _, err := greyproxy.CreateRule(b.db, greyproxy.RuleCreateInput{ContainerPattern: "*", DestinationPattern: "github.com", Action: "deny"}); err != nil {
				t.Fatal(err)
			}
			if !proxyACLBlocked(t, protocol, b, ownershipLabel, registeredSecret, "192.0.2.1:443", nil) {
				t.Error("allow_all bypassed a global deny")
			}
		})
	}
}

func TestSessionAuthorizationRechecksRevocation(t *testing.T) {
	for _, protocol := range []string{"HTTP", "SOCKS5"} {
		for _, change := range []string{"delete", "expire", "remove_secret", "rotate_secret", "shared_secret", "rule_expiry", "empty_rules", "rename"} {
			t.Run(protocol+"/"+change, func(t *testing.T) {
				b := newSessionBypass(t)
				rule := greyproxy.SessionNetworkRule{DestinationPattern: "github.com", PortPattern: "443"}
				registerOwnershipSession(t, b, "first", registeredSecret, false, rule)
				registerOwnershipSession(t, b, "second", secondSecret, false, rule)
				var changeErr error
				blocked := proxyACLBlocked(t, protocol, b, ownershipLabel, registeredSecret, "192.0.2.1:443", func() {
					switch change {
					case "delete":
						_, changeErr = greyproxy.DeleteSession(b.db, "first")
					case "expire":
						_, changeErr = b.db.WriteDB().Exec("UPDATE sessions SET expires_at = datetime('now', '-1 second') WHERE session_id = 'first'")
					case "rule_expiry":
						_, changeErr = b.db.WriteDB().Exec("UPDATE rules SET expires_at = datetime('now', '-1 second') WHERE session_id = 'first'")
					default:
						input := greyproxy.SessionCreateInput{SessionID: "first", ContainerName: ownershipLabel, ClientSecret: registeredSecret, NetworkRules: []greyproxy.SessionNetworkRule{rule}}
						switch change {
						case "remove_secret":
							input.ClientSecret = ""
						case "rotate_secret":
							input.ClientSecret = expiredSecret
						case "shared_secret":
							input.SessionID = "third"
						case "empty_rules":
							input.NetworkRules = nil
						case "rename":
							input.ContainerName = "another-client"
						}
						_, changeErr = greyproxy.CreateOrUpdateSession(b.db, input, make([]byte, 32))
					}
				})
				if changeErr != nil {
					t.Fatal(changeErr)
				}
				if !blocked {
					t.Error("stale authentication retained revoked session grants")
				}
				if proxyACLBlocked(t, protocol, b, ownershipLabel, secondSecret, "192.0.2.1:443", nil) {
					t.Error("revoking first session changed second session's grant")
				}
			})
		}
	}
}

type approvalLogger struct {
	logger.Logger
	holding chan struct{}
}

func (l approvalLogger) Debugf(format string, args ...any) {
	if strings.HasPrefix(format, "HOLD ") {
		close(l.holding)
	}
}

func TestSessionOwnershipDuringApproval(t *testing.T) {
	for _, approvedOwner := range []string{"first", "second"} {
		t.Run(approvedOwner, func(t *testing.T) {
			b := newSessionBypass(t)
			registerOwnershipSession(t, b, "first", registeredSecret, false)
			registerOwnershipSession(t, b, "second", secondSecret, false)
			result := &xctx.AuthResult{}
			ctx := xctx.ContextWithAuthResult(context.Background(), result)
			clientID, ok := NewAuther(b.db, ClientSecretPolicy{}).Authenticate(ctx, ownershipLabel, registeredSecret)
			if !ok {
				t.Fatal("authentication failed")
			}
			ctx = xctx.ContextWithClientID(ctx, xctx.ClientID(clientID))
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			holding := make(chan struct{})
			b.log = approvalLogger{Logger: xlogger.Nop(), holding: holding}
			decision := make(chan bool, 1)
			go func() { decision <- b.Contains(ctx, "tcp", "192.0.2.1:443") }()
			select {
			case <-holding: // subscription installed: no timing sleeps or event races
			case <-ctx.Done():
				t.Fatal("request never waited for approval")
			}
			secret := registeredSecret
			if approvedOwner == "second" {
				secret = secondSecret
			}
			registerOwnershipSession(t, b, approvedOwner, secret, false, greyproxy.SessionNetworkRule{DestinationPattern: "github.com", PortPattern: "443"})
			b.bus.Publish(greyproxy.Event{Type: greyproxy.EventPendingAllowed})
			b.bus.Publish(greyproxy.Event{Type: greyproxy.EventPendingDismissed})
			select {
			case blocked := <-decision:
				if blocked != (approvedOwner == "second") {
					t.Errorf("approval for %s: first session blocked = %v", approvedOwner, blocked)
				}
			case <-ctx.Done():
				t.Fatal("approval did not finish")
			}
		})
	}
}

func TestSessionRuleDenyPrecedence(t *testing.T) {
	b := newSessionBypass(t)
	allow := greyproxy.SessionNetworkRule{DestinationPattern: "github.com", PortPattern: "443", Action: "allow"}
	deny := allow
	deny.Action = "deny"
	registerOwnershipSession(t, b, "first", registeredSecret, false, allow, deny)
	registerOwnershipSession(t, b, "second", secondSecret, false, allow)
	if !proxyACLBlocked(t, "HTTP", b, ownershipLabel, registeredSecret, "192.0.2.1:443", nil) {
		t.Error("deny must win an equal-specificity session tie")
	}
	if proxyACLBlocked(t, "HTTP", b, ownershipLabel, secondSecret, "192.0.2.1:443", nil) {
		t.Error("another session's deny must not apply")
	}
	global, err := greyproxy.CreateRule(b.db, greyproxy.RuleCreateInput{ContainerPattern: "*", DestinationPattern: "github.com", Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	if !proxyACLBlocked(t, "HTTP", b, ownershipLabel, secondSecret, "192.0.2.1:443", nil) {
		t.Error("broad global deny must beat a specific session allow")
	}
	action := "allow"
	if _, err := greyproxy.UpdateRule(b.db, global.ID, greyproxy.RuleUpdateInput{Action: &action}); err != nil {
		t.Fatal(err)
	}
	if proxyACLBlocked(t, "HTTP", b, ownershipLabel, registeredSecret, "192.0.2.1:443", nil) {
		t.Error("global rule priority changed")
	}
}

func TestSharedSOCKS5HandlerKeepsLoginIdentitiesSeparate(t *testing.T) {
	b := newSessionBypass(t)
	registerOwnershipSession(t, b, "first", registeredSecret, false, greyproxy.SessionNetworkRule{DestinationPattern: "first.test", PortPattern: "443"})
	registerOwnershipSession(t, b, "second", secondSecret, false, greyproxy.SessionNetworkRule{DestinationPattern: "second.test", PortPattern: "443"})
	observer := &observeACL{plugin: b, decisions: make(chan aclDecision, 2)}
	proxyHandler := socks5_handler.NewHandler(
		handler.AutherOption(NewAuther(b.db, ClientSecretPolicy{})),
		handler.BypassOption(observer), handler.LoggerOption(xlogger.Nop()),
	)
	if err := proxyHandler.Init(mdx.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}
	if closer, ok := proxyHandler.(io.Closer); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	clients := make([]net.Conn, 2)
	// Both selector instances exist before either authenticates. Reusing a mutable
	// selector would bind the first login to the second connection's context.
	for i := range clients {
		client, server := net.Pipe()
		clients[i] = client
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			_ = proxyHandler.Handle(context.Background(), server)
		}()
		t.Cleanup(func() {
			_ = client.Close()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Error("shared handler connection did not finish")
			}
		})
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := client.Write([]byte{5, 1, 2}); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 2 {
			t.Fatalf("SOCKS5 method: %v, %v", reply, err)
		}
	}
	for i, secret := range []string{registeredSecret, secondSecret} {
		request := append([]byte{1, byte(len(ownershipLabel))}, ownershipLabel...)
		request = append(request, byte(len(secret)))
		request = append(request, secret...)
		if _, err := clients[i].Write(request); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(clients[i], reply); err != nil || reply[1] != 0 {
			t.Fatalf("SOCKS5 login: %v, %v", reply, err)
		}
	}
	for i, addr := range []string{"192.0.2.2:443", "192.0.2.3:443"} {
		dest := &gosocks5.Addr{}
		if err := dest.ParseFrom(addr); err != nil {
			t.Fatal(err)
		}
		if err := gosocks5.NewRequest(gosocks5.CmdConnect, dest).Write(clients[i]); err != nil {
			t.Fatal(err)
		}
	}
	for range clients {
		select {
		case decision := <-observer.decisions:
			if decision.blocked {
				t.Errorf("shared handler lost owning identity for %s", decision.addr)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("shared handler did not authorize both connections")
		}
	}
}
