package plugins

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/bypass"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/handler"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	http_handler "github.com/greyhavenhq/greyproxy/internal/gostx/handler/http"
	socks5_handler "github.com/greyhavenhq/greyproxy/internal/gostx/handler/socks/v5"
	xlogger "github.com/greyhavenhq/greyproxy/internal/gostx/logger"
	mdx "github.com/greyhavenhq/greyproxy/internal/gostx/metadata"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
	_ "modernc.org/sqlite"
)

const (
	registeredSecret = "registered-secret-0123456789abcdefghijklmnop"
	secondSecret     = "second-secret-0123456789abcdefghijklmnopqrs"
	expiredSecret    = "expired-secret-0123456789abcdefghijklmnopqr"
)

// blockEverything makes an accepted HTTP request end with 403 instead of
// dialing out, so 407 can only mean the login was refused.
type blockEverything struct{}

func (blockEverything) Contains(context.Context, string, string, ...bypass.Option) bool { return true }
func (blockEverything) IsWhitelist() bool                                               { return false }

// proxyFrontend logs in through a real gost handler and reports whether the
// proxy accepted the credentials.
type proxyFrontend struct {
	name    string
	isLogin func(t *testing.T, auther *Auther, user, password string) bool
}

var proxyFrontends = []proxyFrontend{
	{"HTTP", isHTTPLoginAccepted},
	{"SOCKS5", isSOCKS5LoginAccepted},
}

func isHTTPLoginAccepted(t *testing.T, auther *Auther, user, password string) bool {
	t.Helper()
	proxyHandler := http_handler.NewHandler(
		handler.AutherOption(auther),
		handler.BypassOption(blockEverything{}),
		handler.LoggerOption(xlogger.Nop()),
		handler.ServiceOption("http-proxy"),
	)
	if err := proxyHandler.Init(mdx.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	go func() { _ = proxyHandler.Handle(context.Background(), serverConn) }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	request := "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n"
	if user != "" || password != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		request += "Proxy-Authorization: Basic " + credentials + "\r\n"
	}
	request += "\r\n"
	if _, err := io.WriteString(clientConn, request); err != nil {
		t.Fatal(err)
	}

	response, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	switch response.StatusCode {
	case http.StatusProxyAuthRequired:
		return false
	case http.StatusForbidden:
		return true
	default:
		t.Fatalf("unexpected HTTP status %d", response.StatusCode)
		return false
	}
}

func isSOCKS5LoginAccepted(t *testing.T, auther *Auther, user, password string) bool {
	t.Helper()
	proxyHandler := socks5_handler.NewHandler(
		handler.AutherOption(auther),
		handler.LoggerOption(xlogger.Nop()),
		handler.ServiceOption("socks5-proxy"),
	)
	if err := proxyHandler.Init(mdx.NewMetadata(nil)); err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	go func() { _ = proxyHandler.Handle(context.Background(), serverConn) }()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	const socksVersion, userPassMethod, userPassVersion = 0x05, 0x02, 0x01
	if _, err := clientConn.Write([]byte{socksVersion, 1, userPassMethod}); err != nil {
		t.Fatal(err)
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, methodReply); err != nil {
		t.Fatal(err)
	}
	if methodReply[1] != userPassMethod {
		t.Fatalf("server chose SOCKS5 method %d, want username/password", methodReply[1])
	}

	loginRequest := []byte{userPassVersion, byte(len(user))}
	loginRequest = append(loginRequest, user...)
	loginRequest = append(loginRequest, byte(len(password)))
	loginRequest = append(loginRequest, password...)
	if _, err := clientConn.Write(loginRequest); err != nil {
		t.Fatal(err)
	}
	loginReply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, loginReply); err != nil {
		t.Fatal(err)
	}
	return loginReply[1] == 0x00
}

// newAutherTestDB returns a migrated database with live sessions for
// "opencode" (two secrets) and "claude" (no secret, rules only), and an
// expired secret for "jobpilot-docker".
func newAutherTestDB(t *testing.T) *greyproxy.DB {
	t.Helper()
	logger.SetDefault(xlogger.Nop())

	dbFile, err := os.CreateTemp(t.TempDir(), "greyproxy_auther_*.db")
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

	encryptionKey := make([]byte, 32)
	sessions := []greyproxy.SessionCreateInput{
		{SessionID: "opencode-1", ContainerName: "opencode", ClientSecret: registeredSecret},
		{SessionID: "opencode-2", ContainerName: "opencode", ClientSecret: secondSecret},
		{SessionID: "claude-1", ContainerName: "claude", AllowAll: true},
		{SessionID: "jobpilot-1", ContainerName: "jobpilot-docker", ClientSecret: expiredSecret},
	}
	for _, session := range sessions {
		if _, err := greyproxy.CreateOrUpdateSession(db, session, encryptionKey); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.WriteDB().Exec(
		"UPDATE sessions SET expires_at = datetime('now', '-1 minute') WHERE session_id = 'jobpilot-1'",
	); err != nil {
		t.Fatal(err)
	}
	return db
}

type loginCase struct {
	name       string
	user       string
	password   string
	isAccepted bool
}

func runLoginCases(t *testing.T, policy ClientSecretPolicy, cases []loginCase) {
	t.Helper()
	auther := NewAuther(newAutherTestDB(t), policy)
	for _, frontend := range proxyFrontends {
		for _, tt := range cases {
			t.Run(frontend.name+"/"+tt.name, func(t *testing.T) {
				if got := frontend.isLogin(t, auther, tt.user, tt.password); got != tt.isAccepted {
					t.Errorf("login %q accepted = %v, want %v", tt.user, got, tt.isAccepted)
				}
			})
		}
	}
}

func TestAutherChecksRegisteredClientSecrets(t *testing.T) {
	runLoginCases(t, ClientSecretPolicy{AllowAnonymous: true}, []loginCase{
		{"the registered secret is accepted", "opencode", registeredSecret, true},
		{"any live secret for the name is accepted", "opencode", secondSecret, true},
		{"a wrong secret is refused", "opencode", "proxy", false},
		{"an empty password is refused", "opencode", "", false},
		{"a name without a secret keeps working", "claude", "proxy", true},
		{"a name whose secret expired keeps working", "jobpilot-docker", "proxy", true},
		{"the anonymous login keeps working", "", "", true},
		{"the reserved anonymous prefix is refused", "unknown-127.0.0.1", "proxy", false},
	})
}

func TestAutherWithRequiredClientSecrets(t *testing.T) {
	runLoginCases(t, ClientSecretPolicy{RequireClientSecret: true, AllowAnonymous: true, ExemptNames: []string{"legacy-tool"}}, []loginCase{
		{"the registered secret is accepted", "opencode", registeredSecret, true},
		{"a wrong secret is refused", "opencode", "proxy", false},
		{"a name without a secret is refused", "claude", "proxy", false},
		{"an expired secret is refused", "jobpilot-docker", expiredSecret, false},
		{"an exempt name is accepted", "legacy-tool", "proxy", true},
		{"the anonymous login is accepted", "", "", true},
		{"the proxy login counts as anonymous", "proxy", "proxy", true},
	})
}

func TestAutherRefusesAnonymousClientsWhenDisabled(t *testing.T) {
	runLoginCases(t, ClientSecretPolicy{RequireClientSecret: true, AllowAnonymous: false}, []loginCase{
		{"the anonymous login is refused", "", "", false},
		{"the proxy login is refused", "proxy", "proxy", false},
		{"the registered secret is still accepted", "opencode", registeredSecret, true},
	})
}

func TestAutherNeverLogsTheSecret(t *testing.T) {
	recorder := &recordingLogger{}
	auther := NewAuther(newAutherTestDB(t), ClientSecretPolicy{AllowAnonymous: true})
	auther.log = recorder
	wrongSecret := "wrong-secret-that-must-not-be-logged-0123456789"

	_, _ = auther.Authenticate(context.Background(), "opencode", wrongSecret)
	_, _ = auther.Authenticate(context.Background(), "opencode", registeredSecret)

	for _, line := range recorder.lines {
		if strings.Contains(line, wrongSecret) || strings.Contains(line, registeredSecret) {
			t.Errorf("log line contains a secret: %q", line)
		}
	}
	if len(recorder.lines) == 0 {
		t.Error("the refused login was not logged")
	}
}

type recordingLogger struct {
	lines []string
}

func (r *recordingLogger) record(format string, args ...any) {
	r.lines = append(r.lines, strings.TrimSpace(fmt.Sprintf(format, args...)))
}

func (r *recordingLogger) WithFields(map[string]any) logger.Logger { return r }
func (r *recordingLogger) Trace(args ...any)                       { r.record("%v", args...) }
func (r *recordingLogger) Tracef(format string, args ...any)       { r.record(format, args...) }
func (r *recordingLogger) Debug(args ...any)                       { r.record("%v", args...) }
func (r *recordingLogger) Debugf(format string, args ...any)       { r.record(format, args...) }
func (r *recordingLogger) Info(args ...any)                        { r.record("%v", args...) }
func (r *recordingLogger) Infof(format string, args ...any)        { r.record(format, args...) }
func (r *recordingLogger) Warn(args ...any)                        { r.record("%v", args...) }
func (r *recordingLogger) Warnf(format string, args ...any)        { r.record(format, args...) }
func (r *recordingLogger) Error(args ...any)                       { r.record("%v", args...) }
func (r *recordingLogger) Errorf(format string, args ...any)       { r.record(format, args...) }
func (r *recordingLogger) Fatal(args ...any)                       { r.record("%v", args...) }
func (r *recordingLogger) Fatalf(format string, args ...any)       { r.record(format, args...) }
func (r *recordingLogger) GetLevel() logger.LogLevel               { return logger.TraceLevel }
func (r *recordingLogger) IsLevelEnabled(logger.LogLevel) bool     { return true }
