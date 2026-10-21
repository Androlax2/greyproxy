package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/auth"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	xctx "github.com/greyhavenhq/greyproxy/internal/gostx/ctx"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

// anonymousIdentityPrefix is what ResolveIdentity gives clients that log in
// without a name, so no client may claim it as a login name.
const anonymousIdentityPrefix = "unknown-"

// ClientSecretPolicy decides which proxy logins are accepted. Whatever the
// policy, a name with a live registered secret only accepts that secret.
type ClientSecretPolicy struct {
	// RequireClientSecret refuses names that have no live secret, except
	// ExemptNames and (while AllowAnonymous is set) the anonymous login.
	RequireClientSecret bool
	ExemptNames         []string
	AllowAnonymous      bool
}

// Auther implements auth.Authenticator.
// It returns a composite ID "ip|username" and checks the password against the
// client secrets registered through POST /api/sessions.
type Auther struct {
	db          *greyproxy.DB
	policy      ClientSecretPolicy
	exemptNames map[string]bool
	log         logger.Logger
}

func NewAuther(db *greyproxy.DB, policy ClientSecretPolicy) *Auther {
	exemptNames := make(map[string]bool, len(policy.ExemptNames))
	for _, name := range policy.ExemptNames {
		exemptNames[name] = true
	}
	return &Auther{
		db:          db,
		policy:      policy,
		exemptNames: exemptNames,
		log: logger.Default().WithFields(map[string]any{
			"kind":   "auther",
			"auther": "greyproxy",
		}),
	}
}

func (a *Auther) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (id string, ok bool) {
	var options auth.Options
	for _, opt := range opts {
		opt(&options)
	}

	// Extract client IP from the context or service info
	clientIP := extractClientIP(ctx)

	isAnonymous := user == "" || user == "proxy"

	// Build composite ID: "ip|username"
	if isAnonymous {
		id = clientIP
	} else {
		id = fmt.Sprintf("%s|%s", clientIP, user)
	}

	if !a.isLoginAccepted(user, password, isAnonymous, clientIP) {
		return "", false
	}

	a.log.Debugf("auth: user=%s client=%s -> id=%s", user, clientIP, id)
	return id, true
}

// isLoginAccepted logs every refusal with the client name, never the password.
func (a *Auther) isLoginAccepted(user, password string, isAnonymous bool, clientIP string) bool {
	if isAnonymous {
		if a.policy.RequireClientSecret && !a.policy.AllowAnonymous {
			a.log.Warnf("auth refused: anonymous login from %s (anonymous clients are disabled)", clientIP)
			return false
		}
		return true
	}

	if strings.HasPrefix(user, anonymousIdentityPrefix) {
		a.log.Warnf("auth refused: client %q from %s uses the reserved %q prefix", user, clientIP, anonymousIdentityPrefix)
		return false
	}

	secretHashes, err := greyproxy.LiveClientSecretHashes(a.db, user)
	if err != nil {
		a.log.Errorf("auth refused: client %q from %s: cannot check client secrets: %v", user, clientIP, err)
		return false
	}
	if len(secretHashes) > 0 {
		if greyproxy.ClientSecretMatches(password, secretHashes) {
			return true
		}
		a.log.Warnf("auth refused: client %q from %s sent a wrong client secret", user, clientIP)
		return false
	}

	if a.policy.RequireClientSecret && !a.exemptNames[user] {
		a.log.Warnf("auth refused: client %q from %s has no registered client secret", user, clientIP)
		return false
	}
	return true
}

func extractClientIP(ctx context.Context) string {
	// Get source address from context using the canonical key from gostx/ctx
	if addr := xctx.SrcAddrFromContext(ctx); addr != nil {
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			return host
		}
		return addr.String()
	}
	return "unknown"
}

// ParseClientID splits a composite client ID "ip|username" into its components.
func ParseClientID(clientID string) (ip, username string) {
	parts := strings.SplitN(clientID, "|", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return clientID, ""
}
