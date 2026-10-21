package api

import (
	"crypto/subtle"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

const (
	dashboardSessionCookie = "greyproxy_session"
	// Browsers cap cookie lifetime at 400 days; the cookie stays valid until the token changes.
	dashboardSessionMaxAge = 400 * 24 * 60 * 60
	// A login link is valid this long after `greyproxy dashboard-url` signs it, and only once.
	dashboardLinkLifetime = 2 * time.Minute
	// Tolerates a client clock slightly ahead of the server's.
	dashboardLinkClockSkew = 10 * time.Second
)

// apiAuth guards every route of the management server (REST API, HTMX
// endpoints, WebSocket and pages) with the token from the data directory
// when requireApiToken is on. Clients send `Authorization: Bearer <token>`;
// the dashboard uses a cookie obtained from the login form or a signed link.
type apiAuth struct {
	token      string
	isRequired bool
	basePath   string // pathPrefix without its trailing slash; "" for "/"

	usedLinksMu sync.Mutex
	usedLinks   map[string]time.Time // signature -> expiry
}

func newAPIAuth(token string, isRequired bool, pathPrefix string) *apiAuth {
	return &apiAuth{
		token:      token,
		isRequired: isRequired,
		basePath:   strings.TrimRight(pathPrefix, "/"),
		usedLinks:  make(map[string]time.Time),
	}
}

func (a *apiAuth) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.isRequired {
			c.Next()
			return
		}

		relativePath := strings.TrimPrefix(c.Request.URL.Path, a.basePath)
		if isPublicPath(relativePath) || a.isAuthenticated(c.Request) {
			c.Next()
			return
		}

		if c.Request.Method == http.MethodGet && isPagePath(relativePath) {
			loginURL := a.basePath + "/login?next=" + url.QueryEscape(c.Request.URL.RequestURI())
			c.Redirect(http.StatusSeeOther, loginURL)
			c.Abort()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid API token"})
	}
}

func isPublicPath(relativePath string) bool {
	return relativePath == "/api/health" ||
		relativePath == "/login" ||
		relativePath == "/auth" ||
		strings.HasPrefix(relativePath, "/static/")
}

func isPagePath(relativePath string) bool {
	return !strings.HasPrefix(relativePath, "/api/") &&
		!strings.HasPrefix(relativePath, "/htmx/") &&
		relativePath != "/ws"
}

// isAuthenticated fails closed when no token is configured.
func (a *apiAuth) isAuthenticated(req *http.Request) bool {
	if a.token == "" {
		return false
	}
	if bearerToken, hasBearer := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer "); hasBearer {
		return constantTimeEqual(strings.TrimSpace(bearerToken), a.token)
	}
	if sessionCookie, err := req.Cookie(dashboardSessionCookie); err == nil {
		return constantTimeEqual(sessionCookie.Value, greyproxy.DashboardSessionValue(a.token))
	}
	return false
}

func constantTimeEqual(given, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(given), []byte(expected)) == 1
}

func (a *apiAuth) registerRoutes(g *gin.RouterGroup) {
	g.GET("/login", a.loginFormHandler)
	g.POST("/login", a.loginSubmitHandler)
	g.GET("/auth", a.loginLinkHandler)
}

func (a *apiAuth) loginFormHandler(c *gin.Context) {
	a.renderLoginForm(c, http.StatusOK, c.Query("next"), "")
}

func (a *apiAuth) loginSubmitHandler(c *gin.Context) {
	next := c.PostForm("next")
	submittedToken := strings.TrimSpace(c.PostForm("token"))
	if a.token == "" || !constantTimeEqual(submittedToken, a.token) {
		a.renderLoginForm(c, http.StatusUnauthorized, next, "That token does not match.")
		return
	}
	a.setSessionCookie(c)
	c.Redirect(http.StatusSeeOther, a.safeRedirectTarget(next))
}

func (a *apiAuth) loginLinkHandler(c *gin.Context) {
	issuedAtUnix, err := strconv.ParseInt(c.Query("ts"), 10, 64)
	signature := c.Query("sig")
	if err != nil || signature == "" || a.token == "" {
		a.renderLoginForm(c, http.StatusUnauthorized, "", "This login link is invalid.")
		return
	}

	issuedAt := time.Unix(issuedAtUnix, 0)
	now := time.Now()
	if issuedAt.After(now.Add(dashboardLinkClockSkew)) || now.Sub(issuedAt) > dashboardLinkLifetime {
		a.renderLoginForm(c, http.StatusUnauthorized, "", "This login link has expired. Run greyproxy dashboard-url again.")
		return
	}
	if !constantTimeEqual(signature, greyproxy.SignDashboardLogin(a.token, issuedAtUnix)) {
		a.renderLoginForm(c, http.StatusUnauthorized, "", "This login link is invalid.")
		return
	}
	if !a.claimLink(signature, issuedAt.Add(dashboardLinkLifetime)) {
		a.renderLoginForm(c, http.StatusUnauthorized, "", "This login link was already used. Run greyproxy dashboard-url again.")
		return
	}

	a.setSessionCookie(c)
	c.Redirect(http.StatusSeeOther, a.basePath+"/dashboard")
}

// claimLink records a link signature as used. It returns false when the
// signature was already used.
func (a *apiAuth) claimLink(signature string, expiresAt time.Time) bool {
	a.usedLinksMu.Lock()
	defer a.usedLinksMu.Unlock()

	now := time.Now()
	for usedSignature, usedExpiry := range a.usedLinks {
		if now.After(usedExpiry) {
			delete(a.usedLinks, usedSignature)
		}
	}
	if _, isUsed := a.usedLinks[signature]; isUsed {
		return false
	}
	a.usedLinks[signature] = expiresAt
	return true
}

func (a *apiAuth) setSessionCookie(c *gin.Context) {
	cookiePath := a.basePath
	if cookiePath == "" {
		cookiePath = "/"
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     dashboardSessionCookie,
		Value:    greyproxy.DashboardSessionValue(a.token),
		Path:     cookiePath,
		MaxAge:   dashboardSessionMaxAge,
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

// safeRedirectTarget keeps post-login redirects on this server's own paths.
func (a *apiAuth) safeRedirectTarget(next string) string {
	dashboardPath := a.basePath + "/dashboard"
	if !strings.HasPrefix(next, a.basePath+"/") ||
		strings.HasPrefix(next, "//") ||
		strings.Contains(next, "\\") {
		return dashboardPath
	}
	parsed, err := url.Parse(next)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return dashboardPath
	}
	return next
}

var loginFormTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Greyproxy login</title>
<style>
body { font-family: system-ui, sans-serif; background: #f4f4f5; color: #18181b; display: flex; min-height: 100vh; align-items: center; justify-content: center; margin: 0; }
main { background: #fff; border: 1px solid #e4e4e7; border-radius: 8px; padding: 32px; width: 100%; max-width: 420px; box-sizing: border-box; }
h1 { font-size: 20px; margin: 0 0 8px; }
p { font-size: 14px; line-height: 1.5; color: #52525b; margin: 0 0 16px; }
code { font-size: 13px; background: #f4f4f5; padding: 1px 4px; border-radius: 4px; }
label { display: block; font-size: 14px; font-weight: 600; margin-bottom: 6px; }
input[type=password] { width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 14px; border: 1px solid #d4d4d8; border-radius: 6px; }
button { margin-top: 16px; width: 100%; padding: 9px; font-size: 14px; font-weight: 600; color: #fff; background: #18181b; border: 0; border-radius: 6px; cursor: pointer; }
.error { color: #b91c1c; font-weight: 600; }
</style>
</head>
<body>
<main>
<h1>Greyproxy</h1>
<p>Run <code>greyproxy dashboard-url</code> and open the link it prints, or paste the token from <code>api-token</code> in greyproxy's data directory.</p>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="next" value="{{.Next}}">
<label for="token">API token</label>
<input type="password" id="token" name="token" autocomplete="current-password" required autofocus>
<button type="submit">Open dashboard</button>
</form>
</main>
</body>
</html>
`))

func (a *apiAuth) renderLoginForm(c *gin.Context, status int, next, errorMessage string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(status)
	_ = loginFormTemplate.Execute(c.Writer, map[string]string{
		"Action": a.basePath + "/login",
		"Next":   next,
		"Error":  errorMessage,
	})
}
