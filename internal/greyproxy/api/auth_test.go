package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	xlogger "github.com/greyhavenhq/greyproxy/internal/gostx/logger"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

const testAPIToken = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// newAuthTestRouter builds the real router plus stand-ins for the routes the
// UI package registers later on the returned group (a page and an /htmx
// endpoint), to prove the check also covers routes added after NewRouter.
func newAuthTestRouter(t *testing.T, token string, isRequired bool, pathPrefix string) *gin.Engine {
	t.Helper()
	// NewRouter's WebSocket handler reads logger.Default(), which only the binary installs.
	logger.SetDefault(xlogger.Nop())
	shared := setupTestShared(t)
	shared.APIToken = token
	shared.RequireAPIToken = isRequired

	router, group := NewRouter(shared, pathPrefix)
	group.GET("/dashboard", func(c *gin.Context) { c.String(http.StatusOK, "dashboard page") })
	group.POST("/htmx/rules", func(c *gin.Context) { c.String(http.StatusOK, "rule created") })
	return router
}

func serve(router *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func withBearer(req *http.Request, token string) *http.Request {
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func sessionCookieFrom(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == dashboardSessionCookie {
			return cookie
		}
	}
	return nil
}

func signedLoginPath(issuedAt time.Time) string {
	issuedAtUnix := issuedAt.Unix()
	return "/auth?ts=" + strconv.FormatInt(issuedAtUnix, 10) + "&sig=" + greyproxy.SignDashboardLogin(testAPIToken, issuedAtUnix)
}

func postLoginForm(router *gin.Engine, token, next string) *httptest.ResponseRecorder {
	form := url.Values{"token": {token}, "next": {next}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return serve(router, req)
}

func TestAPITokenCheckRejectsRequestsWithoutAValidToken(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		token  string
	}{
		{"REST API without a token", http.MethodGet, "/api/rules", ""},
		{"REST API with a wrong token", http.MethodGet, "/api/rules", strings.Repeat("ab", 32)},
		{"REST API with an empty bearer", http.MethodGet, "/api/rules", " "},
		{"allow-all switch without a token", http.MethodPost, "/api/allowall", ""},
		{"session registration without a token", http.MethodPost, "/api/sessions", ""},
		{"HTMX endpoint registered after NewRouter", http.MethodPost, "/htmx/rules", ""},
		{"WebSocket", http.MethodGet, "/ws", ""},
	}

	router := newAuthTestRouter(t, testAPIToken, true, "/")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.token != "" {
				withBearer(req, tt.token)
			}

			response := serve(router, req)

			if response.Code != http.StatusUnauthorized {
				t.Errorf("%s %s = %d, want 401", tt.method, tt.path, response.Code)
			}
		})
	}
}

func TestAPITokenCheckAcceptsTheBearerToken(t *testing.T) {
	router := newAuthTestRouter(t, testAPIToken, true, "/")

	response := serve(router, withBearer(httptest.NewRequest(http.MethodGet, "/api/rules", nil), testAPIToken))

	if response.Code != http.StatusOK {
		t.Errorf("GET /api/rules with the token = %d, want 200", response.Code)
	}
}

func TestAPITokenCheckLeavesHealthAndStaticFilesOpen(t *testing.T) {
	router := newAuthTestRouter(t, testAPIToken, true, "/")

	for _, path := range []string{"/api/health", "/static/missing.css"} {
		response := serve(router, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code == http.StatusUnauthorized || response.Code == http.StatusSeeOther {
			t.Errorf("GET %s = %d, want it reachable without a token", path, response.Code)
		}
	}
}

func TestAPITokenCheckRedirectsPagesToTheLoginForm(t *testing.T) {
	router := newAuthTestRouter(t, testAPIToken, true, "/")

	response := serve(router, httptest.NewRequest(http.MethodGet, "/dashboard?tab=1", nil))

	if response.Code != http.StatusSeeOther {
		t.Fatalf("GET /dashboard = %d, want 303", response.Code)
	}
	if location := response.Header().Get("Location"); location != "/login?next=%2Fdashboard%3Ftab%3D1" {
		t.Errorf("Location = %q, want the login form with next=/dashboard?tab=1", location)
	}
}

func TestAPITokenCheckIsOffByDefault(t *testing.T) {
	router := newAuthTestRouter(t, testAPIToken, false, "/")

	response := serve(router, httptest.NewRequest(http.MethodGet, "/api/rules", nil))

	if response.Code != http.StatusOK {
		t.Errorf("GET /api/rules with the check off = %d, want 200", response.Code)
	}
}

func TestAPITokenCheckFailsClosedWithoutAToken(t *testing.T) {
	router := newAuthTestRouter(t, "", true, "/")

	response := serve(router, withBearer(httptest.NewRequest(http.MethodGet, "/api/rules", nil), ""))

	if response.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/rules with no configured token = %d, want 401", response.Code)
	}
}

func TestLoginFormSetsAStrictHTTPOnlySessionCookie(t *testing.T) {
	router := newAuthTestRouter(t, testAPIToken, true, "/")

	response := postLoginForm(router, testAPIToken, "/dashboard")

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/dashboard" {
		t.Fatalf("POST /login = %d to %q, want 303 to /dashboard", response.Code, response.Header().Get("Location"))
	}
	cookie := sessionCookieFrom(t, response)
	if cookie == nil {
		t.Fatal("POST /login set no session cookie")
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie HttpOnly=%v SameSite=%v, want HttpOnly and SameSite=Strict", cookie.HttpOnly, cookie.SameSite)
	}
	if strings.Contains(cookie.Value, testAPIToken) {
		t.Error("session cookie contains the raw API token")
	}
}

func TestSessionCookieAuthenticatesPagesAndAPI(t *testing.T) {
	router := newAuthTestRouter(t, testAPIToken, true, "/")
	cookie := sessionCookieFrom(t, postLoginForm(router, testAPIToken, ""))
	if cookie == nil {
		t.Fatal("POST /login set no session cookie")
	}

	for _, path := range []string{"/dashboard", "/api/rules"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		if response := serve(router, req); response.Code != http.StatusOK {
			t.Errorf("GET %s with the session cookie = %d, want 200", path, response.Code)
		}
	}
}

func TestLoginFormRejectsAWrongToken(t *testing.T) {
	router := newAuthTestRouter(t, testAPIToken, true, "/")

	response := postLoginForm(router, strings.Repeat("ab", 32), "/dashboard")

	if response.Code != http.StatusUnauthorized {
		t.Errorf("POST /login with a wrong token = %d, want 401", response.Code)
	}
	if sessionCookieFrom(t, response) != nil {
		t.Error("POST /login with a wrong token set a session cookie")
	}
}

func TestLoginFormOnlyRedirectsToLocalPaths(t *testing.T) {
	tests := []struct {
		next string
		want string
	}{
		{"/pending?x=1", "/pending?x=1"},
		{"//evil.example/", "/dashboard"},
		{"https://evil.example/", "/dashboard"},
		{"/\\evil.example", "/dashboard"},
		{"", "/dashboard"},
	}

	router := newAuthTestRouter(t, testAPIToken, true, "/")
	for _, tt := range tests {
		t.Run(tt.next, func(t *testing.T) {
			response := postLoginForm(router, testAPIToken, tt.next)
			if location := response.Header().Get("Location"); location != tt.want {
				t.Errorf("next=%q redirected to %q, want %q", tt.next, location, tt.want)
			}
		})
	}
}

func TestSignedLoginLinkWorksOnce(t *testing.T) {
	router := newAuthTestRouter(t, testAPIToken, true, "/")
	linkPath := signedLoginPath(time.Now())

	firstUse := serve(router, httptest.NewRequest(http.MethodGet, linkPath, nil))
	if firstUse.Code != http.StatusSeeOther || sessionCookieFrom(t, firstUse) == nil {
		t.Fatalf("first use of the link = %d, want 303 with a session cookie", firstUse.Code)
	}

	secondUse := serve(router, httptest.NewRequest(http.MethodGet, linkPath, nil))
	if secondUse.Code != http.StatusUnauthorized || sessionCookieFrom(t, secondUse) != nil {
		t.Errorf("second use of the link = %d, want 401 without a cookie", secondUse.Code)
	}
}

func TestSignedLoginLinkIsRefusedWhenInvalid(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		path string
	}{
		{"expired", signedLoginPath(now.Add(-3 * time.Minute))},
		{"issued in the future", signedLoginPath(now.Add(5 * time.Minute))},
		{"wrong signature", "/auth?ts=" + strconv.FormatInt(now.Unix(), 10) + "&sig=" + strings.Repeat("0", 64)},
		{"missing signature", "/auth?ts=" + strconv.FormatInt(now.Unix(), 10)},
	}

	router := newAuthTestRouter(t, testAPIToken, true, "/")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := serve(router, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if response.Code != http.StatusUnauthorized || sessionCookieFrom(t, response) != nil {
				t.Errorf("GET %s = %d, want 401 without a cookie", tt.path, response.Code)
			}
		})
	}
}

func TestAPITokenCheckHonoursThePathPrefix(t *testing.T) {
	router := newAuthTestRouter(t, testAPIToken, true, "/proxy/")

	unauthenticated := serve(router, httptest.NewRequest(http.MethodGet, "/proxy/api/rules", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Errorf("GET /proxy/api/rules without a token = %d, want 401", unauthenticated.Code)
	}

	page := serve(router, httptest.NewRequest(http.MethodGet, "/proxy/dashboard", nil))
	if location := page.Header().Get("Location"); location != "/proxy/login?next=%2Fproxy%2Fdashboard" {
		t.Errorf("Location = %q, want the prefixed login form", location)
	}

	login := serve(router, httptest.NewRequest(http.MethodGet, signedLoginPathWithPrefix("/proxy", time.Now()), nil))
	cookie := sessionCookieFrom(t, login)
	if login.Header().Get("Location") != "/proxy/dashboard" || cookie == nil || cookie.Path != "/proxy" {
		t.Errorf("prefixed login link = %d to %q with cookie %+v, want 303 to /proxy/dashboard and cookie path /proxy",
			login.Code, login.Header().Get("Location"), cookie)
	}
}

func signedLoginPathWithPrefix(basePath string, issuedAt time.Time) string {
	return basePath + signedLoginPath(issuedAt)
}
