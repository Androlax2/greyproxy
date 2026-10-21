package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	greyproxy "github.com/greyhavenhq/greyproxy/internal/greyproxy"
)

const testClientSecret = "client-secret-0123456789abcdefghijklmnopqrstu"

func newSessionsRouter(t *testing.T) (*gin.Engine, *Shared) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	shared := setupTestSharedWithCreds(t)
	router := gin.New()
	router.POST("/api/sessions", SessionsCreateHandler(shared))
	router.GET("/api/sessions", SessionsListHandler(shared))
	return router, shared
}

func postSession(router *gin.Engine, body map[string]any) *httptest.ResponseRecorder {
	encodedBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(encodedBody))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestSessionsCreateAcceptsAClientSecretOnItsOwn(t *testing.T) {
	router, shared := newSessionsRouter(t)

	response := postSession(router, map[string]any{
		"session_id": "gw-secret-only", "container_name": "opencode", "client_secret": testClientSecret,
	})

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", response.Code, response.Body.String())
	}
	hashes, err := greyproxy.LiveClientSecretHashes(shared.DB, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 1 || hashes[0] != greyproxy.HashClientSecret(testClientSecret) {
		t.Errorf("stored hashes = %v, want the SHA-256 of the secret", hashes)
	}
}

func TestSessionsCreateRefusesAShortClientSecret(t *testing.T) {
	router, _ := newSessionsRouter(t)

	response := postSession(router, map[string]any{
		"session_id": "gw-short", "container_name": "opencode", "client_secret": "proxy",
	})

	if response.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body = %s", response.Code, response.Body.String())
	}
}

func TestSessionsCreateStillRequiresSomethingToRegister(t *testing.T) {
	router, _ := newSessionsRouter(t)

	response := postSession(router, map[string]any{"session_id": "gw-empty", "container_name": "opencode"})

	if response.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body = %s", response.Code, response.Body.String())
	}
}

func TestSessionsReregisteredWithoutASecretDropsTheOldSecret(t *testing.T) {
	router, shared := newSessionsRouter(t)
	postSession(router, map[string]any{
		"session_id": "gw-re", "container_name": "opencode", "client_secret": testClientSecret,
	})

	response := postSession(router, map[string]any{
		"session_id": "gw-re", "container_name": "opencode", "allow_all": true,
	})

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", response.Code, response.Body.String())
	}
	hashes, err := greyproxy.LiveClientSecretHashes(shared.DB, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 0 {
		t.Errorf("stored hashes = %v, want none after re-registering without a secret", hashes)
	}
}

func TestSessionsResponsesNeverContainTheClientSecret(t *testing.T) {
	router, _ := newSessionsRouter(t)
	createResponse := postSession(router, map[string]any{
		"session_id": "gw-hidden", "container_name": "opencode", "client_secret": testClientSecret,
	})

	listRecorder := httptest.NewRecorder()
	router.ServeHTTP(listRecorder, httptest.NewRequest(http.MethodGet, "/api/sessions", nil))

	secretHash := greyproxy.HashClientSecret(testClientSecret)
	for endpoint, body := range map[string]string{
		"POST /api/sessions": createResponse.Body.String(),
		"GET /api/sessions":  listRecorder.Body.String(),
	} {
		if strings.Contains(body, testClientSecret) || strings.Contains(body, secretHash) || strings.Contains(body, "client_secret") {
			t.Errorf("%s exposes the client secret or its hash: %s", endpoint, body)
		}
	}
	if !strings.Contains(listRecorder.Body.String(), "gw-hidden") {
		t.Errorf("GET /api/sessions does not list the session: %s", listRecorder.Body.String())
	}
}
