package greyproxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	apiTokenFile  = "api-token"
	apiTokenBytes = 32
)

// APITokenPath returns where the management API token lives in dataDir.
func APITokenPath(dataDir string) string {
	return filepath.Join(dataDir, apiTokenFile)
}

// LoadOrCreateAPIToken returns the management API token from dataDir/api-token,
// creating it (32 random bytes, hex-encoded, mode 0600) when it does not exist.
// A corrupt file or one other users can read is an error, never overwritten:
// clients such as greywall read the same file.
func LoadOrCreateAPIToken(dataDir string) (string, error) {
	token, err := ReadAPIToken(dataDir)
	if err == nil {
		return token, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	randomBytes := make([]byte, apiTokenBytes)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", fmt.Errorf("generate API token: %w", err)
	}
	token = hex.EncodeToString(randomBytes)

	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return "", fmt.Errorf("create data dir: %w", err)
	}
	tokenPath := APITokenPath(dataDir)
	// O_EXCL: two processes starting at once must not overwrite each other's token.
	tokenFile, err := os.OpenFile(tokenPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ReadAPIToken(dataDir)
	}
	if err != nil {
		return "", fmt.Errorf("create API token file: %w", err)
	}
	if _, err := tokenFile.WriteString(token); err != nil {
		_ = tokenFile.Close()
		return "", fmt.Errorf("write API token file %s: %w", tokenPath, err)
	}
	if err := tokenFile.Close(); err != nil {
		return "", fmt.Errorf("write API token file %s: %w", tokenPath, err)
	}
	return token, nil
}

// ReadAPIToken reads an existing token from dataDir/api-token. The error wraps
// os.ErrNotExist when the file is missing.
func ReadAPIToken(dataDir string) (string, error) {
	tokenPath := APITokenPath(dataDir)
	fileInfo, err := os.Stat(tokenPath)
	if err != nil {
		return "", fmt.Errorf("read API token: %w", err)
	}
	if runtime.GOOS != "windows" && fileInfo.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("API token file %s is accessible to other users (mode %04o); run: chmod 600 %s",
			tokenPath, fileInfo.Mode().Perm(), tokenPath)
	}

	contents, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("read API token: %w", err)
	}
	token := strings.TrimSpace(string(contents))
	if decoded, err := hex.DecodeString(token); err != nil || len(decoded) != apiTokenBytes {
		return "", fmt.Errorf("API token file %s is corrupt (want %d hex characters); delete it to generate a new token, then restart greyproxy and every client that reads it",
			tokenPath, apiTokenBytes*2)
	}
	return token, nil
}

// SignDashboardLogin returns the signature of a dashboard login link issued at
// issuedAtUnix. The link proves knowledge of the token without carrying it.
func SignDashboardLogin(token string, issuedAtUnix int64) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("greyproxy-dashboard-login:" + strconv.FormatInt(issuedAtUnix, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// DashboardSessionValue is the cookie value that authenticates the dashboard.
// It is derived from the token so the browser never stores the token itself.
func DashboardSessionValue(token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("greyproxy-dashboard-session"))
	return hex.EncodeToString(mac.Sum(nil))
}
