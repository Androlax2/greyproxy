package greyproxy

import (
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestLoadOrCreateAPITokenCreatesPrivateHexToken(t *testing.T) {
	dataDir := t.TempDir()

	token, err := LoadOrCreateAPIToken(dataDir)
	if err != nil {
		t.Fatal(err)
	}

	if decoded, err := hex.DecodeString(token); err != nil || len(decoded) != 32 {
		t.Errorf("token %q is not 32 hex-encoded bytes", token)
	}
	fileInfo, err := os.Stat(APITokenPath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fileInfo.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %04o, want 0600", fileInfo.Mode().Perm())
	}
}

func TestLoadOrCreateAPITokenReturnsTheExistingToken(t *testing.T) {
	dataDir := t.TempDir()

	firstToken, err := LoadOrCreateAPIToken(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	secondToken, err := LoadOrCreateAPIToken(dataDir)
	if err != nil {
		t.Fatal(err)
	}

	if firstToken != secondToken {
		t.Errorf("second start returned a new token %q, want the existing %q", secondToken, firstToken)
	}
}

func TestLoadOrCreateAPITokenRefusesACorruptFile(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(APITokenPath(dataDir), []byte("not-a-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreateAPIToken(dataDir); err == nil {
		t.Fatal("LoadOrCreateAPIToken accepted a corrupt token file, want an error")
	}
	contents, _ := os.ReadFile(APITokenPath(dataDir))
	if string(contents) != "not-a-token" {
		t.Errorf("corrupt token file was overwritten with %q", contents)
	}
}

func TestLoadOrCreateAPITokenRefusesAFileOtherUsersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not apply on Windows")
	}
	dataDir := t.TempDir()
	validToken := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := os.WriteFile(APITokenPath(dataDir), []byte(validToken), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(APITokenPath(dataDir), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreateAPIToken(dataDir); err == nil {
		t.Fatal("LoadOrCreateAPIToken accepted a world-readable token file, want an error")
	}
}

func TestReadAPITokenReportsAMissingFile(t *testing.T) {
	_, err := ReadAPIToken(t.TempDir())

	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ReadAPIToken error = %v, want one wrapping os.ErrNotExist", err)
	}
}

func TestReadAPITokenTrimsATrailingNewline(t *testing.T) {
	dataDir := t.TempDir()
	validToken := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := os.WriteFile(APITokenPath(dataDir), []byte(validToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	token, err := ReadAPIToken(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if token != validToken {
		t.Errorf("token = %q, want %q", token, validToken)
	}
}
