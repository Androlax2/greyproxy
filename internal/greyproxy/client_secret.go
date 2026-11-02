package greyproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// SessionIdentity is produced only by a unique live client-secret match.
// Keep its fields private: session IDs and client labels alone are not proof.
type SessionIdentity struct {
	sessionID     string
	containerName string
	secretHash    string
}

// CheckClientSecret preserves name-based login policy while identifying a
// session only when exactly one live session owns the supplied secret.
func CheckClientSecret(db *DB, containerName, password string) (identity *SessionIdentity, hasSecrets, accepted bool, err error) {
	rows, err := db.ReadDB().Query(
		`SELECT session_id, client_secret_hash FROM sessions
		 WHERE container_name = ? AND client_secret_hash IS NOT NULL AND expires_at > datetime('now')`, containerName,
	)
	if err != nil {
		return nil, false, false, err
	}
	defer func() { _ = rows.Close() }()
	passwordHash := HashClientSecret(password)
	matches := 0
	for rows.Next() {
		var sessionID, hash string
		if err := rows.Scan(&sessionID, &hash); err != nil {
			return nil, false, false, err
		}
		hasSecrets = true
		if subtle.ConstantTimeCompare([]byte(passwordHash), []byte(hash)) == 1 {
			matches++
			identity = &SessionIdentity{sessionID: sessionID, containerName: containerName, secretHash: hash}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, false, err
	}
	if matches != 1 {
		identity = nil
	}
	return identity, hasSecrets, matches > 0, nil
}

// Use in the same query as the grant lookup so revocation cannot race a
// separate identity check. A second session with the secret makes it ambiguous.
const activeSessionIdentitySQL = `session_id = ? AND session_id != ''
	AND container_name = ? AND client_secret_hash = ? AND expires_at > datetime('now')
	AND NOT EXISTS (SELECT 1 FROM sessions AS other
		WHERE other.container_name = sessions.container_name
		AND other.client_secret_hash = sessions.client_secret_hash
		AND other.session_id != sessions.session_id AND other.expires_at > datetime('now'))`

func (identity *SessionIdentity) credentials(containerName string) (sessionID, secretHash string) {
	if identity == nil || identity.containerName != containerName {
		return "", ""
	}
	return identity.sessionID, identity.secretHash
}

// MinClientSecretLength rejects secrets too short to resist guessing, such as
// the literal "proxy" clients used as a password before secrets existed.
const MinClientSecretLength = 32

// HashClientSecret returns the hex SHA-256 stored for a client secret.
func HashClientSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// LiveClientSecretHashes returns the secret hashes of the unexpired sessions
// registered for containerName. An empty result means the name has no secret.
func LiveClientSecretHashes(db *DB, containerName string) ([]string, error) {
	rows, err := db.ReadDB().Query(
		`SELECT client_secret_hash FROM sessions
		 WHERE container_name = ? AND client_secret_hash IS NOT NULL AND expires_at > datetime('now')`,
		containerName,
	)
	if err != nil {
		return nil, fmt.Errorf("query client secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("scan client secret: %w", err)
		}
		hashes = append(hashes, hash)
	}
	return hashes, rows.Err()
}

// ClientSecretMatches reports whether password hashes to one of hashes,
// comparing in constant time.
func ClientSecretMatches(password string, hashes []string) bool {
	passwordHash := []byte(HashClientSecret(password))
	isMatch := false
	for _, hash := range hashes {
		if subtle.ConstantTimeCompare(passwordHash, []byte(hash)) == 1 {
			isMatch = true
		}
	}
	return isMatch
}
