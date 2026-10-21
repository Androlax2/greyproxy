package greyproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

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
