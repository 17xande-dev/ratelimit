package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// MaxAccountKeyBytes is the maximum length of an AccountKey result.
// It fits under the default MaxKeyBytes of 256; a hashed key is 71 bytes.
const MaxAccountKeyBytes = 200

// AccountKey turns an account identifier (an email address or a username) into
// a second-tier limiter key by trimming surrounding white space and lower-casing
// it. If the result is longer than MaxAccountKeyBytes, it returns "sha256:"
// plus the hex SHA-256 of the normalised value so long identifiers can use
// distinct buckets without being refused for their length.
func AccountKey(id string) string {
	key := strings.ToLower(strings.TrimSpace(id))
	// Lower-casing can increase the byte length, so check the normalised key.
	if len(key) <= MaxAccountKeyBytes {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(sum[:])
}
