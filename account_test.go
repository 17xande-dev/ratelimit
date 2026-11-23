package ratelimit

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAccountKey(t *testing.T) {
	if MaxAccountKeyBytes != 200 {
		t.Errorf("MaxAccountKeyBytes = %d, want 200", MaxAccountKeyBytes)
	}
	const suffix = "@example.com"
	longAddress := strings.Repeat("a", 5000-len(suffix)) + suffix
	digest := func(normalised string) string {
		return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(normalised)))
	}
	for _, tc := range []struct {
		name, id, want string
	}{
		{"padded mixed-case email", "  Owner@Example.COM ", "owner@example.com"},
		{"200 bytes after normalisation", " " + strings.Repeat("A", 200) + " ", strings.Repeat("a", 200)},
		{"201 bytes", strings.Repeat("a", 201), digest(strings.Repeat("a", 201))},
		{"grows after lower-casing", strings.Repeat("\u023a", 100), digest(strings.Repeat("\u2c65", 100))},
		{"5000-byte email", longAddress, digest(longAddress)},
		{"5000-byte email with extra byte", longAddress + "x", digest(longAddress + "x")},
		{"uppercase 5000-byte email", strings.ToUpper(longAddress), digest(longAddress)},
		{"short invalid UTF-8", "A\xff", "a\ufffd"},
		{"long invalid UTF-8", strings.Repeat("\xff", 100), digest(strings.Repeat("\ufffd", 100))},
		{"literal hash prefix", "sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("a", 64)},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := AccountKey(tc.id); got != tc.want {
				t.Errorf("AccountKey result starts with %.80q (%d bytes), want %.80q (%d bytes)", got, len(got), tc.want, len(tc.want))
			}
		})
	}
}

func FuzzAccountKey(f *testing.F) {
	for _, id := range []string{
		"", "  Owner@Example.COM ", strings.Repeat("A", 200), strings.Repeat("A", 201),
		strings.Repeat("\u023a", 100), "A\xff", strings.Repeat("\xff", 100),
	} {
		f.Add(id)
	}
	f.Fuzz(func(t *testing.T, id string) {
		key := AccountKey(id)
		if len(key) > MaxAccountKeyBytes {
			t.Errorf("key length = %d, exceeds MaxAccountKeyBytes (%d)", len(key), MaxAccountKeyBytes)
		}
		if len(key) > 256 {
			t.Errorf("key length = %d, exceeds the default MaxKeyBytes (256)", len(key))
		}
		if AccountKey(id) != key {
			t.Error("AccountKey returned different keys for the same input")
		}
		if strings.IndexFunc(id, func(r rune) bool { return r >= utf8.RuneSelf }) < 0 &&
			AccountKey(strings.ToUpper(id)) != key {
			t.Error("AccountKey returned different keys for ASCII case variants")
		}
	})
}
