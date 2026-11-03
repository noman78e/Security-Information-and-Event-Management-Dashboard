// Package auth protects the dashboard with a password: salted password
// hashing, sign-in sessions, a first-run setup code, and lock-out after
// repeated wrong guesses. It uses only the Go standard library.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Iterations is the PBKDF2 work factor used for new passwords. Stored
// hashes remember their own value, so this can be raised later.
var Iterations = 150000

// pbkdf2SHA256 is PBKDF2 with HMAC-SHA256 (RFC 8018).
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	numBlocks := (keyLen + hLen - 1) / hLen
	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hLen)
	U := make([]byte, hLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hLen:]
		copy(U, T)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

// HashPassword returns "pbkdf2-sha256$iterations$salt$hash".
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(pw), salt, Iterations, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", Iterations, enc.EncodeToString(salt), enc.EncodeToString(dk)), nil
}

// VerifyPassword checks a password against a stored hash in constant time.
func VerifyPassword(pw, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10000000 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(want) < 16 {
		return false
	}
	got := pbkdf2SHA256([]byte(pw), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ValidatePassword enforces a minimum quality for new passwords.
func ValidatePassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	switch {
	case n < 10:
		return errors.New("the password must have at least 10 characters")
	case n > 128:
		return errors.New("the password must have at most 128 characters")
	case strings.TrimSpace(pw) == "":
		return errors.New("the password cannot be only spaces")
	}
	return nil
}
