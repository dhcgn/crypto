package hash

import (
	"crypto/rand"
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

var (
	Iteration = 100_000
	keyLen    = 32
)

func HashPasswordWithPbkdf2(password string) ([]byte, []byte) {
	salt := make([]byte, 16)
	rand.Read(salt)

	hash := pbkdf2.Key([]byte(password), salt, Iteration, keyLen, sha512.New)
	return hash, salt
}

func HashPasswordWithPbkdf2WithSalt(password string, salt []byte) []byte {
	hash := pbkdf2.Key([]byte(password), salt, Iteration, keyLen, sha512.New)
	return hash
}
