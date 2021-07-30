package hash

import (
	"crypto/rand"
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// Iteration number of Pbkdf2
	Iteration = 100_000
	keyLen    = 32
)

func HashPasswordWithPbkdf2(password string) (hash []byte, salt []byte) {
	salt = make([]byte, 16)
	rand.Read(salt)

	hash = pbkdf2.Key([]byte(password), salt, Iteration, keyLen, sha512.New)
	return hash, salt
}

func HashPasswordWithPbkdf2WithSalt(password string, salt []byte) (hash []byte) {
	hash = pbkdf2.Key([]byte(password), salt, Iteration, keyLen, sha512.New)
	return hash
}
