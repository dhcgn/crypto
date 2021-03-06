package simple

import (
	"crypto/aes"
	"crypto/rand"
	"io"

	"github.com/dhcgn/crypto/hash"

	"crypto/cipher"
)

// Encrypt encrypts a plaintext using the password.
// Uses AES-256-GCM (an authenticated encryption mode)
// to encrypt and decrypt data, password will be derived
// with PBKDF2 and 100.000 iterations. Because of this
// high iteration count the encryption and decryption process
// takes a minimum of around 200ms.
func Encrypt(password string, plaintext []byte) (cipherstring string, err error) {
	hash, salt := hash.HashPasswordWithPbkdf2(password)

	block, err := aes.NewCipher(hash[:32])
	if err != nil {
		return "", err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	cipherData := aesgcm.Seal(nil, nonce, plaintext, nil)

	//
	// fmt.Println("nonce", base32.StdEncoding.EncodeToString(nonce))
	// fmt.Println("ciphertext", base32.StdEncoding.EncodeToString(cipherData))
	// fmt.Println("hash", base32.StdEncoding.EncodeToString(hash))
	// fmt.Println("salt", base32.StdEncoding.EncodeToString(salt))
	//

	return toCipherString(cipherData, nonce, salt), nil
}

// Decrypt decrypts a ciphertext from the cipherstring using the password.
// Uses AES-256-GCM (an authenticated encryption mode)
// to encrypt and decrypt data, password will be derived
// with PBKDF2 and 100.000 iterations. Because of this
// high iteration count the encryption and decryption process
// takes a minimum of around 200ms.
func Decrypt(password string, cipherstring string) (plain []byte, err error) {
	ciphertext, nonce, salt, err := fromCipherString(cipherstring)
	if err != nil {
		return nil, err
	}

	hash := hash.HashPasswordWithPbkdf2WithSalt(password, salt)

	block, err := aes.NewCipher(hash[:32])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	//
	// fmt.Println("nonce", base32.StdEncoding.EncodeToString(nonce))
	// fmt.Println("ciphertext", base32.StdEncoding.EncodeToString(ciphertext))
	// fmt.Println("hash", base32.StdEncoding.EncodeToString(hash))
	// fmt.Println("salt", base32.StdEncoding.EncodeToString(salt))
	//

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
