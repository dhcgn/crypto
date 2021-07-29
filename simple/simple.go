package simple

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"strings"

	"github.com/dhcgn/crypto/hash"

	"crypto/cipher"
)

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

func toCipherString(cipherData, nonce, salt []byte) string {
	toBase32 := func(data []byte) string {
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	}

	return fmt.Sprintf("%v.%v.%v", toBase32(cipherData), toBase32(nonce), toBase32(salt))
}

func fromCipherString(cipherString string) (cipherData, nonce, salt []byte, err error) {
	splits := strings.Split(cipherString, ".")

	cipherData, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(splits[0])
	if err != nil {
		return nil, nil, nil, err
	}
	nonce, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(splits[1])
	if err != nil {
		return nil, nil, nil, err
	}
	salt, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(splits[2])
	if err != nil {
		return nil, nil, nil, err
	}

	return
}

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
