package main

import (
	"fmt"
	"time"

	"github.com/dhcgn/crypto/simple"
)

func main() {
	pwd := "my secret password"
	plain := "my-secret-data"

	fmt.Println("--- Encrypt")

	start := time.Now()
	cipherstring, err := simple.Encrypt(pwd, []byte(plain))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Encrypt() =", cipherstring, "\nDuration", time.Since(start))

	fmt.Println("--- Decrypt")

	start = time.Now()
	encrypted, err := simple.Decrypt(pwd, cipherstring)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Decrypt() =", string(encrypted), "\nDuration", time.Since(start))

}
