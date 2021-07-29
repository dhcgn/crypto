package simple

import (
	"encoding/base32"
	"fmt"
	"strings"
)

func fromCipherString(cipherString string) (cipherData, nonce, salt []byte, err error) {
	splits := strings.Split(cipherString, ".")

	cipherData, err = decodeStringWithNoPadding(splits[0])
	if err != nil {
		return nil, nil, nil, err
	}
	nonce, err = decodeStringWithNoPadding(splits[1])
	if err != nil {
		return nil, nil, nil, err
	}
	salt, err = decodeStringWithNoPadding(splits[2])
	if err != nil {
		return nil, nil, nil, err
	}

	return
}

func decodeStringWithNoPadding(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

func encodeStringWithNoPadding(s []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s)
}

func toCipherString(cipherData, nonce, salt []byte) string {
	return fmt.Sprintf("%v.%v.%v",
		encodeStringWithNoPadding(cipherData),
		encodeStringWithNoPadding(nonce),
		encodeStringWithNoPadding(salt))
}

func isCipherStringValid(input string) bool {
	if input == "" {
		return false
	}

	splits := strings.Split(input, ".")
	if len(splits) != 3 {
		return false
	}

	for _, v := range splits {
		_, err := decodeStringWithNoPadding(v)
		if err != nil {
			return false
		}
	}
	return true
}
