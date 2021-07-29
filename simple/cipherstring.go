package simple

import (
	"encoding/base32"
	"fmt"
	"strings"
)

const versiontag = "CSv1"

func fromCipherString(cipherString string) (cipherData, nonce, salt []byte, err error) {
	if !isCipherStringValid(cipherString) {
		return nil, nil, nil, fmt.Errorf("invalid cipher string: %v", cipherString)
	}
	splits := strings.Split(cipherString, ".")

	cipherData, err = decodeStringWithNoPadding(splits[1])
	if err != nil {
		return nil, nil, nil, err
	}
	nonce, err = decodeStringWithNoPadding(splits[2])
	if err != nil {
		return nil, nil, nil, err
	}
	salt, err = decodeStringWithNoPadding(splits[3])
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
	return fmt.Sprintf("%v.%v.%v.%v",
		versiontag,
		encodeStringWithNoPadding(cipherData),
		encodeStringWithNoPadding(nonce),
		encodeStringWithNoPadding(salt))
}

func isCipherStringValid(input string) bool {
	if input == "" {
		return false
	}

	splits := strings.Split(input, ".")
	if len(splits) != 4 {
		return false
	}

	for _, v := range splits[1:] {
		_, err := decodeStringWithNoPadding(v)
		if err != nil {
			return false
		}
	}
	return true
}
