package simple

import (
	"reflect"
	"testing"

	"github.com/dhcgn/crypto/hash"
)

func init() {
	hash.Iteration = 1
}

func TestEncrypt(t *testing.T) {
	type args struct {
		password  string
		plaintext []byte
	}
	tests := []struct {
		name             string
		args             args
		wantCipherstring string
		wantErr          bool
	}{
		{
			name: "No Error",
			args: args{
				password:  "my-secret-password",
				plaintext: []byte("my-secret-data"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCipherstring, err := Encrypt(tt.args.password, tt.args.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !isCipherStringValid(gotCipherstring) {
				t.Errorf("Encrypt() = isCipherStringValid is false")
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	type args struct {
		password     string
		cipherstring string
	}
	tests := []struct {
		name      string
		args      args
		wantPlain []byte
		wantErr   bool
	}{
		{
			name: "No Error",
			args: args{
				password:     "my-secret-password",
				cipherstring: "CSv1.443MMQSEWDPHEYKVS42FWJN633PS4EQIOFXDGMJOM2ON4ACJ.CIG44UL5BXWJU6JSW2BQ.KIORDLXAIJAT7NCTJHWYCE273Q",
			},
			wantPlain: []byte("my-secret-data"),
		},
		{
			name: "Error",
			args: args{
				password:     "my-secret-password",
				cipherstring: "WRONG FORMAT",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPlain, err := Decrypt(tt.args.password, tt.args.cipherstring)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPlain, tt.wantPlain) {
				t.Errorf("Decrypt() = %v, want %v", string(gotPlain), string(tt.wantPlain))
			}
		})
	}
}
