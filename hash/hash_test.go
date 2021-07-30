package hash

import (
	"reflect"
	"testing"
)

func TestHashPasswordWithPbkdf2(t *testing.T) {
	type args struct {
		password string
	}
	tests := []struct {
		name           string
		args           args
		wantHashLength int
		wantSaltLength int
	}{
		{
			name: "Length",
			args: args{
				password: "password",
			},
			wantHashLength: 32,
			wantSaltLength: 16,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHash, gotSalt := HashPasswordWithPbkdf2(tt.args.password)
			if len(gotHash) != tt.wantHashLength {
				t.Errorf("HashPasswordWithPbkdf2() gotHashLength = %v, want %v", len(gotHash), tt.wantHashLength)
			}
			if len(gotSalt) != tt.wantSaltLength {
				t.Errorf("HashPasswordWithPbkdf2() gotSaltLength = %v, want %v", len(gotSalt), tt.wantSaltLength)
			}
		})
	}
}

func TestHashPasswordWithPbkdf2WithSalt(t *testing.T) {
	type args struct {
		password string
		salt     []byte
	}
	tests := []struct {
		name     string
		args     args
		wantHash []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotHash := HashPasswordWithPbkdf2WithSalt(tt.args.password, tt.args.salt); !reflect.DeepEqual(gotHash, tt.wantHash) {
				t.Errorf("HashPasswordWithPbkdf2WithSalt() = %v, want %v", gotHash, tt.wantHash)
			}
		})
	}
}
