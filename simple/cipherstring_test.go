package simple

import (
	"reflect"
	"testing"
)

func Test_fromCipherString(t *testing.T) {
	type args struct {
		cipherString string
	}
	tests := []struct {
		name           string
		args           args
		wantCipherData []byte
		wantNonce      []byte
		wantSalt       []byte
		wantErr        bool
	}{
		{
			name: "From Cipher String",
			args: args{
				cipherString: "CSv1.AE.AI.AM",
			},
			wantCipherData: []byte{0x01},
			wantNonce:      []byte{0x02},
			wantSalt:       []byte{0x03},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCipherData, gotNonce, gotSalt, err := fromCipherString(tt.args.cipherString)
			if (err != nil) != tt.wantErr {
				t.Errorf("fromCipherString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotCipherData, tt.wantCipherData) {
				t.Errorf("fromCipherString() gotCipherData = %v, want %v", gotCipherData, tt.wantCipherData)
			}
			if !reflect.DeepEqual(gotNonce, tt.wantNonce) {
				t.Errorf("fromCipherString() gotNonce = %v, want %v", gotNonce, tt.wantNonce)
			}
			if !reflect.DeepEqual(gotSalt, tt.wantSalt) {
				t.Errorf("fromCipherString() gotSalt = %v, want %v", gotSalt, tt.wantSalt)
			}
		})
	}
}

func Test_decodeStringWithNoPadding(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Decode String",
			args: args{
				s: "AE",
			},
			want: []byte{0x01},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeStringWithNoPadding(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeStringWithNoPadding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeStringWithNoPadding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_encodeStringWithNoPadding(t *testing.T) {
	type args struct {
		s []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Encode String",
			args: args{
				s: []byte{0x01},
			},
			want: "AE",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeStringWithNoPadding(tt.args.s); got != tt.want {
				t.Errorf("encodeStringWithNoPadding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_toCipherString(t *testing.T) {
	type args struct {
		cipherData []byte
		nonce      []byte
		salt       []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "To Cipher String",
			args: args{
				cipherData: []byte{0x01},
				nonce:      []byte{0x02},
				salt:       []byte{0x03},
			},
			want: "CSv1.AE.AI.AM",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toCipherString(tt.args.cipherData, tt.args.nonce, tt.args.salt); got != tt.want {
				t.Errorf("toCipherString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isCipherStringValid(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Minimum",
			args: args{
				input: "CSv1.AE.AI.AM",
			},
			want: true,
		},
		{
			name: "Real World Sample",
			args: args{
				input: "CSv1.443MMQSEWDPHEYKVS42FWJN633PS4EQIOFXDGMJOM2ON4ACJ.CIG44UL5BXWJU6JSW2BQ.KIORDLXAIJAT7NCTJHWYCE273Q",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCipherStringValid(tt.args.input); got != tt.want {
				t.Errorf("isCipherStringValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
