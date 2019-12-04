package cryptopal

import (
	"bytes"
	"testing"
)

func TestHexToBase64(t *testing.T) {

	input := []byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	expected := []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

	actual, err := HexToBase64(input)
	if err != nil {
		t.Errorf("expected nil error got %#v", err)
	}
	if bytes.Compare(actual, expected) != 0 {
		t.Errorf("expected %s, got %s", expected, actual)
	}

}

func TestFixedXOR(t *testing.T) {
	input := []byte("1c0111001f010100061a024b53535009181c")
	xored := []byte("686974207468652062756c6c277320657965")

	expected := []byte("746865206b696420646f6e277420706c6179")

	actual, _ := FixedXOR(input, xored)
	if bytes.Compare(actual, expected) != 0 {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}
