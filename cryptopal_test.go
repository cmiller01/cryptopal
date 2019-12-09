package cryptopal

import (
	"bytes"
	"testing"
)

func TestHexToBase64(t *testing.T) {

	input := []byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	expected := []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
	hexIn := &HexIn{Src: input}

	actual, err := hexIn.ToBase64()
	if err != nil {
		t.Errorf("expected nil error got %#v", err)
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf("expected %s, got %s", expected, actual)
	}

}

func TestFixedXOR(t *testing.T) {
	input := []byte("1c0111001f010100061a024b53535009181c")
	xored := []byte("686974207468652062756c6c277320657965")
	hexIn := &HexIn{Src: input}

	expected := []byte("746865206b696420646f6e277420706c6179")

	actual, _ := hexIn.FixedXOR(xored)
	if !bytes.Equal(actual, expected) {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}

func TestSingleXOR(t *testing.T) {
	input := []byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	expected := byte(88) // checked manually
	hexIn := &HexIn{Src: input}

	actual, _ := hexIn.SingleXOR()
	if actual != expected {
		t.Errorf("expected magic 88, got %d", actual)
	}
}

func TestFindXOR(t *testing.T) {
	input := challenge4
	res := FindXOR(input)
	fmt.Println("results %s", res)
}
