package cryptopal

import (
	"bytes"
	"encoding/base64"
	"fmt"
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

	actual, _, _ := hexIn.SingleXOR()
	if actual != expected {
		t.Errorf("expected magic 88, got %d", actual)
	}

}

func TestFindXOR(t *testing.T) {
	input := challenge4
	actual := FindXOR(input)
	expected := "Now that the party is jumping\n"
	if string(actual) != expected {
		t.Errorf("expected %#v got %#v", expected, actual)
	}
}

func TestRepeatingXOR(t *testing.T) {
	input := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

	key := "ICE"

	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	actual := RepeatingKeyXOR(input, key)
	if expected != actual {
		t.Errorf("\nexpected %s\n     got %s", expected, actual)
	}
}

func TestBreakRepeatingXOR(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(challenge6)
	if err != nil {
		t.FailNow()
	}
	res, err := BreakRepeatingXOR(data)
	if err != nil {
		t.Errorf("expected nil error got %s", err)
	}
	fmt.Printf("got %s", res)

}
