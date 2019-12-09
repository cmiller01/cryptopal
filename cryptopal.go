package cryptopal

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// HexIn is a struct for taking a hex encoded byte slice as src
type HexIn struct {
	Src []byte // a hex encoded byte slice
}

// ToBase64 converts a hex to base64 (bytes) which can be cast as a string
// see: https://cryptopals.com/sets/1/challenges/1
func (h *HexIn) ToBase64() ([]byte, error) {
	// hex to bytes
	hexDst := make([]byte, hex.DecodedLen(len(h.Src)))
	n, err := hex.Decode(hexDst, h.Src)
	if err != nil {
		return nil, fmt.Errorf("can't decode h.Src %s due to %w", h.Src, err)
	}

	dst := make([]byte, base64.StdEncoding.EncodedLen(n))
	base64.StdEncoding.Encode(dst, hexDst)
	return dst, nil
}

// FixedXOR returns a slice of bytes that have been xored against a h.Src
// see: https://cryptopals.com/sets/1/challenges/2
func (h *HexIn) FixedXOR(xor []byte) ([]byte, error) {
	srcDecoded := make([]byte, hex.DecodedLen(len(h.Src)))
	xorDecoded := make([]byte, hex.DecodedLen(len(xor)))
	hex.Decode(srcDecoded, h.Src)
	hex.Decode(xorDecoded, xor)
	for i := range srcDecoded {
		srcDecoded[i] = srcDecoded[i] ^ xorDecoded[i]
	}
	dest := make([]byte, hex.EncodedLen(len(srcDecoded)))
	hex.Encode(dest, srcDecoded)
	return dest, nil
}

func singleXOR(input []byte, key byte) []byte {
	res := make([]byte, len(input))
	for i, value := range input {
		res[i] = value ^ key
	}
	return res
}

func scorePlaintext(input []byte) (score int) {

	if !utf8.Valid(input) {
		return score
	}
	// "score points" for two letters, points for printable characters
	// lose points for control characters and invalid encoded utf8 strings
	for i := range input {
		if unicode.IsLetter(rune(input[i])) {
			score += 2
		}
		if unicode.IsPrint(rune(input[i])) {
			score++
		}
		if unicode.IsPunct(rune(input[i])) {
			score--
		}
		if unicode.IsControl(rune(input[i])) {
			score -= 2
		}
	}
	return score

}

// SingleXOR returns the most likely value that was xored against a string
func (h *HexIn) SingleXOR() (byte, int) {
	decoded := make([]byte, hex.DecodedLen(len(h.Src)))
	result := make([]int, 256)
	hex.Decode(decoded, h.Src)
	for i := 0; i <= 255; i++ {
		key := byte(i)
		res := singleXOR(decoded, key)
		score := scorePlaintext(res)
		result[i] = score

	}
	var maxScore int
	var key byte
	for r := range result {
		if result[r] >= maxScore {
			key = byte(r)
			maxScore = result[r]
		}
	}
	return key, maxScore

}

// FindXOR find the decoded string among a bunch of strings...
func FindXOR(blob string) string {
	// turn into slice of strings
	input := strings.Fields(blob)
	results := make(map[int]int, len(input))
	for i := range input {
		h := &HexIn{Src: []byte(input[i])}
		_, results[i] = h.SingleXOR()
	}
	var maxScore int
	var idx int
	for k, v := range results {
		if v >= maxScore {
			maxScore = v
			idx = k
		}
	}
	h := &HexIn{Src: []byte(input[idx])}
	key, _ := h.SingleXOR()
	final := singleXOR(h.Src, key)
	return string(final)

}
