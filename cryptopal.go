package cryptopal

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

// SingleXOR returns the most likely value that was xored against a string
func (h *HexIn) SingleXOR() byte {
	decoded := make([]byte, hex.DecodedLen(len(h.Src)))
	result := make([]int, 256)
	hex.Decode(decoded, h.Src)
	for i := 0; i <= 255; i++ {
		key := byte(i)
		res := singleXOR(decoded, key)
		// "score points" for two letters, points for printable characters
		// lose points for control characters and invalid encoded utf8 strings
		var score int
		for i := range res {
			// if the whole thing isn't valid utf8 then throw it out...
			if utf8.Valid(res) {
				if unicode.IsLetter(rune(res[i])) {
					score += 2
				}
				if unicode.IsPrint(rune(res[i])) {
					score++
				}
				if unicode.IsPunct(rune(res[i])) {
					score--
				}
				if unicode.IsControl(rune(res[i])) {
					score -= 2
				}
			}
		}
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
	return key

}
