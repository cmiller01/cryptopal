package cryptopal

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// HexToBase64 converts a hex to base64 (bytes) which can be cast as a string
// see: https://cryptopals.com/sets/1/challenges/1
func HexToBase64(src []byte) ([]byte, error) {
	// hex to bytes
	hexDst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(hexDst, src)
	if err != nil {
		return nil, fmt.Errorf("can't decode src %s due to %w", src, err)
	}

	dst := make([]byte, base64.StdEncoding.EncodedLen(n))
	base64.StdEncoding.Encode(dst, hexDst)
	return dst, nil
}

// FixedXOR returns a slice of bytes that have been xored against a src
func FixedXOR(src []byte, xor []byte) ([]byte, error) {
	srcDecoded := make([]byte, hex.DecodedLen(len(src)))
	xorDecoded := make([]byte, hex.DecodedLen(len(xor)))
	hex.Decode(srcDecoded, src)
	hex.Decode(xorDecoded, xor)
	for i := range srcDecoded {
		srcDecoded[i] = srcDecoded[i] ^ xorDecoded[i]
	}
	dest := make([]byte, hex.EncodedLen(len(srcDecoded)))
	hex.Encode(dest, srcDecoded)
	return dest, nil
}
