package cryptopal

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
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

func scoreWord(word string) int {
	// see https://norvig.com/mayzner.html
	wordLength := len(word)
	switch wordLength {
	case 1, 9, 10:
		return 2
	case 2, 3, 4:
		return 10
	case 5, 6, 7, 8:
		return 4
	}
	if len(word) > 20 {
		return 0
	}
	return 1
}

// singleXOR returns the input xored against a key
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
	words := strings.Fields(string(input))
	for i := range words {
		score += scoreWord(words[i])
	}
	return score

}

// SingleXOR returns the most likely value that was xored against a string
func (h *HexIn) SingleXOR() (byte, int, []byte) {
	decoded := make([]byte, hex.DecodedLen(len(h.Src)))
	result := make([]int, 256)
	resultPlain := make([][]byte, 256)
	hex.Decode(decoded, h.Src)
	for i := 0; i <= 255; i++ {
		key := byte(i)
		res := singleXOR(decoded, key)
		score := scorePlaintext(res)
		result[i] = score
		resultPlain[i] = res
	}
	var maxScore int
	var key byte
	for r := range result {
		if result[r] >= maxScore {
			key = byte(r)
			maxScore = result[r]
		}
	}
	return key, maxScore, resultPlain[key]

}

// FindXOR find the decoded string among a bunch of strings...
func FindXOR(blob string) string {
	// turn into slice of strings
	input := strings.Fields(blob)
	results := make(map[int]int, len(input))
	for i := range input {
		h := &HexIn{Src: []byte(input[i])}
		_, foo, _ := h.SingleXOR()
		results[i] = foo
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
	_, _, final := h.SingleXOR()
	return string(final)

}

// RepeatingKeyXOR encrypts an input string with 'repeating key XOR'
// see: https://cryptopals.com/sets/1/challenges/5
func RepeatingKeyXOR(input string, key string) (result string) {
	inbytes := []byte(input)
	kbytes := []byte(key)

	res := make([]byte, len(inbytes))
	for idx, b := range inbytes {
		res[idx] = b ^ (kbytes[(idx)%len(kbytes)])
	}
	return hex.EncodeToString(res)
}

func hamming(x, y []byte) (n int, err error) {
	if len(x) != len(y) {
		return n, fmt.Errorf("expected equal length strings got len %d and %d", len(x), len(y))
	}

	for idx := range x {
		a := x[idx]
		b := y[idx]
		for i := 0; i < 8; i++ {
			if a&(1<<i) != b&(1<<i) {
				n++
			}
		}
	}
	return n, nil
}

// scoreSingleXOR returns the most likely value that was xored against a string
func scoreSingleXOR(input []byte) byte {
	result := make([]int, 256, 256)
	for i := 0; i <= 255; i++ {
		key := byte(i)
		res := singleXOR(input, key)
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
	return key
}

// BreakRepeatingXOR tries to break an encrypted string
func BreakRepeatingXOR(cipher []byte) (result string, err error) {
	minKeySize := 2
	maxKeySize := 40

	type distance struct {
		KeySize  int
		Distance float32
	}

	// find minimum distances
	keyDistances := make([]distance, maxKeySize-minKeySize+1, maxKeySize-minKeySize+1)
	for k := minKeySize; k < (maxKeySize + 1); k++ {
		var dist int
		var iters int
		for i := 0; i < len(cipher)/k-2; i++ {
			x := cipher[i*k : (i+1)*k]
			y := cipher[(i+1)*k : (i+2)*k]
			d, err := hamming(x, y)
			if err != nil {
				return result, err
			}
			dist += d
			iters++
		}
		keyDistances[k-minKeySize] = distance{
			KeySize:  k,
			Distance: float32(dist) / float32(k) / float32(iters),
		}
	}

	sort.Slice(keyDistances, func(i, j int) bool { return keyDistances[i].Distance < keyDistances[j].Distance })

	fmt.Printf("DEBUG keyDistances %#v", keyDistances)
	type cipherStruct struct {
		KeySize          int
		Blocks           [][]byte
		TransposedBlocks [][]byte
		Key              []byte
		Plaintext        string
	}
	// keysizes to test
	topKeySizes := 2
	ciphers := make([]cipherStruct, topKeySizes, topKeySizes)
	for i := range ciphers {
		keySize := keyDistances[i].KeySize
		blocks := make([][]byte, 0)
		for b := 0; b < (len(cipher) / keySize); b++ {
			blocks = append(blocks, cipher[b*keySize:(b+1)*keySize])
		}

		transposedBlocks := make([][]byte, keySize, keySize)
		for idx := range blocks {
			for i := range blocks[idx] {
				transposedBlocks[i] = append(transposedBlocks[i], blocks[idx][i])
			}
		}
		key := []byte{}
		for _, t := range transposedBlocks {
			x := scoreSingleXOR(t)
			key = append(key, x)
		}
		result = RepeatingKeyXOR(string(cipher), string(key))
		resultB, _ := hex.DecodeString(result)
		ciphers[i] = cipherStruct{
			KeySize:          keySize,
			Blocks:           blocks,
			Key:              key,
			TransposedBlocks: transposedBlocks,
			Plaintext:        string(resultB),
		}
		for _, c := range ciphers {
			fmt.Printf("DEBUG ====== plaintext: %s\n KeySize: %d\n", c.Plaintext, c.KeySize)
		}
	}

	return result, err
}
