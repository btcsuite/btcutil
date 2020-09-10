// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58

import (
	"math/big"
)

//go:generate go run genalphabet.go

var bigRadix = big.NewInt(58)
var bigRadix10 = big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58) // 58^10
var bigZero = big.NewInt(0)

// Decode decodes a modified base58 string to a byte slice.
func Decode(b string) []byte {
	answer := big.NewInt(0)
	j := big.NewInt(1)

	scratch := new(big.Int)
	for i := len(b) - 1; i >= 0; i-- {
		tmp := b58[b[i]]
		if tmp == 255 {
			return []byte("")
		}
		scratch.SetInt64(int64(tmp))
		scratch.Mul(j, scratch)
		answer.Add(answer, scratch)
		j.Mul(j, bigRadix)
	}

	tmpval := answer.Bytes()

	var numZeros int
	for numZeros = 0; numZeros < len(b); numZeros++ {
		if b[numZeros] != alphabetIdx0 {
			break
		}
	}
	flen := numZeros + len(tmpval)
	val := make([]byte, flen)
	copy(val[numZeros:], tmpval)

	return val
}

// Encode encodes a byte slice to a modified base58 string.
func Encode(b []byte) string {
	x := new(big.Int)
	x.SetBytes(b)

	answer := make([]byte, 0, len(b)*136/100)
	mod := new(big.Int)
	for x.Cmp(bigZero) > 0 {
		// Calculating with big.Int is slow for each iteration.
		//    x, mod = x / 58, x % 58
		//
		// Instead we can try to do as much calculations on int64.
		//    x, mod = x / 58^10, x % 58^10
		//
		// Which will give us mod, which is 10 digit base58 number.
		// We'll loop that 10 times to convert to the answer.

		x.DivMod(x, bigRadix10, mod)
		if x.Cmp(bigZero) == 0 {
			// When x = 0, we need to ensure we don't add any extra zeros.
			m := mod.Int64()
			for m > 0 {
				answer = append(answer, alphabet[m%58])
				m /= 58
			}
		} else {
			m := mod.Int64()
			for i := 0; i < 10; i++ {
				answer = append(answer, alphabet[m%58])
				m /= 58
			}
		}
	}

	// leading zero bytes
	for _, i := range b {
		if i != 0 {
			break
		}
		answer = append(answer, alphabetIdx0)
	}

	// reverse
	alen := len(answer)
	for i := 0; i < alen/2; i++ {
		answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
	}

	return string(answer)
}
