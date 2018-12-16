// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcutil/base58"
)

var stringTests = []struct {
	in  string
	out string
}{
	{"", ""},
	{" ", "Z"},
	{"-", "8"},
	{"0", "q"},
	{"1", "i"},
	{"-1", "hS7"},
	{"11", "hk3"},
	{"abc", "Z5U2"},
	{"1234598760", "smJifwo7XxpWqd"},
	{"abcdefghijklmnopqrstuvwxyz", "syx7sur5gY3WkgtjK9pCbJQUdhBZ55TrvpnC"},
	{"00000000000000000000000000000000000000000000000000000000000000", "s14pTHZeN9N69eYiAkvZq41tbHGvixSwMfgX7XvyEQP3XvQL7q4USpf5cA7eDTfckHmhE7HMpmTV6rvbLmkfy"},
}

var invalidStringTests = []struct {
	in  string
	out string
}{
	{"0", ""},
	{"O", ""},
	{"I", ""},
	{"l", ""},
	{"3mJr0", ""},
	{"O3yxU", ""},
	{"3sNI", ""},
	{"4kl8", ""},
	{"0OIl", ""},
	{"!@#$%^&*()-_=+~`", ""},
}

var hexTests = []struct {
	in  string
	out string
}{
	{"61", "pg"},
	{"626262", "2sgV"},
	{"636363", "2PNi"},
	{"73696d706c792061206c6f6e6720737472696e67", "pcEuFj68N1S8n9qHX1tmKpCCFLvp"},
	{"00eb15231dfceb60925886b67d065299925915aeb172c06647", "r4Srf52g9jJgTHDrVXjvLUN8ZuQsiJDN9L"},
	{"516b6fcd0f", "wB8LTmg"},
	{"bf4f89001e670274dd", "sSNosLWLoP8tU"},
	{"572e4794", "sNE7fm"},
	{"ecac89cad93923c02321", "NJDM3diCXwauyw"},
	{"10c8511e", "Rtnzm"},
	{"00000000000000000000", "rrrrrrrrrr"},
}

func TestBase58(t *testing.T) {
	// Encode tests
	for x, test := range stringTests {
		tmp := []byte(test.in)
		if res := base58.Encode(tmp); res != test.out {
			t.Errorf("Encode test #%d failed: got: %s want: %s",
				x, res, test.out)
			continue
		}
	}

	// Decode tests
	for x, test := range hexTests {
		b, err := hex.DecodeString(test.in)
		if err != nil {
			t.Errorf("hex.DecodeString failed failed #%d: got: %s", x, test.in)
			continue
		}
		if res := base58.Decode(test.out); !bytes.Equal(res, b) {
			t.Errorf("Decode test #%d failed: got: %q want: %q",
				x, res, test.in)
			continue
		}
	}

	// Decode with invalid input
	for x, test := range invalidStringTests {
		if res := base58.Decode(test.in); string(res) != test.out {
			t.Errorf("Decode invalidString test #%d failed: got: %q want: %q",
				x, res, test.out)
			continue
		}
	}
}
