// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58_test

import (
	"testing"

	"github.com/btcutil/base58"
)

var checkEncodingStringTests = []struct {
	version byte
	in      string
	out     string
}{
	{20, "", "sM4QNrX"},
	{20, " ", "BpKiadBN"},
	{20, "-", "BsjvrwCt"},
	{20, "0", "Bh3pyu2X"},
	{20, "1", "BhUmeGwU"},
	{20, "-1", "mMfe7CakB"},
	{20, "11", "mPfBMTDVH"},
	{20, "abc", "hQ5VtDj7deq"},
	{20, "1234598760", "Zm4b3uQ8nzv87o64UNPP"},
	{20, "abcdefghijklmnopqrstuvwxyz", "KpRYDcKCuFxAXdW6SwxQPUe57L8tKmas7XyxnMvNHp"},
	{20, "00000000000000000000000000000000000000000000000000000000000000", "b5rNWXAJ2ypudZVxLJozuTb3MeghW9cax8mJ2RDjgaFi5nMBwxb9XAiFQXbt8qNoRVn7pF5x8ECAyXU3tRwVU3Xx8jK"},
}

func TestBase58Check(t *testing.T) {
	for x, test := range checkEncodingStringTests {
		// test encoding
		if res := base58.CheckEncode([]byte(test.in), test.version); res != test.out {
			t.Errorf("CheckEncode test #%d failed: got %s, want: %s", x, res, test.out)
		}

		// test decoding
		res, version, err := base58.CheckDecode(test.out)
		if err != nil {
			t.Errorf("CheckDecode test #%d failed with err: %v", x, err)
		} else if version != test.version {
			t.Errorf("CheckDecode test #%d failed: got version: %d want: %d", x, version, test.version)
		} else if string(res) != test.in {
			t.Errorf("CheckDecode test #%d failed: got: %s want: %s", x, res, test.in)
		}
	}

	// test the two decoding failure cases
	// case 1: checksum error
	_, _, err := base58.CheckDecode("3MNQE1Y")
	if err != base58.ErrChecksum {
		t.Error("Checkdecode test failed, expected ErrChecksum")
	}
	// case 2: invalid formats (string lengths below 5 mean the version byte and/or the checksum
	// bytes are missing).
	testString := ""
	for len := 0; len < 4; len++ {
		// make a string of length `len`
		_, _, err = base58.CheckDecode(testString)
		if err != base58.ErrInvalidFormat {
			t.Error("Checkdecode test failed, expected ErrInvalidFormat")
		}
	}

}
