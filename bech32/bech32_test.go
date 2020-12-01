// Copyright (c) 2017-2020 The btcsuite developers
// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bech32

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// TestBech32 tests whether decoding and re-encoding the valid BIP-173 test
// vectors works and if decoding invalid test vectors fails for the correct
// reason.
func TestBech32(t *testing.T) {
	tests := []struct {
		str           string
		expectedError error
	}{
		{"A12UEL5L", nil},
		{"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs", nil},
		{"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", nil},
		{"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j", nil},
		{"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", nil},
		{"split1checkupstagehandshakeupstreamerranterredcaperred2y9e2w", ErrInvalidChecksum{"2y9e3w", "2y9e2w"}},              // invalid checksum
		{"s lit1checkupstagehandshakeupstreamerranterredcaperredp8hs2p", ErrInvalidCharacter(' ')},                            // invalid character (space) in hrp
		{"spl\x7Ft1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", ErrInvalidCharacter(127)},                         // invalid character (DEL) in hrp
		{"split1cheo2y9e2w", ErrNonCharsetChar('o')},                                                                          // invalid character (o) in data part
		{"split1a2y9w", ErrInvalidSeparatorIndex(5)},                                                                          // too short data part
		{"1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", ErrInvalidSeparatorIndex(0)},                              // empty hrp
		{"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j", ErrInvalidLength(91)}, // too long

		// Additional test vectors used in bitcoin core
		{" 1nwldj5", ErrInvalidCharacter(' ')},
		{"\x7f" + "1axkwrx", ErrInvalidCharacter(0x7f)},
		{"\x801eym55h", ErrInvalidCharacter(0x80)},
		{"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", ErrInvalidLength(91)},
		{"pzry9x0s0muk", ErrInvalidSeparatorIndex(-1)},
		{"1pzry9x0s0muk", ErrInvalidSeparatorIndex(0)},
		{"x1b4n0q5v", ErrNonCharsetChar(98)},
		{"li1dgmt3", ErrInvalidSeparatorIndex(2)},
		{"de1lg7wt\xff", ErrInvalidCharacter(0xff)},
		{"A1G7SGD8", ErrInvalidChecksum{"2uel5l", "g7sgd8"}},
		{"10a06t8", ErrInvalidLength(7)},
		{"1qzzfhee", ErrInvalidSeparatorIndex(0)},
		{"a12UEL5L", ErrMixedCase{}},
		{"A12uEL5L", ErrMixedCase{}},
	}

	for i, test := range tests {
		str := test.str
		hrp, decoded, err := Decode(str)
		if test.expectedError != err {
			t.Errorf("%d: expected decoding error %v "+
				"instead got %v", i, test.expectedError, err)
			continue
		}

		if err != nil {
			// End test case here if a decoding error was expected.
			continue
		}

		// Check that it encodes to the same string
		encoded, err := Encode(hrp, decoded)
		if err != nil {
			t.Errorf("encoding failed: %v", err)
		}

		if encoded != strings.ToLower(str) {
			t.Errorf("expected data to encode to %v, but got %v",
				str, encoded)
		}

		// Flip a bit in the string an make sure it is caught.
		pos := strings.LastIndexAny(str, "1")
		flipped := str[:pos+1] + string((str[pos+1] ^ 1)) + str[pos+2:]
		_, _, err = Decode(flipped)
		if err == nil {
			t.Error("expected decoding to fail")
		}
	}
}

// TestCanDecodeUnlimtedBech32 tests whether decoding a large bech32 string works
// when using the DecodeNoLimit version
func TestCanDecodeUnlimtedBech32(t *testing.T) {
	input := "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5kx0yd"

	// Sanity check that an input of this length errors on regular Decode()
	_, _, err := Decode(input)
	if err == nil {
		t.Fatalf("Test vector not appropriate")
	}

	// Try and decode it.
	hrp, data, err := DecodeNoLimit(input)
	if err != nil {
		t.Fatalf("Expected decoding of large string to work. Got error: %v", err)
	}

	// Verify data for correctness.
	if hrp != "1" {
		t.Fatalf("Unexpected hrp: %v", hrp)
	}
	decodedHex := fmt.Sprintf("%x", data)
	expected := "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000"
	if decodedHex != expected {
		t.Fatalf("Unexpected decoded data: %s", decodedHex)
	}
}

// BenchmarkEncodeDecodeCycle performs a benchmark for a full encode/decode
// cycle of a bech32 string. It also  reports the allocation count, which we
// expect to be 2 for a fully optimized cycle.
func BenchmarkEncodeDecodeCycle(b *testing.B) {

	// Use a fixed, 49-byte raw data for testing.
	inputData, err := hex.DecodeString("cbe6365ddbcda9a9915422c3f091c13f8c7b2f263b8d34067bd12c274408473fa764871c9dd51b1bb34873b3473b633ed1")
	if err != nil {
		b.Fatalf("failed to initialize input data: %v", err)
	}

	// Convert this into a 79-byte, base 32 byte slice.
	base32Input, err := ConvertBits(inputData, 8, 5, true)
	if err != nil {
		b.Fatalf("failed to convert input to 32 bits-per-element: %v", err)
	}

	// Use a fixed hrp for the tests. This should generate an encoded bech32
	// string of size 90 (the maximum allowed by BIP-173).
	hrp := "bc"

	// Begin the benchmark. Given that we test one roundtrip per iteration
	// (that is, one Encode() and one Decode() operation), we expect at most
	// 2 allocations per reported test op.
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		str, err := Encode(hrp, base32Input)
		if err != nil {
			b.Fatalf("failed to encode input: %v", err)
		}

		_, _, err = Decode(str)
		if err != nil {
			b.Fatalf("failed to decode string: %v", err)
		}
	}
}

// TestConvertBits tests whether base conversion works using TestConvertBits().
func TestConvertBits(t *testing.T) {
	tests := []struct {
		input    string
		output   string
		fromBits uint8
		toBits   uint8
		pad      bool
	}{
		// Trivial empty conversions.
		{"", "", 8, 5, false},
		{"", "", 8, 5, true},
		{"", "", 5, 8, false},
		{"", "", 5, 8, true},

		// Conversions of 0 value with/without padding.
		{"00", "00", 8, 5, false},
		{"00", "0000", 8, 5, true},
		{"0000", "00", 5, 8, false},
		{"0000", "0000", 5, 8, true},

		// Testing when conversion ends exactly at the byte edge. This makes
		// both padded and unpadded versions the same.
		{"0000000000", "0000000000000000", 8, 5, false},
		{"0000000000", "0000000000000000", 8, 5, true},
		{"0000000000000000", "0000000000", 5, 8, false},
		{"0000000000000000", "0000000000", 5, 8, true},

		// Conversions of full byte sequences.
		{"ffffff", "1f1f1f1f1e", 8, 5, true},
		{"1f1f1f1f1e", "ffffff", 5, 8, false},
		{"1f1f1f1f1e", "ffffff00", 5, 8, true},

		// Sample random conversions.
		{"c9ca", "190705", 8, 5, false},
		{"c9ca", "19070500", 8, 5, true},
		{"19070500", "c9ca", 5, 8, false},
		{"19070500", "c9ca00", 5, 8, true},

		// Test cases tested on TestConvertBitsFailures with their corresponding
		// fixes.
		{"ff", "1f1c", 8, 5, true},
		{"1f1c10", "ff20", 5, 8, true},

		// Large conversions.
		{
			"cbe6365ddbcda9a9915422c3f091c13f8c7b2f263b8d34067bd12c274408473fa764871c9dd51b1bb34873b3473b633ed1",
			"190f13030c170e1b1916141a13040a14040b011f01040e01071e0607160b1906070e06130801131b1a0416020e110008081c1f1a0e19040703120e1d0a06181b160d0407070c1a07070d11131d1408",
			8, 5, true,
		},
		{
			"190f13030c170e1b1916141a13040a14040b011f01040e01071e0607160b1906070e06130801131b1a0416020e110008081c1f1a0e19040703120e1d0a06181b160d0407070c1a07070d11131d1408",
			"cbe6365ddbcda9a9915422c3f091c13f8c7b2f263b8d34067bd12c274408473fa764871c9dd51b1bb34873b3473b633ed100",
			5, 8, true,
		},
	}

	for i, tc := range tests {
		input, err := hex.DecodeString(tc.input)
		if err != nil {
			t.Fatalf("invalid test input data: %v", err)
		}

		expected, err := hex.DecodeString(tc.output)
		if err != nil {
			t.Fatalf("invalid test output data: %v", err)
		}

		actual, err := ConvertBits(input, tc.fromBits, tc.toBits, tc.pad)
		if err != nil {
			t.Fatalf("test case %d failed: %v", i, err)
		}

		if !bytes.Equal(actual, expected) {
			t.Fatalf("test case %d has wrong output; expected=%x actual=%x",
				i, expected, actual)
		}
	}
}

// TestConvertBitsFailures tests for the expected conversion failures of
// ConvertBits().
func TestConvertBitsFailures(t *testing.T) {
	tests := []struct {
		input    string
		fromBits uint8
		toBits   uint8
		pad      bool
		err      error
	}{
		// Not enough output bytes when not using padding.
		{"ff", 8, 5, false, ErrInvalidIncompleteGroup{}},
		{"1f1c10", 5, 8, false, ErrInvalidIncompleteGroup{}},

		// Unsupported bit conversions.
		{"", 0, 5, false, ErrInvalidBitGroups{}},
		{"", 10, 5, false, ErrInvalidBitGroups{}},
		{"", 5, 0, false, ErrInvalidBitGroups{}},
		{"", 5, 10, false, ErrInvalidBitGroups{}},
	}

	for i, tc := range tests {
		input, err := hex.DecodeString(tc.input)
		if err != nil {
			t.Fatalf("invalid test input data: %v", err)
		}

		_, err = ConvertBits(input, tc.fromBits, tc.toBits, tc.pad)
		if err != tc.err {
			t.Fatalf("test case %d failure: expected '%v' got '%v'", i,
				tc.err, err)
		}
	}

}

// BenchmarkConvertBitsDown benchmarks the speed and memory allocation behavior
// of ConvertBits when converting from a higher base into a lower base (e.g. 8
// => 5).
//
// Only a single allocation is expected, which is used for the output array.
func BenchmarkConvertBitsDown(b *testing.B) {
	// Use a fixed, 49-byte raw data for testing.
	inputData, err := hex.DecodeString("cbe6365ddbcda9a9915422c3f091c13f8c7b2f263b8d34067bd12c274408473fa764871c9dd51b1bb34873b3473b633ed1")
	if err != nil {
		b.Fatalf("failed to initialize input data: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ConvertBits(inputData, 8, 5, true)
		if err != nil {
			b.Fatalf("error converting bits: %v", err)
		}
	}
}

// BenchmarkConvertBitsDown benchmarks the speed and memory allocation behavior
// of ConvertBits when converting from a lower base into a higher base (e.g. 5
// => 8).
//
// Only a single allocation is expected, which is used for the output array.
func BenchmarkConvertBitsUp(b *testing.B) {
	// Use a fixed, 79-byte raw data for testing.
	inputData, err := hex.DecodeString("190f13030c170e1b1916141a13040a14040b011f01040e01071e0607160b1906070e06130801131b1a0416020e110008081c1f1a0e19040703120e1d0a06181b160d0407070c1a07070d11131d1408")
	if err != nil {
		b.Fatalf("failed to initialize input data: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ConvertBits(inputData, 8, 5, true)
		if err != nil {
			b.Fatalf("error converting bits: %v", err)
		}
	}
}
