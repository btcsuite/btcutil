// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58_test

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcutil/base58"
)

// https://www.wolframalpha.com/input/?i=ceil%28+1+%2B+%28+160%2F8+%2B+4+%29+*+log%28256%29+%2F+log%2858%29+%29
const maxBtcAddrLen = 34

func BenchmarkBase58EncodeAddr(b *testing.B) {
	b.StopTimer()
	data := bytes.Repeat([]byte{0xff}, maxBtcAddrLen)
	b.SetBytes(int64(len(data)))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		base58.Encode(data)
	}
}

func BenchmarkBase58DecodeAddr(b *testing.B) {
	b.StopTimer()
	data := bytes.Repeat([]byte{0xff}, maxBtcAddrLen)
	encoded := base58.Encode(data)
	b.SetBytes(int64(len(encoded)))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		base58.Decode(encoded)
	}
}

func BenchmarkBase58Encode5k(b *testing.B) {
	b.StopTimer()
	data := bytes.Repeat([]byte{0xff}, 5000)
	b.SetBytes(int64(len(data)))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		base58.Encode(data)
	}
}

func BenchmarkBase58Decode5k(b *testing.B) {
	b.StopTimer()
	data := bytes.Repeat([]byte{0xff}, 5000)
	encoded := base58.Encode(data)
	b.SetBytes(int64(len(encoded)))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		base58.Decode(encoded)
	}
}
