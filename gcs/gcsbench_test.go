// Copyright (c) 2016-2017 The btcsuite developers
// Copyright (c) 2016-2017 The Lightning Network Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gcs_test

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcutil/gcs"
)

// BenchmarkGCSFilterBuild benchmarks building a filter.
func BenchmarkGCSFilterBuild(b *testing.B) {
	b.StopTimer()
	for i := 0; i < gcs.KeySize; i += 4 {
		binary.BigEndian.PutUint32(key[i:], rand.Uint32())
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		gcs.BuildGCSFilter(P, key, contents)
	}
}

// BenchmarkGCSFilterMatch benchmarks querying a filter for a single value.
func BenchmarkGCSFilterMatch(b *testing.B) {
	b.StopTimer()
	filter, err = gcs.BuildGCSFilter(P, key, contents)
	if err != nil {
		b.Errorf("Failed to build filter")
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		filter.Match(key, []byte("Nate"))
		filter.Match(key, []byte("Nates"))
	}
}

// BenchmarkGCSFilterMatchAny benchmarks querying a filter for a list of values.
func BenchmarkGCSFilterMatchAny(b *testing.B) {
	for i := 0; i < b.N; i++ {
		filter.MatchAny(key, contents2)
	}
}
