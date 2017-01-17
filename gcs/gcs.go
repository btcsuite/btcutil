// Copyright (c) 2016-2017 The btcsuite developers
// Copyright (c) 2016-2017 The Lightning Network Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gcs

import (
	"fmt"
	"io"
	"sort"

	"github.com/aead/siphash"
	"github.com/kkdai/bstream"
)

// Inspired by https://github.com/rasky/gcs

var (
	// ErrNTooBig signifies that the filter can't handle N items.
	ErrNTooBig = fmt.Errorf("N is too big to fit in uint32")

	// ErrPTooBig signifies that the filter can't handle `1/2**P`
	// collision probability.
	ErrPTooBig = fmt.Errorf("P is too big to fit in uint32")

	// ErrNoData signifies that an empty slice was passed.
	ErrNoData = fmt.Errorf("No data provided")
)

const (
	//KeySize is the size of the byte array required for key material for
	// the SipHash keyed hash function.
	KeySize = 16
)

// GCSFilter describes an immutable filter that can be built from
// a set of data elements, serialized, deserialized, and queried
// in a thread-safe manner. The serialized form is compressed as
// a Golomb Coded Set (GCS), but does not include N or P to allow
// the user to encode the metadata separately if necessary. The
// hash function used is SipHash, a keyed function; the key used
// in building the filter is required in order to match filter
// values and is not included in the serialized form.
type GCSFilter struct {
	n          uint32
	p          uint8
	modulusP   uint64
	modulusNP  uint64
	filterData []byte
}

// BuildGCSFilter builds a new GCS filter with the collision probability of
// `1/(2**P)`, key `key`, and including every `[]byte` in `data` as a member of
// the set.
func BuildGCSFilter(P uint8, key [KeySize]byte,
	data [][]byte) (*GCSFilter, error) {

	// Some initial parameter checks: make sure we have data from which to
	// build the filter, and make sure our parameters will fit the hash
	// function we're using.
	if len(data) == 0 {
		return nil, ErrNoData
	}
	if len(data) > ((1 << 32) - 1) {
		return nil, ErrNTooBig
	}
	if P > 32 {
		return nil, ErrPTooBig
	}

	// Create the filter object and insert metadata.
	f := GCSFilter{
		n: uint32(len(data)),
		p: P,
	}
	f.modulusP = uint64(1 << f.p)
	f.modulusNP = uint64(f.n) * f.modulusP

	// Build the filter.
	var values uint64Slice
	b := bstream.NewBStreamWriter(0)

	// Insert the hash (modulo N*P) of each data element into a slice and
	// sort the slice.
	for _, d := range data {
		v := siphash.Sum64(d, &key) % f.modulusNP
		values = append(values, v)
	}
	sort.Sort(values)

	// Write the sorted list of values into the filter bitstream,
	// compressing it using Golomb coding.
	var value, lastValue, remainder uint64
	for _, v := range values {
		// Calculate the difference between this value and the last,
		// modulo P.
		remainder = (v - lastValue) % f.modulusP
		// Calculate the difference between this value and the last,
		// divided by P.
		value = (v - lastValue - remainder) / f.modulusP
		lastValue = v
		// Write the P multiple into the bitstream in unary; the
		// average should be around 1 (2 bits - 0b10).
		for value > 0 {
			b.WriteBit(true)
			value--
		}
		b.WriteBit(false)
		// Write the remainder as a big-endian integer with enough bits
		// to represent the appropriate collision probability.
		b.WriteBits(remainder, int(f.p))
	}

	// Copy the bitstream into the filter object and return the object.
	f.filterData = b.Bytes()
	return &f, nil
}

// FromBytes deserializes a GCS filter from a known N, P, and serialized
// filter as returned by Bytes().
func FromBytes(N uint32, P uint8, d []byte) (*GCSFilter, error) {

	// Basic sanity check.
	if P > 32 {
		return nil, ErrPTooBig
	}

	// Create the filter object and insert metadata.
	f := &GCSFilter{
		n: N,
		p: P,
	}
	f.modulusP = uint64(1 << f.p)
	f.modulusNP = uint64(f.n) * f.modulusP

	// Copy the filter.
	f.filterData = make([]byte, len(d))
	copy(f.filterData, d)
	return f, nil
}

// Bytes returns the serialized format of the GCS filter, which does not
// include N or P (returned by separate methods) or the key used by SipHash.
func (f *GCSFilter) Bytes() []byte {
	filterData := make([]byte, len(f.filterData))
	copy(filterData, f.filterData)
	return filterData
}

// P returns the filter's collision probability as a negative power of 2 (that
// is, a collision probability of `1/2**20` is represented as 20).
func (f *GCSFilter) P() uint8 {
	return f.p
}

// N returns the size of the data set used to build the filter.
func (f *GCSFilter) N() uint32 {
	return f.n
}

// Match checks whether a []byte value is likely (within collision
// probability) to be a member of the set represented by the filter.
func (f *GCSFilter) Match(key [KeySize]byte, data []byte) (bool, error) {

	// Create a filter bitstream.
	filterData := f.Bytes()
	b := bstream.NewBStreamReader(filterData)

	// Hash our search term with the same parameters as the filter.
	term := siphash.Sum64(data, &key) % f.modulusNP

	// Go through the search filter and look for the desired value.
	var lastValue uint64
	for lastValue < term {
		// Read the difference between previous and new value
		// from bitstream.
		value, err := f.readFullUint64(b)
		if err != nil {
			if err == io.EOF {
				return false, nil
			}
			return false, err
		}
		// Add the previous value to it.
		value += lastValue
		if value == term {
			return true, nil
		}
		lastValue = value
	}
	return false, nil
}

// MatchAny returns checks whether any []byte value is likely (within
// collision probability) to be a member of the set represented by the
// filter faster than calling Match() for each value individually.
func (f *GCSFilter) MatchAny(key [KeySize]byte, data [][]byte) (bool, error) {

	// Basic sanity check.
	if len(data) == 0 {
		return false, ErrNoData
	}

	// Create a filter bitstream.
	filterData := f.Bytes()
	b := bstream.NewBStreamReader(filterData)

	// Create an uncompressed filter of the search values.
	var values uint64Slice
	for _, d := range data {
		v := siphash.Sum64(d, &key) % f.modulusNP
		values = append(values, v)
	}
	sort.Sort(values)

	// Zip down the filters, comparing values until we either run out of
	// values to compare in one of the filters or we reach a matching value.
	var lastValue1, lastValue2 uint64
	lastValue2 = values[0]
	i := 1
	for lastValue1 != lastValue2 {
		// Check which filter to advance to make sure we're comparing
		// the right values.
		switch {
		case lastValue1 > lastValue2:
			// Advance filter created from search terms or return
			// false if we're at the end because nothing matched.
			if i < len(values) {
				lastValue2 = values[i]
				i++
			} else {
				return false, nil
			}
		case lastValue2 > lastValue1:
			// Advance filter we're searching or return false if
			// we're at the end because nothing matched.
			value, err := f.readFullUint64(b)
			if err != nil {
				if err == io.EOF {
					return false, nil
				}
				return false, err
			}
			lastValue1 += value
		}
	}
	// If we've made it this far, an element matched between filters so
	// we return true.
	return true, nil
}

// readFullUint64 reads a value represented by the sum of a unary multiple
// of the filter's P modulus (`2**P`) and a big-endian P-bit remainder.
func (f *GCSFilter) readFullUint64(b *bstream.BStream) (uint64, error) {
	var v uint64

	// Count the 1s until we reach a 0.
	c, err := b.ReadBit()
	if err != nil {
		return 0, err
	}
	for c == true {
		v++
		c, err = b.ReadBit()
		if err != nil {
			return 0, err
		}
	}

	// Read P bits.
	remainder, err := b.ReadBits(int(f.p))
	if err != nil {
		return 0, err
	}

	// Add the multiple and the remainder.
	v = v*f.modulusP + remainder
	return v, nil
}
