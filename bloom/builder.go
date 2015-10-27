// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bloom

import (
	"math"

	"github.com/btcsuite/btcd/wire"
)

// Builder represents a bloom filter being built by a client.  The intended use
// is for a wallet to add data to the filter (using Add, AddOutPoint, and
// AddShaHash) and create a filterload message to send to a bitcoin full node
// by calling MsgFilterLoad.
//
// Builder methods are not safe for concurrent access.
type Builder filter

// NewBuilder creates a new bloom filter instance, mainly to be used by SPV
// clients.  The tweak parameter is a random value added to the seed value.
// The false positive rate is the probability of a false positive where 1.0 is
// "match everything" and zero is unachievable.  Thus, providing any false
// positive rates less than 0 or greater than 1 will be adjusted to the valid
// range.
//
// For more information on what values to use for both elements and fprate,
// see https://en.wikipedia.org/wiki/Bloom_filter.
func NewBuilder(elements, tweak uint32, fprate float64, flags wire.BloomUpdateType) *Builder {
	// Massage the false positive rate to sane values.
	if fprate > 1.0 {
		fprate = 1.0
	}
	if fprate < 0 {
		fprate = 1e-9
	}

	// Calculate the size of the filter in bytes for the given number of
	// elements and false positive rate.
	//
	// Equivalent to m = -(n*ln(p) / ln(2)^2), where m is in bits.
	// Then clamp it to the maximum filter size and convert to bytes.
	dataLen := uint32(-1 * float64(elements) * math.Log(fprate) / ln2Squared)
	dataLen = minUint32(dataLen, wire.MaxFilterLoadFilterSize*8) / 8

	// Calculate the number of hash functions based on the size of the
	// filter calculated above and the number of elements.
	//
	// Equivalent to k = (m/n) * ln(2)
	// Then clamp it to the maximum allowed hash funcs.
	hashFuncs := uint32(float64(dataLen*8) / float64(elements) * math.Ln2)
	hashFuncs = minUint32(hashFuncs, wire.MaxFilterLoadHashFuncs)

	data := make([]byte, dataLen)
	msg := wire.NewMsgFilterLoad(data, hashFuncs, tweak, flags)

	return (*Builder)(msg)
}

// Add adds the passed byte slice to the bloom filter.
func (b *Builder) Add(data []byte) {
	(*filter)(b).add(data)
}

// AddOutPoint adds the passed transaction outpoint to the bloom filter.
func (b *Builder) AddOutPoint(outpoint *wire.OutPoint) {
	(*filter)(b).addOutPoint(outpoint)
}

// AddShaHash adds the passed wire.ShaHash to the Filter.
func (b *Builder) AddShaHash(sha *wire.ShaHash) {
	(*filter)(b).add(sha.Bytes())
}

// MsgFilterLoad returns the underlying wire.MsgFilterLoad for the bloom
// filter.
func (b *Builder) MsgFilterLoad() *wire.MsgFilterLoad {
	return (*wire.MsgFilterLoad)(b)
}
