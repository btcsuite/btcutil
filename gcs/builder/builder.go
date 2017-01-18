// Copyright (c) 2017 The btcsuite developers
// Copyright (c) 2017 The Lightning Network Developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/gcs"
)

// DefaultP is the default collision probability (2^-20)
const DefaultP = 20

// GCSBuilder is a utility class that makes building GCS filters convenient.
type GCSBuilder struct {
	p    uint8
	key  [gcs.KeySize]byte
	data [][]byte
	err  error
}

// RandomKey is a utility function that returns a cryptographically random
// [gcs.KeySize]byte usable as a key for a GCS filter.
func RandomKey() ([gcs.KeySize]byte, error) {
	var key [gcs.KeySize]byte

	// Read a byte slice from rand.Reader.
	randKey := make([]byte, gcs.KeySize)
	_, err := rand.Read(randKey)

	// This shouldn't happen unless the user is on a system that doesn't
	// have a system CSPRNG. OK to panic in this case.
	if err != nil {
		return key, err
	}

	// Copy the byte slice to a [gcs.KeySize]byte array and return it.
	copy(key[:], randKey[:])
	return key, nil
}

// DeriveKey is a utility function that derives a key from a chainhash.Hash by
// truncating the bytes of the hash to the appopriate key size.
func DeriveKey(keyHash *chainhash.Hash) [gcs.KeySize]byte {
	var key [gcs.KeySize]byte
	copy(key[:], keyHash.CloneBytes()[:])
	return key
}

// OutPointToFilterEntry is a utility function that derives a filter entry from
// a wire.OutPoint in a standardized way for use with both building and querying
// filters.
func OutPointToFilterEntry(outpoint wire.OutPoint) []byte {
	// Size of the hash plus size of int32 index
	data := make([]byte, chainhash.HashSize+4)
	copy(data[:], outpoint.Hash.CloneBytes()[:])
	binary.LittleEndian.PutUint32(data[chainhash.HashSize:], outpoint.Index)
	return data
}

// Key retrieves the key with which the builder will build a filter. This is
// useful if the builder is created with a random initial key.
func (b *GCSBuilder) Key() ([gcs.KeySize]byte, error) {
	// Do nothing if the builder's errored out.
	if b.err != nil {
		return [gcs.KeySize]byte{}, b.err
	}

	return b.key, nil
}

// SetKey sets the key with which the builder will build a filter to the passed
// [gcs.KeySize]byte.
func (b *GCSBuilder) SetKey(key [gcs.KeySize]byte) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	copy(b.key[:], key[:])
	return b
}

// SetKeyFromHash sets the key with which the builder will build a filter to a
// key derived from the passed chainhash.Hash using DeriveKey().
func (b *GCSBuilder) SetKeyFromHash(keyHash *chainhash.Hash) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	return b.SetKey(DeriveKey(keyHash))
}

// SetP sets the filter's probability after calling Builder().
func (b *GCSBuilder) SetP(p uint8) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	// Basic sanity check.
	if p > 32 {
		b.err = gcs.ErrPTooBig
		return b
	}

	b.p = p
	return b
}

// Preallocate sets the estimated filter size after calling Builder() to reduce
// the probability of memory reallocations. If the builder has already had data
// added to it, SetN has no effect.
func (b *GCSBuilder) Preallocate(n uint32) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	if len(b.data) == 0 {
		b.data = make([][]byte, 0, n)
	}
	return b
}

// AddEntry adds a []byte to the list of entries to be included in the GCS
// filter when it's built.
func (b *GCSBuilder) AddEntry(data []byte) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	b.data = append(b.data, data)
	return b
}

// AddEntries adds all the []byte entries in a [][]byte to the list of entries
// to be included in the GCS filter when it's built.
func (b *GCSBuilder) AddEntries(data [][]byte) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	for _, entry := range data {
		b.AddEntry(entry)
	}
	return b
}

// AddOutPoint adds a wire.OutPoint to the list of entries to be included in the
// GCS filter when it's built.
func (b *GCSBuilder) AddOutPoint(outpoint wire.OutPoint) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	return b.AddEntry(OutPointToFilterEntry(outpoint))
}

// AddHash adds a chainhash.Hash to the list of entries to be included in the
// GCS filter when it's built.
func (b *GCSBuilder) AddHash(hash *chainhash.Hash) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	return b.AddEntry(hash.CloneBytes())
}

// AddScript adds all the data pushed in the script serialized as the passed
// []byte to the list of entries to be included in the GCS filter when it's
// built. T
func (b *GCSBuilder) AddScript(script []byte) *GCSBuilder {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return b
	}

	data, err := txscript.PushedData(script)
	if err != nil {
		b.err = err
		return b
	}
	return b.AddEntries(data)
}

// Build returns a function which builds a GCS filter with the given parameters
// and data.
func (b *GCSBuilder) Build() (*gcs.Filter, error) {
	// Do nothing if the builder's already errored out.
	if b.err != nil {
		return nil, b.err
	}

	return gcs.BuildGCSFilter(b.p, b.key, b.data)
}

// WithKeyPN creates a GCSBuilder with specified key and the passed
// probability and estimated filter size.
func WithKeyPN(key [gcs.KeySize]byte, p uint8, n uint32) *GCSBuilder {
	b := GCSBuilder{}
	return b.SetKey(key).SetP(p).Preallocate(n)
}

// WithKeyP creates a GCSBuilder with specified key and the passed
// probability. Estimated filter size is set to zero, which means more
// reallocations are done when building the filter.
func WithKeyP(key [gcs.KeySize]byte, p uint8) *GCSBuilder {
	return WithKeyPN(key, p, 0)
}

// WithKey creates a GCSBuilder with specified key. Probability is set to
// 20 (2^-20 collision probability). Estimated filter size is set to zero, which
// means more reallocations are done when building the filter.
func WithKey(key [gcs.KeySize]byte) *GCSBuilder {
	return WithKeyPN(key, DefaultP, 0)
}

// WithKeyHashPN creates a GCSBuilder with key derived from the specified
// chainhash.Hash and the passed probability and estimated filter size.
func WithKeyHashPN(keyHash *chainhash.Hash, p uint8, n uint32) *GCSBuilder {
	return WithKeyPN(DeriveKey(keyHash), p, n)
}

// WithKeyHashP creates a GCSBuilder with key derived from the specified
// chainhash.Hash and the passed probability. Estimated filter size is set to
// zero, which means more reallocations are done when building the filter.
func WithKeyHashP(keyHash *chainhash.Hash, p uint8) *GCSBuilder {
	return WithKeyHashPN(keyHash, p, 0)
}

// WithKeyHash creates a GCSBuilder with key derived from the specified
// chainhash.Hash. Probability is set to 20 (2^-20 collision probability).
// Estimated filter size is set to zero, which means more reallocations are
// done when building the filter.
func WithKeyHash(keyHash *chainhash.Hash) *GCSBuilder {
	return WithKeyHashPN(keyHash, DefaultP, 0)
}

// WithRandomKeyPN creates a GCSBuilder with a cryptographically random
// key and the passed probability and estimated filter size.
func WithRandomKeyPN(p uint8, n uint32) *GCSBuilder {
	key, err := RandomKey()
	if err != nil {
		b := GCSBuilder{err: err}
		return &b
	}
	return WithKeyPN(key, p, n)
}

// WithRandomKeyP creates a GCSBuilder with a cryptographically random
// key and the passed probability. Estimated filter size is set to zero, which
// means more reallocations are done when building the filter.
func WithRandomKeyP(p uint8) *GCSBuilder {
	return WithRandomKeyPN(p, 0)
}

// WithRandomKey creates a GCSBuilder with a cryptographically random
// key. Probability is set to 20 (2^-20 collision probability). Estimated
// filter size is set to zero, which means more reallocations are done when
// building the filter.
func WithRandomKey() *GCSBuilder {
	return WithRandomKeyPN(DefaultP, 0)
}
