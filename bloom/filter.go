// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bloom

import (
	"encoding/binary"
	"math"
	"sync"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// ln2Squared is simply the square of the natural log of 2.
const ln2Squared = math.Ln2 * math.Ln2

// minUint32 is a convenience function to return the minimum value of the two
// passed uint32 values.
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

type filter wire.MsgFilterLoad

// add adds the passed byte slice to the bloom filter.
func (f *filter) add(data []byte) {
	// Adding data to a bloom filter consists of setting all of the bit
	// offsets which result from hashing the data using each independent
	// hash function.  The shifts and masks below are a faster equivalent
	// of:
	//   arrayIndex := idx / 8    (idx >> 3)
	//   bitOffset := idx % 8     (idx & 7)
	///  filter[arrayIndex] |= 1<<bitOffset
	for i := uint32(0); i < f.HashFuncs; i++ {
		idx := f.hash(i, data)
		f.Filter[idx>>3] |= (1 << (7 & idx))
	}
}

// addOutPoint adds the passed transaction outpoint to the bloom filter.
func (f *filter) addOutPoint(outpoint *wire.OutPoint) {
	// Serialize
	var buf [wire.HashSize + 4]byte
	copy(buf[:], outpoint.Hash.Bytes())
	binary.LittleEndian.PutUint32(buf[wire.HashSize:], outpoint.Index)
	f.add(buf[:])
}

// hash returns the bit offset in the bloom filter which corresponds to the
// passed data for the given indepedent hash function number.
func (f *filter) hash(hashNum uint32, data []byte) uint32 {
	// bitcoind: 0xfba4c795 chosen as it guarantees a reasonable bit
	// difference between hashNum values.
	//
	// Note that << 3 is equivalent to multiplying by 8, but is faster.
	// Thus the returned hash is brought into range of the number of bits
	// the filter has and returned.
	mm := MurmurHash3(hashNum*0xfba4c795+f.Tweak, data)
	return mm % (uint32(len(f.Filter)) << 3)
}

// matches returns true if the bloom filter might contain the passed data and
// false if it definitely does not.
//
// This function MUST be called with the filter lock held.
func (f *filter) matches(data []byte) bool {
	// The bloom filter does not contain the data if any of the bit offsets
	// which result from hashing the data using each independent hash
	// function are not set.  The shifts and masks below are a faster
	// equivalent of:
	//   arrayIndex := idx / 8     (idx >> 3)
	//   bitOffset := idx % 8      (idx & 7)
	///  if filter[arrayIndex] & 1<<bitOffset == 0 { ... }
	for i := uint32(0); i < f.HashFuncs; i++ {
		idx := f.hash(i, data)
		if f.Filter[idx>>3]&(1<<(idx&7)) == 0 {
			return false
		}
	}
	return true
}

// Filter defines a bitcoin bloom filter that provides easy manipulation of raw
// filter data.
type Filter struct {
	mtx    sync.Mutex
	filter *filter
}

// LoadFilter creates a new Filter instance with the given underlying
// wire.MsgFilterLoad.
func LoadFilter(msg *wire.MsgFilterLoad) *Filter {
	return &Filter{
		filter: (*filter)(msg),
	}
}

// IsLoaded returns true if a filter is loaded, otherwise false.
func (f *Filter) IsLoaded() bool {
	f.mtx.Lock()
	loaded := f.filter != nil
	f.mtx.Unlock()
	return loaded
}

// Reload loads a new filter replacing any existing filter.
// This function is safe for concurrent access.
func (f *Filter) Reload(msg *wire.MsgFilterLoad) {
	f.mtx.Lock()
	f.filter = (*filter)(msg)
	f.mtx.Unlock()
}

// Unload unloads the bloom filter.
//
// This function is safe for concurrent access.
func (f *Filter) Unload() {
	f.mtx.Lock()
	f.filter = nil
	f.mtx.Unlock()
}

// Matches returns true if the bloom filter might contain the passed data and
// false if it definitely does not.
//
// This function is safe for concurrent access.
func (f *Filter) Matches(data []byte) bool {
	f.mtx.Lock()
	match := f.filter != nil && f.filter.matches(data)
	f.mtx.Unlock()
	return match
}

// matchesOutPoint returns true if the bloom filter might contain the passed
// outpoint and false if it definitely does not.
//
// This function MUST be called with the filter lock held.
func (f *Filter) matchesOutPoint(outpoint *wire.OutPoint) bool {
	// Serialize
	var buf [wire.HashSize + 4]byte
	copy(buf[:], outpoint.Hash.Bytes())
	binary.LittleEndian.PutUint32(buf[wire.HashSize:], outpoint.Index)

	return f.filter != nil && f.filter.matches(buf[:])
}

// MatchesOutPoint returns true if the bloom filter might contain the passed
// outpoint and false if it definitely does not.
//
// This function is safe for concurrent access.
func (f *Filter) MatchesOutPoint(outpoint *wire.OutPoint) bool {
	f.mtx.Lock()
	match := f.matchesOutPoint(outpoint)
	f.mtx.Unlock()
	return match
}

// maybeAddOutpoint potentially adds the passed outpoint to the bloom filter
// depending on the bloom update flags and the type of the passed public key
// script.
//
// This function MUST be called with the filter lock held.
func (f *Filter) maybeAddOutpoint(pkScript []byte, outHash *wire.ShaHash, outIdx uint32) {
	switch f.filter.Flags {
	case wire.BloomUpdateAll:
		outpoint := wire.NewOutPoint(outHash, outIdx)
		f.filter.addOutPoint(outpoint)
	case wire.BloomUpdateP2PubkeyOnly:
		class := txscript.GetScriptClass(pkScript)
		if class == txscript.PubKeyTy || class == txscript.MultiSigTy {
			outpoint := wire.NewOutPoint(outHash, outIdx)
			f.filter.addOutPoint(outpoint)
		}
	}
}

// MatchTxAndUpdate returns whether the bloom filter matches data within the
// passed transaction.  If the filter matches, the filter may be updated,
// depending on the fitler flags.
func (f *Filter) MatchTxAndUpdate(tx *btcutil.Tx) bool {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	// A nil filter does not match anything.
	if f.filter == nil {
		return false
	}

	// Check if the filter matches the hash of the transaction.
	// This is useful for finding transactions when they appear in a block.
	matched := f.filter.matches(tx.Sha().Bytes())

	// Check if the filter matches any data elements in the public key
	// scripts of any of the outputs.  When it does, add the outpoint that
	// matched so transactions which spend from the matched transaction are
	// also included in the filter.  This removes the burden of updating the
	// filter for this scenario from the client.  It is also more efficient
	// on the network since it avoids the need for another filteradd message
	// from the client and avoids some potential races that could otherwise
	// occur.
	for i, txOut := range tx.MsgTx().TxOut {
		pushedData, err := txscript.PushedData(txOut.PkScript)
		if err != nil {
			continue
		}

		for _, data := range pushedData {
			if !f.filter.matches(data) {
				continue
			}

			matched = true
			f.maybeAddOutpoint(txOut.PkScript, tx.Sha(), uint32(i))
			break
		}
	}

	// Nothing more to do if a match has already been made.
	if matched {
		return true
	}

	// At this point, the transaction and none of the data elements in the
	// public key scripts of its outputs matched.

	// Check if the filter matches any outpoints this transaction spends or
	// any any data elements in the signature scripts of any of the inputs.
	for _, txin := range tx.MsgTx().TxIn {
		if f.matchesOutPoint(&txin.PreviousOutPoint) {
			return true
		}

		pushedData, err := txscript.PushedData(txin.SignatureScript)
		if err != nil {
			continue
		}
		for _, data := range pushedData {
			if f.filter.matches(data) {
				return true
			}
		}
	}

	return false
}
