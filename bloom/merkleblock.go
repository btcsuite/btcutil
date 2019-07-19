// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bloom

import (
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// merkleBlock is used to house intermediate information needed to generate a
// wire.MsgMerkleBlock according to a filter.
type merkleBlock struct {
	numTx       uint32
	allHashes   []*chainhash.Hash
	finalHashes []*chainhash.Hash
	matchedBits []byte
	bits        []byte
}

// calcTreeWidth calculates and returns the the number of nodes (width) or a
// merkle tree at the given depth-first height.
func calcTreeWidth(numTx, height uint32) uint32 {
	return (numTx + (1 << height) - 1) >> height
}

// calcHash returns the hash for a sub-tree given a depth-first height and
// node position.
func (m *merkleBlock) calcHash(height, pos uint32) *chainhash.Hash {
	if height == 0 {
		return m.allHashes[pos]
	}

	var right *chainhash.Hash
	left := m.calcHash(height-1, pos*2)
	if pos*2+1 < calcTreeWidth(m.numTx, height-1) {
		right = m.calcHash(height-1, pos*2+1)
	} else {
		right = left
	}
	return blockchain.HashMerkleBranches(left, right)
}

// traverseAndBuild builds a partial merkle tree using a recursive depth-first
// approach.  As it calculates the hashes, it also saves whether or not each
// node is a parent node and a list of final hashes to be included in the
// merkle block.
func (m *merkleBlock) traverseAndBuild(height, pos uint32) {
	// Determine whether this node is a parent of a matched node.
	var isParent byte
	for i := pos << height; i < (pos+1)<<height && i < m.numTx; i++ {
		isParent |= m.matchedBits[i]
	}
	m.bits = append(m.bits, isParent)

	// When the node is a leaf node or not a parent of a matched node,
	// append the hash to the list that will be part of the final merkle
	// block.
	if height == 0 || isParent == 0x00 {
		m.finalHashes = append(m.finalHashes, m.calcHash(height, pos))
		return
	}

	// At this point, the node is an internal node and it is the parent of
	// of an included leaf node.

	// Descend into the left child and process its sub-tree.
	m.traverseAndBuild(height-1, pos*2)

	// Descend into the right child and process its sub-tree if
	// there is one.
	if pos*2+1 < calcTreeWidth(m.numTx, height-1) {
		m.traverseAndBuild(height-1, pos*2+1)
	}
}

// newMerkleBlock returns a new *wire.MsgMerkleBlock and an array of the matched
// transaction index numbers based on the passed block, filter, and txid set.
func newMerkleBlock(block *btcutil.Block, filter *Filter,
	txids map[chainhash.Hash]struct{}) (*wire.MsgMerkleBlock, []uint32) {

	numTx := uint32(len(block.Transactions()))
	mBlock := merkleBlock{
		numTx:       numTx,
		allHashes:   make([]*chainhash.Hash, 0, numTx),
		matchedBits: make([]byte, 0, numTx),
	}

	// Find and keep track of any transactions that match the filter.
	var matchedIndices []uint32
	for txIndex, tx := range block.Transactions() {
		txHash := tx.Hash()
		matched := false
		if txids != nil {
			_, matched = txids[*txHash]
		}
		if matched || (filter != nil && filter.MatchTxAndUpdate(tx)) {
			mBlock.matchedBits = append(mBlock.matchedBits, 0x01)
			matchedIndices = append(matchedIndices, uint32(txIndex))
		} else {
			mBlock.matchedBits = append(mBlock.matchedBits, 0x00)
		}
		mBlock.allHashes = append(mBlock.allHashes, txHash)
	}

	// Calculate the number of merkle branches (height) in the tree.
	height := uint32(0)
	for calcTreeWidth(mBlock.numTx, height) > 1 {
		height++
	}

	// Build the depth-first partial merkle tree.
	mBlock.traverseAndBuild(height, 0)

	// Create and return the merkle block.
	msgMerkleBlock := wire.MsgMerkleBlock{
		Header:       block.MsgBlock().Header,
		Transactions: mBlock.numTx,
		Hashes:       make([]*chainhash.Hash, 0, len(mBlock.finalHashes)),
		Flags:        make([]byte, (len(mBlock.bits)+7)/8),
	}
	for _, hash := range mBlock.finalHashes {
		msgMerkleBlock.AddTxHash(hash)
	}
	for i := uint32(0); i < uint32(len(mBlock.bits)); i++ {
		msgMerkleBlock.Flags[i/8] |= mBlock.bits[i] << (i % 8)
	}
	return &msgMerkleBlock, matchedIndices
}

// NewMerkleBlock returns a new *wire.MsgMerkleBlock and an array of the matched
// transaction index numbers based on the passed block and filter.
func NewMerkleBlock(block *btcutil.Block, filter *Filter) (*wire.MsgMerkleBlock, []uint32) {
	return newMerkleBlock(block, filter, nil)
}

// NewMerkleBlockWithTxs returns a new *wire.MsgMerkleBlock and an array of the
// matched transaction index numbers based on the passed block and transactions.
func NewMerkleBlockWithTxs(block *btcutil.Block,
	txids map[chainhash.Hash]struct{}) (*wire.MsgMerkleBlock, []uint32) {
	return newMerkleBlock(block, nil, txids)
}

// merkleBlockVerifier is a helper struct that facilitates the verification of a
// merkle proof.
type merkleBlockVerifier struct {
	// numTx is the number of transactions in the block.
	numTx uint32

	// merkleRoot is the expected merkle root we should arrive at after
	// fully traversing the tree.
	merkleRoot chainhash.Hash

	// proof is the list of hashes we'll use to arrive at the merkle root of
	// the tree.
	proof []*chainhash.Hash

	// bits is the list of bits we'll use to arrive at the merkle root of
	// the tree. If the bit is set, then we'll need to continue traversing
	// the tree.
	bits []byte

	// numBits is the total number of bits. We'll use this after traversing
	// the tree to ensure we consumed all of them except for those that
	// serve as padding.
	numBits int

	// committedTxIDs is the list of transactions the merkle proof
	// committed to.
	committedTxIDs []*chainhash.Hash
}

// newMerkleBlockVerifier constructs a verifier for a given merkle proof.
func newMerkleBlockVerifier(merkleBlock *wire.MsgMerkleBlock) *merkleBlockVerifier {
	proof := make([]*chainhash.Hash, 0, len(merkleBlock.Hashes))
	for _, hash := range merkleBlock.Hashes {
		proof = append(proof, hash)
	}

	// When traversing through the tree, the bits will be interpreted in
	// little endian, so we'll extract them in that order.
	bits := make([]byte, 0, len(merkleBlock.Flags)*8)
	for _, flag := range merkleBlock.Flags {
		for i := byte(0); i < 8; i++ {
			var bit byte
			if flag&(1<<i) != 0 {
				bit = 0x01
			}
			bits = append(bits, bit)
		}
	}

	return &merkleBlockVerifier{
		numTx:      merkleBlock.Transactions,
		merkleRoot: merkleBlock.Header.MerkleRoot,
		proof:      proof,
		bits:       bits,
		numBits:    len(bits),
	}
}

// traverseAndExtract traverses the merkle proof to arrive at the expected
// merkle root. Any transactions that the proof commits to are added to the
// committedTxIDs slice within the verifier.
func (v *merkleBlockVerifier) traverseAndExtract(height, pos uint32) *chainhash.Hash {
	// If we've consumed all of our bits, but we've yet to finish traversing
	// the tree, there's nothing else we can do.
	if len(v.bits) == 0 {
		return &chainhash.Hash{}
	}

	// Otherwise, we'll pop off the next bit of the stack.
	nextBit := v.bits[0]
	v.bits = v.bits[1:]
	isParent := nextBit != 0

	// If the bit isn't set or we're at the leaf level of the tree, then
	// there's no need to traverse it as we won't find anything relevant.
	// Therefore, we'll use the next hash and continue to the next node.
	if !isParent || height == 0 {
		// If we've consumed all of our proof, but we've yet to finish
		// traversing the tree, there's nothing else we can do.
		if len(v.proof) == 0 {
			return &chainhash.Hash{}
		}

		// Otherwise, we'll obtain the next hash of the proof.
		nextHash := v.proof[0]
		v.proof = v.proof[1:]

		// If the hash is found to be a relevant leaf, we'll add it to
		// our list of committed transactions.
		if height == 0 && isParent {
			v.committedTxIDs = append(v.committedTxIDs, nextHash)
		}

		return nextHash
	}

	// Otherwise, the bit is set, so we'll need to traverse the tree one
	// level down. We'll determine if there is a right child based on the
	// number of transactions and the tree height. If there isn't one, we'll
	// hash the left child with itself.
	left := v.traverseAndExtract(height-1, pos*2)
	var right *chainhash.Hash
	if pos*2+1 < calcTreeWidth(v.numTx, height-1) {
		right = v.traverseAndExtract(height-1, pos*2+1)
	} else {
		right = left
	}

	return blockchain.HashMerkleBranches(left, right)
}

// verify verifies the merkle proof is valid. It is considered valid if the end
// result matches the expected merkle root of the block.
func (v *merkleBlockVerifier) verify() bool {
	// A merkle proof cannot commit to 0 transactions.
	if v.numTx == 0 {
		return false
	}

	// The number of hashes in a merkle proof cannot be greater than the
	// number of transactions in the block.
	if uint32(len(v.proof)) > v.numTx {
		return false
	}

	// A merkle proof should have at least one bit per hash.
	if len(v.bits) < len(v.proof) {
		return false
	}

	// Calculate the height of the merkle tree based on the number of
	// transactions within the block.
	height := uint32(0)
	for calcTreeWidth(v.numTx, height) > 1 {
		height++
	}

	// With the height obtained, we can begin to traverse the tree to arrive
	// at the merkle root.
	merkleRoot := v.traverseAndExtract(height, 0)

	// The traversal should've consumed all the bits (except for those that
	// serve as padding) and hashes within the proof, otherwise it is
	// invalid.
	if ((v.numBits-len(v.bits))+7)/8 != (v.numBits+7)/8 {
		return false
	}
	if len(v.proof) > 0 {
		return false
	}

	return merkleRoot.IsEqual(&v.merkleRoot)
}

// ExtractCommittedTxIDs extracts the txids that were committed in the merkle
// proof if it's found to be valid.
func ExtractCommittedTxIDs(merkleBlock *wire.MsgMerkleBlock) []*chainhash.Hash {
	verifier := newMerkleBlockVerifier(merkleBlock)
	valid := verifier.verify()
	if !valid {
		return nil
	}
	return verifier.committedTxIDs
}
