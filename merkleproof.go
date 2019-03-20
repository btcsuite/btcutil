package btcutil

import (
	"bytes"
	"encoding/binary"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// MerkleProof contains the position of the hash whose inclusion you want to prove
// and then the chain of hashes you need to calculate the root hash
type MerkleProof struct {
	Position uint64
	Hashes   []*chainhash.Hash
}

// Bytes serializes the merkle proof into a byte slice
func (m MerkleProof) Bytes() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, m.Position)
	for _, p := range m.Hashes {
		buf.Write(p[:])
	}
	return buf.Bytes()
}

// NewMerkleProof generates a MerkleProof from a merkle tree and a index of the
// element you want to prove. The merkle tree is expected to be in the form that
// is returned by BuildMerkleTreeStore
func NewMerkleProof(merkleTree []*chainhash.Hash, idx uint64) MerkleProof {
	treeHeight := calcTreeHeight(uint64((len(merkleTree) + 1) / 2))
	proof := MerkleProof{Position: idx, Hashes: make([]*chainhash.Hash, treeHeight)}
	for i := uint(0); i < treeHeight; i++ {
		proof.Hashes[i] = merkleTree[idx^1]
		idx = (idx >> 1) | (1 << treeHeight)
	}
	return proof
}

// NewMerkleProofFromBytes will deserialize a merkle proof from a byte slice
func NewMerkleProofFromBytes(b []byte) MerkleProof {
	m := MerkleProof{}
	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.BigEndian, &m.Position)
	m.Hashes = make([]*chainhash.Hash, 0)
	for {
		if buf.Len() < 32 {
			break
		}
		hash, _ := chainhash.NewHash(buf.Next(32))
		m.Hashes = append(m.Hashes, hash)
	}
	return m
}

// Check will validate a merkle proof given the hash of the element to prove (hash)
// and the expected root hash (expectedRoot). Will return true when the merkle proof
// is valid, false otherwise.
func (proof MerkleProof) Check(hash, expectedRoot *chainhash.Hash) bool {
	treeHeight := uint(len(proof.Hashes))
	hashIdx := proof.Position
	for _, h := range proof.Hashes {
		var newHash chainhash.Hash
		if hashIdx&1 == 1 {
			newHash = chainhash.DoubleHashH(append(h[:], hash[:]...))
		} else {
			newHash = chainhash.DoubleHashH(append(hash[:], h[:]...))
		}
		hash = &newHash
		hashIdx = (hashIdx >> 1) | (1 << treeHeight)
	}

	return bytes.Equal(hash[:], expectedRoot[:])
}

// calcTreeHeight will return the height of a tree with n elements.
func calcTreeHeight(n uint64) (e uint) {
	for ; (1 << e) < n; e++ {
	}
	return
}
