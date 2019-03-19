package btcutil

import (
	"bytes"
	"encoding/binary"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type MerkleProof struct {
	Position uint64
	Hashes   []*chainhash.Hash
}

func (m MerkleProof) Bytes() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, m.Position)
	for _, p := range m.Hashes {
		buf.Write(p[:])
	}
	return buf.Bytes()
}

func NewMerkleProof(merkleTree []*chainhash.Hash, idx uint64) MerkleProof {
	treeHeight := calcTreeHeight(uint64((len(merkleTree) + 1) / 2))
	proof := MerkleProof{Position: idx, Hashes: make([]*chainhash.Hash, treeHeight)}
	for i := uint(0); i < treeHeight; i++ {
		proof.Hashes[i] = merkleTree[idx^1]
		idx = (idx >> 1) | (1 << treeHeight)
	}
	return proof
}

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

func calcTreeHeight(n uint64) (e uint) {
	for ; (1 << e) < n; e++ {
	}
	return
}
