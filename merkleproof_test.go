package btcutil_test

import (
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcutil"
)

// TestMerkleProof will test the functionality of the MerkleProof.
func TestMerkleProof(t *testing.T) {
	// Get block 100.000
	b := btcutil.NewBlock(&Block100000)

	// Read the transactions from the block
	txs := b.Transactions()

	// Build a merkle tree
	merkleTree := blockchain.BuildMerkleTreeStore(txs, false)

	// Generate the merkle proof for transaction at index 1
	proof := btcutil.NewMerkleProof(merkleTree, 1)

	// Check if the proof validates based on the hash of the transaction at
	// index 1
	if !proof.Check(txs[1].Hash(), &(b.MsgBlock().Header.MerkleRoot)) {
		t.Error("Proof does not validate")
	}

	// Serialize and Deserialize the proof
	proof = btcutil.NewMerkleProofFromBytes(proof.Bytes())

	// Verify if the proof still verifies
	if !proof.Check(txs[1].Hash(), &(b.MsgBlock().Header.MerkleRoot)) {
		t.Error("De- and reserialized proof does not validate")
	}
}
