package btcutil_test

import (
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcutil"
)

func TestMerkleProof(t *testing.T) {
	b := btcutil.NewBlock(&Block100000)

	txs := b.Transactions()

	merkleTree := blockchain.BuildMerkleTreeStore(txs, false)

	proof := btcutil.NewMerkleProof(merkleTree, 1)

	if !proof.Check(txs[1].Hash(), &(b.MsgBlock().Header.MerkleRoot)) {
		t.Error("Proof does not validate")
	}

	// Test Serialize and Deserialize
	proof = btcutil.NewMerkleProofFromBytes(proof.Bytes())

	if !proof.Check(txs[1].Hash(), &(b.MsgBlock().Header.MerkleRoot)) {
		t.Error("De- and reserialized proof does not validate")
	}

}
