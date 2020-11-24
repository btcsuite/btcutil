package btcutil

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// UBlock represents a utreexo block. It mimicks the behavior of Block in block.go
type UBlock struct {
	msgUBlock *wire.MsgUBlock

	serializedUBlock          []byte          // Serialized bytes for the block
	serializedUBlockNoWitness []byte          // Serialized bytes for block w/o witness data
	blockHash                 *chainhash.Hash // Cached block hash
	blockHeight               int32           // Height in the main block chain
	transactions              []*Tx           // Transactions
	txnsGenerated             bool            // ALL wrapped transactions generated
}

// MsgBlock returns the underlying wire.MsgUBlock for the Block.
func (ub *UBlock) MsgUBlock() *wire.MsgUBlock {
	return ub.msgUBlock
}

func (ub *UBlock) Bytes() ([]byte, error) {
	// Return the cached serialized bytes if it has already been generated.
	if len(ub.serializedUBlock) != 0 {
		return ub.serializedUBlock, nil
	}

	// Serialize the MsgBlock.
	w := bytes.NewBuffer(make([]byte, 0, ub.msgUBlock.SerializeSize()))
	err := ub.msgUBlock.Serialize(w)
	if err != nil {
		return nil, err
	}
	serializedUBlock := w.Bytes()

	// Cache the serialized bytes and return them.
	ub.serializedUBlock = serializedUBlock
	return serializedUBlock, nil
}

// BytesNoWitness returns the serialized bytes for the block with transactions
// encoded without any witness data.
func (ub *UBlock) BytesNoWitness() ([]byte, error) {
	// Return the cached serialized bytes if it has already been generated.
	if len(ub.serializedUBlockNoWitness) != 0 {
		return ub.serializedUBlockNoWitness, nil
	}

	// Serialize the MsgBlock.
	var w bytes.Buffer
	err := ub.msgUBlock.SerializeNoWitness(&w)
	if err != nil {
		return nil, err
	}
	serializedUBlock := w.Bytes()

	// Cache the serialized bytes and return them.
	ub.serializedUBlockNoWitness = serializedUBlock
	return serializedUBlock, nil
}

// Hash returns the block identifier hash for the Block.  This is equivalent to
// calling BlockHash on the underlying wire.MsgBlock, however it caches the
// result so subsequent calls are more efficient.
func (ub *UBlock) Hash() *chainhash.Hash {
	// Return the cached block hash if it has already been generated.
	if ub.blockHash != nil {
		return ub.blockHash
	}

	// Cache the block hash and return it.
	hash := ub.msgUBlock.BlockHash()
	ub.blockHash = &hash
	return &hash
}

// Transactions returns a slice of wrapped transactions (btcutil.Tx) for all
// transactions in the Block.  This is nearly equivalent to accessing the raw
// transactions (wire.MsgTx) in the underlying wire.MsgBlock, however it
// instead provides easy access to wrapped versions (btcutil.Tx) of them.
func (ub *UBlock) Transactions() []*Tx {
	// Return transactions if they have ALL already been generated.  This
	// flag is necessary because the wrapped transactions are lazily
	// generated in a sparse fashion.
	if ub.txnsGenerated {
		return ub.transactions
	}

	// Generate slice to hold all of the wrapped transactions if needed.
	if len(ub.transactions) == 0 {
		ub.transactions = make([]*Tx, len(ub.msgUBlock.MsgBlock.Transactions))
	}

	// Generate and cache the wrapped transactions for all that haven't
	// already ubeen done.
	for i, tx := range ub.transactions {
		if tx == nil {
			newTx := NewTx(ub.msgUBlock.MsgBlock.Transactions[i])
			newTx.SetIndex(i)
			ub.transactions[i] = newTx
		}
	}

	ub.txnsGenerated = true

	return ub.transactions
}

// Height returns the saved height of the block in the block chain.  This value
// will be BlockHeightUnknown if it hasn't already explicitly been set.
func (b *UBlock) Height() int32 {
	return b.blockHeight
}

// SetHeight sets the height of the block in the block chain.
func (b *UBlock) SetHeight(height int32) {
	b.blockHeight = height
}

// NewUBlock returns a new instance of a bitcoin block given an underlying
// wire.MsgUBlock.  See UBlock.
func NewBUlock(msgUBlock *wire.MsgUBlock) *UBlock {
	return &UBlock{
		msgUBlock:   msgUBlock,
		blockHeight: BlockHeightUnknown,
	}
}

// NewUBlockFromReader returns a new instance of a utreexo block given a
// Reader to deserialize the ublock.  See UBlock.
func NewUBlockFromReader(r io.Reader) (*UBlock, error) {
	// Deserialize the bytes into a MsgBlock.
	var msgUBlock wire.MsgUBlock
	err := msgUBlock.Deserialize(r)
	if err != nil {
		return nil, err
	}

	ub := UBlock{
		msgUBlock:   &msgUBlock,
		blockHeight: BlockHeightUnknown,
	}
	return &ub, nil
}

// NewUBlockFromBlockAndBytes returns a new instance of a utreexo block given
// an underlying wire.MsgUBlock and the serialized bytes for it.  See UBlock.
func NewUBlockFromBlockAndBytes(msgUBlock *wire.MsgUBlock, serializedUBlock []byte) *UBlock {
	return &UBlock{
		msgUBlock:        msgUBlock,
		serializedUBlock: serializedUBlock,
		blockHeight:      BlockHeightUnknown,
	}
}

// Block builds a block from the UBlock. For compatibility with some functions
// that want a block
func (ub *UBlock) Block() *Block {
	block := Block{
		msgBlock:      &ub.msgUBlock.MsgBlock,
		blockHash:     ub.blockHash,
		blockHeight:   ub.blockHeight,
		transactions:  ub.transactions,
		txnsGenerated: ub.txnsGenerated,
	}
	return &block
}

// ProofSanity checks the consistency of a UBlock
func (ub *UBlock) ProofSanity(inputSkipList []uint32, nl uint64, h uint8) error {
	// get the outpoints that need proof
	proveOPs := BlockToDelOPs(&ub.msgUBlock.MsgBlock, inputSkipList)

	// ensure that all outpoints are provided in the extradata
	if len(proveOPs) != len(ub.msgUBlock.UtreexoData.Stxos) {
		err := fmt.Errorf("height %d %d outpoints need proofs but only %d proven\n",
			ub.msgUBlock.UtreexoData.Height, len(proveOPs), len(ub.msgUBlock.UtreexoData.Stxos))
		return err
	}
	for i, _ := range ub.msgUBlock.UtreexoData.Stxos {
		if chainhash.Hash(proveOPs[i].Hash) != chainhash.Hash(ub.msgUBlock.UtreexoData.Stxos[i].TxHash) ||
			proveOPs[i].Index != ub.msgUBlock.UtreexoData.Stxos[i].Index {
			err := fmt.Errorf("block/utxoData mismatch %s v %s\n",
				proveOPs[i].String(), ub.msgUBlock.UtreexoData.Stxos[i].OPString())
			return err
		}
	}
	// derive leafHashes from leafData
	if !ub.msgUBlock.UtreexoData.ProofSanity(nl, h) {
		return fmt.Errorf("height %d LeafData / Proof mismatch", ub.msgUBlock.UtreexoData.Height)
	}

	return nil
}

// BlockToDelOPs gives all the UTXOs in a block that need proofs in order to be
// deleted.  All txinputs except for the coinbase input and utxos created
// within the same block (on the skiplist)
func BlockToDelOPs(
	blk *wire.MsgBlock, skiplist []uint32) (delOPs []wire.OutPoint) {

	var blockInIdx uint32
	for txinblock, tx := range blk.Transactions {
		if txinblock == 0 {
			blockInIdx++ // coinbase tx always has 1 input
			continue
		}

		// loop through inputs
		for _, txin := range tx.TxIn {
			// check if on skiplist.  If so, don't make leaf
			if len(skiplist) > 0 && skiplist[0] == blockInIdx {
				// fmt.Printf("skip %s\n", txin.PreviousOutPoint.String())
				skiplist = skiplist[1:]
				blockInIdx++
				continue
			}

			delOPs = append(delOPs, txin.PreviousOutPoint)
			blockInIdx++
		}
	}
	return
}
