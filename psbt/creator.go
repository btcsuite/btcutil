// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

// The Creator has only one function:
// takes a list of inputs and outputs and converts them to
// the simplest Psbt, i.e. one with no data appended to inputs or outputs,
// but only the raw unsigned transaction in the global section.

import (
	"github.com/btcsuite/btcd/wire"
)

// PsbtCreator holds a reference to a created Psbt struct.
type PsbtCreator struct {
	Cpsbt *Psbt
}

// createPsbt, on provision of an input and output 'skeleton' for
// the transaction, returns a PsbtCreator struct.
// Note that we require OutPoints and not TxIn structs, as we will
// only populate the txid:n information, *not* any scriptSig/witness
// information. Also note that the BIP does not discuss version and locktime;
// we allow them here as variables to be set on creation.
func (c *PsbtCreator) createPsbt(inputs []*wire.OutPoint,
	outputs []*wire.TxOut, Version int32, nLockTime int32) error {
	// Create the new struct; the input and output lists will be empty,
	// the unsignedTx object must be constructed and serialized,
	// and that serialization should be entered as the only entry for
	// the globalKVPairs list.
	unsignedTx := wire.NewMsgTx(Version)
	for _, in := range inputs {
		unsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: *in,
			Sequence:         wire.MaxTxInSequenceNum,
		})
	}
	for _, out := range outputs {
		unsignedTx.AddTxOut(out)
	}

	// The input and output lists are empty, but there is a list of those
	// two lists, and each one must be of length matching the unsigned
	// transaction; the unknown list can be nil.
	pInputs := make([]PsbtInput, len(unsignedTx.TxIn))
	pOutputs := make([]PsbtOutput, len(unsignedTx.TxOut))
	c.Cpsbt = &Psbt{
		UnsignedTx: unsignedTx,
		Inputs:     &pInputs,
		Outputs:    &pOutputs,
		Unknowns:   nil,
	}

	// This will populate the `Raw` element of the Psbt struct.
	if err := c.Cpsbt.Serialize(); err != nil {
		return err
	}
	// This new Psbt is "raw" and contains no key-value fields,
	// so sanity checking with c.Cpsbt.SanityCheck() is not required.
	return nil
}
