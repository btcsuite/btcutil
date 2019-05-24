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

// Creator holds a reference to a created Psbt struct.
type Creator struct {
	Cpsbt *Psbt
}

// CreatePsbt , on provision of an input and output 'skeleton' for
// the transaction, returns a Creator struct.
// Note that we require OutPoints and not TxIn structs, as we will
// only populate the txid:n information, *not* any scriptSig/witness
// information. The values of nLockTime, nSequence (per input) and
// transaction version (must be 1 of 2) must be specified here. Note
// that the default nSequence value is wire.MaxTxInSequenceNum.
func (c *Creator) CreatePsbt(inputs []*wire.OutPoint,
	outputs []*wire.TxOut, Version int32, nLockTime uint32,
	nSequences []uint32) error {
	// Create the new struct; the input and output lists will be empty,
	// the unsignedTx object must be constructed and serialized,
	// and that serialization should be entered as the only entry for
	// the globalKVPairs list.

	// Check the version is a valid Bitcoin tx version; the nLockTime
	// can be any valid uint32. There must be one sequence number per
	// input.
	if !(Version == 1 || Version == 2) || len(nSequences) != len(inputs) {
		return ErrInvalidPsbtFormat
	}
	unsignedTx := wire.NewMsgTx(Version)
	unsignedTx.LockTime = nLockTime

	for i, in := range inputs {
		unsignedTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: *in,
			Sequence:         nSequences[i],
		})
	}
	for _, out := range outputs {
		unsignedTx.AddTxOut(out)
	}

	// The input and output lists are empty, but there is a list of those
	// two lists, and each one must be of length matching the unsigned
	// transaction; the unknown list can be nil.
	pInputs := make([]PInput, len(unsignedTx.TxIn))
	pOutputs := make([]POutput, len(unsignedTx.TxOut))
	c.Cpsbt = &Psbt{
		UnsignedTx: unsignedTx,
		Inputs:     pInputs,
		Outputs:    pOutputs,
		Unknowns:   nil,
	}

	// This new Psbt is "raw" and contains no key-value fields,
	// so sanity checking with c.Cpsbt.SanityCheck() is not required.
	return nil
}
