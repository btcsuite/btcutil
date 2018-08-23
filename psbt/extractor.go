// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

// The Extractor requires provision of a single PSBT
// in which all necessary signatures are encoded, and
// uses it to construct a fully valid network serialized
// transaction.

import (
	"bytes"

	"github.com/btcsuite/btcd/wire"
)

// Extractor takes a finalized psbt and outputs a network serialization
func Extract(p *Psbt) ([]byte, error) {
	if !p.IsComplete() {
		return nil, ErrIncompletePSBT
	}
	var err error
	// We take the existing UnsignedTx field and append SignatureScript
	// and Witness as appropriate, then allow MsgTx to do the serialization
	// for us.
	newTx := p.UnsignedTx.Copy()
	for i, tin := range newTx.TxIn {
		pInput := &(*p.Inputs)[i]
		if pInput.FinalScriptSig != nil {
			tin.SignatureScript = pInput.FinalScriptSig
		}
		if pInput.FinalScriptWitness != nil {
			// to set the witness, need to re-deserialize the field
			// For each input, the witness is encoded as a stack
			// with one or more items. Therefore, we first read a
			// varint which encodes the number of stack items.
			r := bytes.NewReader(pInput.FinalScriptWitness)
			witCount, err := wire.ReadVarInt(r, 0)
			if err != nil {
				return nil, err
			}

			// Then for witCount number of stack items, each item
			// has a varint length prefix, followed by the witness
			// item itself.
			tin.Witness = make([][]byte, witCount)
			for j := uint64(0); j < witCount; j++ {
				// the 10000 size limit is as per BIP141 for witness script;
				// TODO this constant should be somewhere else in the lib,
				// perhaps btcd/wire/common.go ?
				wit, err := wire.ReadVarBytes(r, 0, 10000, "witness")
				if err != nil {
					return nil, err
				}
				tin.Witness[j] = wit
			}
		}
	}
	var networkSerializedTx bytes.Buffer
	err = newTx.Serialize(&networkSerializedTx)
	if err != nil {
		return nil, err
	}
	return networkSerializedTx.Bytes(), nil
}
