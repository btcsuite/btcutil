// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

import (
	"errors"
	"fmt"
)

// Combine accepts 2 or more PSBT packets and attempts
// to merge them into a single PSBT, or return an error.
func Combine(packets []*Packet) (*Packet, error) {
	if len(packets) < 2 {
		return nil, errors.New("nothing to combine")
	}

	// Use the first PSBT in the slice of packets as the base.
	// PSBTs can be uniquely identified by 0x00 global transaction typed key-value pair.
	// Check that the global transaction matches.
	base, err := NewUpdater(packets[0])
	if err != nil {
		return nil, err
	}

	for _, p := range packets {
		// The transaction must be the same.
		if base.Upsbt.UnsignedTx.TxHash() != p.UnsignedTx.TxHash() {
			return nil, fmt.Errorf("cannot combine different transactions : (got %s, want %s)", p.UnsignedTx.TxHash(), base.Upsbt.UnsignedTx.TxHash())
		}

		// Merge inputs.
		for idx, pIn := range p.Inputs {
			for _, partialSig := range pIn.PartialSigs {
				if err = base.addPartialSignature(idx, partialSig.Signature, partialSig.PubKey); err != nil && err != ErrDuplicateKey {
					return nil, fmt.Errorf("failed adding partial signature : %v", err)
				}
			}

			if pIn.WitnessUtxo != nil && base.Upsbt.Inputs[idx].WitnessUtxo == nil {
				if err := base.AddInWitnessUtxo(pIn.WitnessUtxo, idx); err != nil {
					return nil, fmt.Errorf("failed adding witness utxo : %v", err)
				}
			}

			if pIn.NonWitnessUtxo != nil && base.Upsbt.Inputs[idx].NonWitnessUtxo == nil {
				if err := base.AddInNonWitnessUtxo(pIn.NonWitnessUtxo, idx); err != nil {
					return nil, fmt.Errorf("failed adding witness utxo : %v", err)
				}
			}

			for _, bip32 := range pIn.Bip32Derivation {
				if err = base.AddInBip32Derivation(bip32.MasterKeyFingerprint, bip32.Bip32Path, bip32.PubKey, idx); err != nil && err != ErrDuplicateKey {
					return nil, fmt.Errorf("failed adding bip32 derivation : %v", err)
				}
			}

			if pIn.WitnessScript != nil && base.Upsbt.Inputs[idx].WitnessScript == nil {
				if err := base.AddInWitnessScript(pIn.WitnessScript, idx); err != nil {
					return nil, fmt.Errorf("failed adding witness script : %v", err)
				}
			}

			if pIn.RedeemScript != nil && base.Upsbt.Inputs[idx].RedeemScript == nil {
				if err := base.AddInRedeemScript(pIn.RedeemScript, idx); err != nil {
					return nil, fmt.Errorf("failed adding redem script : %v", err)
				}
			}

			if pIn.FinalScriptSig != nil && base.Upsbt.Inputs[idx].FinalScriptSig == nil {
				base.Upsbt.Inputs[idx].FinalScriptSig = pIn.FinalScriptSig
			}

			if pIn.FinalScriptWitness != nil && base.Upsbt.Inputs[idx].FinalScriptWitness == nil {
				base.Upsbt.Inputs[idx].FinalScriptWitness = pIn.FinalScriptWitness
			}

			base.Upsbt.Inputs[idx].Unknowns = append(base.Upsbt.Inputs[idx].Unknowns, pIn.Unknowns...)
		}

		// Merge outputs.
		for idx, pOut := range p.Outputs {
			for _, bip32 := range pOut.Bip32Derivation {
				if err = base.AddOutBip32Derivation(bip32.MasterKeyFingerprint, bip32.Bip32Path, bip32.PubKey, idx); err != nil && err != ErrDuplicateKey {
					return nil, fmt.Errorf("failed adding bip32 derivation : %v", err)
				}
			}

			if pOut.WitnessScript != nil && base.Upsbt.Outputs[idx].WitnessScript == nil {
				if err := base.AddOutWitnessScript(pOut.WitnessScript, idx); err != nil {
					return nil, fmt.Errorf("failed adding witness script : %v", err)
				}
			}

			if pOut.RedeemScript != nil && base.Upsbt.Outputs[idx].RedeemScript == nil {
				if err := base.AddOutRedeemScript(pOut.RedeemScript, idx); err != nil {
					return nil, fmt.Errorf("failed adding redem script : %v", err)
				}
			}
		}
	}

	return base.Upsbt, nil
}
