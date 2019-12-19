// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

// signer encapsulates the role 'Signer'
// as specified in BIP174; it controls the insertion of signatures;
// the Sign() function will attempt to insert signatures using
// Updater.addPartialSignature, after first ensuring the Psbt is in the
// correct state.

import (
	"github.com/btcsuite/btcd/txscript"
)

// Sign allows the caller to sign a PSBT at a particular input; they
// must provide a signature and a pubkey, both as byte slices; they can also
// optionally provide both witnessScript and/or redeemScript, otherwise
// these arguments must be set as nil (and in that case, they must already
// be present in the PSBT if required for signing to succeed).
//
// Return value:
// 0 indicates that the partial signature was successfully attached.
// 1 indicates that this input is already finalized, so the provided
// signature was *not* attached
// -1 indicates that the provided signature data was not valid. In this
// case an error will also be returned.
//
// This serves as a wrapper around Updater.addPartialSignature;
// it ensures that the redeemScript and witnessScript are updated as needed
// (note that the Updater is allowed to add redeemScripts and witnessScripts
// independently, before signing), and ensures that the right form of utxo
// field (NonWitnessUtxo or WitnessUtxo) is included in the input so that
// signature insertion (and then finalization) can take place.
func (u *Updater) Sign(inIndex int, sig []byte, pubKey []byte,
	redeemScript []byte, witnessScript []byte) (int, error) {

	if isFinalized(u.Upsbt, inIndex) {
		return 1, nil
	}

	if witnessScript != nil {
		// Add the witnessScript to the PSBT in preparation.
		// If it already exists, it will be overwritten.
		err := u.AddInWitnessScript(witnessScript, inIndex)
		if err != nil {
			return -1, err
		}
	}

	if redeemScript != nil {
		// Add the redeemScript to the PSBT in preparation.
		// If it already exists, it will be overwritten.
		err := u.AddInRedeemScript(redeemScript, inIndex)
		if err != nil {
			return -1, err
		}
	}

	// At this point, the PSBT must have the requisite
	// witnessScript or redeemScript fields for signing to succeed.

	// case 1: if witnessScript is present, it must be of type witness;
	// if not, signature insertion will of course fail.
	if u.Upsbt.Inputs[inIndex].WitnessScript != nil {
		if u.Upsbt.Inputs[inIndex].WitnessUtxo == nil {
			err := nonWitnessToWitness(u.Upsbt, inIndex)
			if err != nil {
				return -1, err
			}
		}
		err := u.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return -1, err
		}
	} else if u.Upsbt.Inputs[inIndex].RedeemScript != nil {
		// case 2: no witness script, only redeem script; can be legacy
		// p2sh or p2sh-wrapped p2wkh
		// We only need to decide if the input is witness, and we don't
		// rely on the witnessutxo/nonwitnessutxo in the PSBT, instead
		// we check the redeemScript content:
		if txscript.IsWitnessProgram(redeemScript) {
			if u.Upsbt.Inputs[inIndex].WitnessUtxo == nil {
				err := nonWitnessToWitness(u.Upsbt, inIndex)
				if err != nil {
					return -1, err
				}
			}
		}
		// If it is not a valid witness program, we here assume
		// that the provided WitnessUtxo/NonWitnessUtxo field was correct.
		err := u.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return -1, err
		}
	} else {
		// case 3: Neither provided only works for native p2wkh, or
		// non-segwit non-p2sh. To check if it's segwit, check
		// the scriptPubKey of the output.
		if u.Upsbt.Inputs[inIndex].WitnessUtxo == nil {
			outIndex := u.Upsbt.UnsignedTx.TxIn[inIndex].
				PreviousOutPoint.Index
			script := u.Upsbt.Inputs[inIndex].NonWitnessUtxo.
				TxOut[outIndex].PkScript
			if txscript.IsWitnessProgram(script) {
				err := nonWitnessToWitness(u.Upsbt, inIndex)
				if err != nil {
					return -1, err
				}
			}
		}
		err := u.addPartialSignature(inIndex, sig, pubKey)
		if err != nil {
			return -1, err
		}
	}
	return 0, nil
}

// nonWitnessToWitness extracts the TxOut from the existing
// NonWitnessUtxo field in the given PSBT input and sets it as type
// witness by replacing the NonWitnessUtxo field with a WitnessUtxo
// field. See https://github.com/bitcoin/bitcoin/pull/14197
func nonWitnessToWitness(p *Psbt, inIndex int) error {
	outIndex := p.UnsignedTx.TxIn[inIndex].PreviousOutPoint.Index
	txout := p.Inputs[inIndex].NonWitnessUtxo.TxOut[outIndex]
	// Remove the non-witness first, else sanity check will not pass:
	p.Inputs[inIndex].NonWitnessUtxo = nil
	u := Updater{Upsbt: p}
	return u.AddInWitnessUtxo(txout, inIndex)
}
