// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package psbt

// The Finalizer requires provision of a single PSBT input
// in which all necessary signatures are encoded, and
// uses it to construct valid final scriptSig and scriptWitness
// fields.
// NOTE that p2sh (legacy) and p2wsh currently support only
// multisig and no other custom script.

import (
	"bytes"
	"errors"

	"io"
	"sort"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// A utility function due to non-exported witness serialization
// (writeTxWitness encodes the bitcoin protocol encoding for a transaction
// input's witness into w).
func writeTxWitness(w io.Writer, wit [][]byte) error {
	err := wire.WriteVarInt(w, 0, uint64(len(wit)))
	if err != nil {
		return err
	}
	for _, item := range wit {
		err = wire.WriteVarBytes(w, 0, item)
		if err != nil {
			return err
		}
	}
	return nil
}

// writePKHWitness writes a witness for a p2wkh spending input
func writePKHWitness(sig []byte, pub []byte) ([]byte, error) {
	var buf bytes.Buffer
	var witnessItems = [][]byte{sig, pub}
	err := writeTxWitness(&buf, witnessItems)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// checkIsMultisigScript is a utility function to check wheter
// a given redeemscript fits the standard multisig template used
// in all p2sh based multisig, given a set of pubkeys for redemption.
func checkIsMultiSigScript(pubKeys [][]byte, sigs [][]byte,
	script []byte) bool {

	// First insist that the script type is multisig
	if txscript.GetScriptClass(script) != txscript.MultiSigTy {
		return false
	}

	// Inspect the script to ensure that the number of sigs and
	// pubkeys is correct
	_, numSigs, err := txscript.CalcMultiSigStats(script)

	if err != nil {
		return false
	}

	if numSigs != len(pubKeys) || numSigs != len(sigs) {
		return false
	}

	return true
}

// extractKeyOrderFromScript is a utility function
// to extract an ordered list of signatures, given
// a serialized script (redeemscript or witness script),
// a list of pubkeys and the signatures corresponding to those
// pubkeys, so that the signatures will be embedded in the final
// scriptSig or scriptWitness in the correct order.
func extractKeyOrderFromScript(script []byte, expectedPubkeys [][]byte,
	sigs [][]byte) ([][]byte, error) {

	if !checkIsMultiSigScript(expectedPubkeys, sigs, script) {
		return nil, ErrUnsupportedScriptType
	}
	// Arrange the pubkeys and sigs into a slice of format:
	// [[pub,sig], [pub,sig],..]
	pubsSigs := [][][]byte{}
	for i, pub := range expectedPubkeys {
		tmp := [][]byte{pub, sigs[i]}
		pubsSigs = append(pubsSigs, tmp)
	}
	type kv struct {
		Key   int
		Value [][]byte
	}
	var positionMap []kv
	for _, p := range pubsSigs {
		pos := bytes.Index(script, p[0])
		if pos < 0 {
			return nil, errors.New("Script does not contain pubkeys")
		}
		positionMap = append(positionMap, kv{Key: pos, Value: p})
	}

	sort.Slice(positionMap, func(i, j int) bool {
		return positionMap[i].Key < positionMap[j].Key
	})
	// Build the return array of signatures
	sigsNew := [][]byte{}
	for _, x := range positionMap {
		sigsNew = append(sigsNew, x.Value[1])
	}
	return sigsNew, nil
}

// getMultisigScriptWitness creates a full Witness field for the transaction,
// given the public keys and signatures to be appended, after checking
// that the witnessScript is of type M of N multisig. This
// is used for both p2wsh and nested p2wsh multisig cases.
func getMultisigScriptWitness(witnessScript []byte, pubKeys [][]byte,
	sigs [][]byte) ([]byte, error) {

	orderedSigs, err := extractKeyOrderFromScript(witnessScript, pubKeys, sigs)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	var witnessItems = [][]byte{
		nil}
	for _, os := range orderedSigs {
		witnessItems = append(witnessItems, os)
	}
	witnessItems = append(witnessItems, witnessScript)
	err = writeTxWitness(&buf, witnessItems)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// checkSigHashFlags compares the sighash flag byte on a signature with the
// value expected according to any PsbtInSighashType field in this section
// of the PSBT, and returns true if they match, false otherwise.
// If no SighashType field exists, it is assumed to be SIGHASH_ALL.
// TODO sighash type not restricted to one byte in future?
func checkSigHashFlags(sig []byte, input *PInput) bool {
	expectedSighashType := txscript.SigHashAll
	if input.SighashType != 0 {
		expectedSighashType = input.SighashType
	}

	return expectedSighashType == txscript.SigHashType(sig[len(sig)-1])
}

// isFinalized considers this input finalized if it contains
// at least one of the FinalScriptSig or FinalScriptWitness
// are filled (which only occurs in a successful call to Finalize*)
func isFinalized(p *Psbt, inIndex int) bool {
	input := p.Inputs[inIndex]
	return input.FinalScriptSig != nil || input.FinalScriptWitness != nil
}

// isFinalizable checks whether the structure of the entry
// for the input of the Psbt p at index inIndex contains sufficient
// information to finalize this input. Deduce the template
// from the contents.
func isFinalizable(p *Psbt, inIndex int) bool {
	pInput := p.Inputs[inIndex]

	// Cannot be finalizable without any signatures
	if pInput.PartialSigs == nil {
		return false
	}

	if pInput.WitnessUtxo != nil {
		if txscript.IsWitnessProgram(pInput.WitnessUtxo.PkScript) {
			if txscript.IsPayToWitnessScriptHash(pInput.WitnessUtxo.PkScript) {
				if pInput.WitnessScript == nil || pInput.RedeemScript != nil {
					return false
				}
			} else {
				// if it's p2wkh there should be no redeemScript or witnessScript
				if pInput.WitnessScript != nil || pInput.RedeemScript != nil {
					return false
				}
			}
		} else if txscript.IsPayToScriptHash(pInput.WitnessUtxo.PkScript) {
			if pInput.RedeemScript == nil {
				return false
			}
			// if it's nested, and it's p2wsh, it must have WitnessScript;
			// if p2wkh, it must not.
			if txscript.IsPayToWitnessScriptHash(pInput.RedeemScript) {
				if pInput.WitnessScript == nil {
					return false
				}
			} else if txscript.IsPayToWitnessPubKeyHash(pInput.RedeemScript) {
				if pInput.WitnessScript != nil {
					return false
				}
			} else {
				// unrecognized type
				return false
			}
		}
	} else if pInput.NonWitnessUtxo != nil {
		if pInput.WitnessScript != nil {
			return false
		}
		outIndex := p.UnsignedTx.TxIn[inIndex].PreviousOutPoint.Index
		if txscript.IsPayToScriptHash(pInput.NonWitnessUtxo.TxOut[outIndex].PkScript) {
			if pInput.RedeemScript == nil {
				return false
			}
		} else {
			if pInput.RedeemScript != nil {
				return false
			}
		}
	} else {
		// one of witness and nonwitness utxo must be present
		return false
	}

	return true
}

// MaybeFinalize attempts to finalize the input at index inIndex
// in the PSBT p, returning true with no error if it succeeds, OR
// if the input has already been finalized.
func MaybeFinalize(p *Psbt, inIndex int) (bool, error) {
	if isFinalized(p, inIndex) {
		return true, nil
	}
	if !isFinalizable(p, inIndex) {
		return false, ErrNotFinalizable
	}
	err := Finalize(p, inIndex)
	if err != nil {
		return false, err
	}
	return true, nil
}

// MaybeFinalizeAll attempts to finalize all inputs of the Psbt that
// are not already finalized, and returns an error if it fails to do so.
func MaybeFinalizeAll(p *Psbt) error {
	for i := range p.UnsignedTx.TxIn {
		success, err := MaybeFinalize(p, i)
		if err != nil || !success {
			return err
		}
	}
	return nil
}

// Finalize assumes that the provided Psbt struct
// has all partial signatures and redeem scripts/witness scripts
// already prepared for the specified input, and so removes all temporary
// data and replaces them with completed scriptSig and witness
// fields, which are stored in key-types 07 and 08. The witness/
// non-witness utxo fields in the inputs (key-types 00 and 01) are
// left intact as they may be needed for validation (?).
// If there is any invalid or incomplete data, an error is
// returned.
func Finalize(p *Psbt, inIndex int) error {
	var err error
	pInput := p.Inputs[inIndex]
	if pInput.WitnessUtxo != nil {
		err = FinalizeWitness(p, inIndex)
		if err != nil {
			return err
		}
	} else if pInput.NonWitnessUtxo != nil {
		err = FinalizeNonWitness(p, inIndex)
		if err != nil {
			return err
		}
	} else {
		return ErrInvalidPsbtFormat
	}

	if err = p.SanityCheck(); err != nil {
		return err
	}
	return nil
}

// checkFinalScriptSigWitness checks whether a given input in the
// Psbt struct already has the fields 07 (FinalInScriptSig) or 08
// (FinalInWitness). If so, it returns true. It does not modify the
// Psbt.
func checkFinalScriptSigWitness(p *Psbt, inIndex int) bool {
	pInput := p.Inputs[inIndex]
	if pInput.FinalScriptSig != nil {
		return true
	}
	if pInput.FinalScriptWitness != nil {
		return true
	}
	return false
}

// FinalizeNonWitness attempts to create PsbtInFinalScriptSig field
// for input at index inIndex, and removes all other fields except
// for the utxo field, for an input of type non-witness, or returns
// an error.
func FinalizeNonWitness(p *Psbt, inIndex int) error {
	if checkFinalScriptSigWitness(p, inIndex) {
		return ErrInputAlreadyFinalized
	}
	// Construct a scriptSig given the pubkey, signature (keytype 02),
	// of which there might be multiple, and the redeem script
	// field (keytype 04) if present (note, it is not present
	// for p2pkh type inputs).
	var scriptSig []byte
	var err error
	pInput := p.Inputs[inIndex]
	containsRedeemScript := pInput.RedeemScript != nil
	var pubKeys [][]byte
	var sigs [][]byte
	for _, ps := range pInput.PartialSigs {
		pubKeys = append(pubKeys, ps.PubKey)
		sigOK := checkSigHashFlags(ps.Signature, &pInput)
		if !sigOK {
			return ErrInvalidSigHashFlags
		}
		sigs = append(sigs, ps.Signature)
	}

	if len(sigs) < 1 || len(pubKeys) < 1 {
		// We have failed to identify at least 1 (sig, pub) pair
		// in the PSBT, which indicates it was not ready to be finalized.
		return ErrNotFinalizable
	}

	if !containsRedeemScript {
		// p2pkh - insist on one sig/pub and build scriptSig
		if len(sigs) != 1 || len(pubKeys) != 1 {
			return ErrNotFinalizable
		}
		builder := txscript.NewScriptBuilder()
		builder.AddData(sigs[0]).AddData(pubKeys[0])
		scriptSig, err = builder.Script()
		if err != nil {
			return err
		}
	} else {
		// This is assumed p2sh multisig
		// Given redeemScript and pubKeys we can decide in what order
		// signatures must be appended.
		orderedSigs, err := extractKeyOrderFromScript(pInput.RedeemScript,
			pubKeys, sigs)
		if err != nil {
			return err
		}
		// TODO the below is specific to the multisig case.
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_FALSE)
		for _, os := range orderedSigs {
			builder.AddData(os)
		}
		builder.AddData(pInput.RedeemScript)
		scriptSig, err = builder.Script()
		if err != nil {
			return err
		}
	}
	// At this point, a scriptSig has been constructed.
	// Remove all fields other than non-witness utxo (00)
	// and finaliscriptsig (07)
	newInput := NewPsbtInput(pInput.NonWitnessUtxo, nil)
	newInput.FinalScriptSig = scriptSig
	// overwrite the entry in the input list at the correct index
	// Note that this removes all the other entries in the list for
	// this input index.
	p.Inputs[inIndex] = *newInput
	return nil
}

// FinalizeWitness attempts to create PsbtInFinalScriptSig field
// and PsbtInFinalScriptWitness field for input at index inIndex,
// and removes all other fields except for the utxo field, for an
// input of type witness, or returns an error.
func FinalizeWitness(p *Psbt, inIndex int) error {
	if checkFinalScriptSigWitness(p, inIndex) {
		return ErrInputAlreadyFinalized
	}
	// Construct a scriptSig given the redeem script
	// field (keytype 04) if present (if not present it's empty
	// as per bip141).
	// Fill this in in field FinalScriptSig (keytype 07).
	// And/or construct a FinalScriptWitness field (keytype 08),
	// assuming either p2wkh or p2wsh multisig.
	var scriptSig []byte
	var witness []byte
	var err error
	pInput := p.Inputs[inIndex]
	containsRedeemScript := pInput.RedeemScript != nil
	cointainsWitnessScript := pInput.WitnessScript != nil
	var pubKeys [][]byte
	var sigs [][]byte
	for _, ps := range pInput.PartialSigs {
		pubKeys = append(pubKeys, ps.PubKey)
		sigOK := checkSigHashFlags(ps.Signature, &pInput)
		if !sigOK {
			return ErrInvalidSigHashFlags
		}
		sigs = append(sigs, ps.Signature)
	}
	if len(sigs) == 0 || len(pubKeys) == 0 {
		return ErrNotFinalizable
	}
	if !containsRedeemScript {
		if len(pubKeys) == 1 && len(sigs) == 1 && !cointainsWitnessScript {
			// p2wkh case
			witness, err = writePKHWitness(sigs[0], pubKeys[0])
			if err != nil {
				return err
			}
		} else {
			// Otherwise, we must have a witnessScript field,
			// to fulfil the requirements of p2wsh
			// NOTE (we tacitly assume multisig)
			if !cointainsWitnessScript {
				return ErrNotFinalizable
			}
			witness, err = getMultisigScriptWitness(pInput.WitnessScript,
				pubKeys, sigs)
			if err != nil {
				return err
			}
		}

	} else {
		// This is currently assumed p2wsh, multisig, nested in p2sh,
		// or p2wkh, nested in p2sh.
		// The scriptSig is taken from the redeemscript field, but embedded
		// in a push
		builder := txscript.NewScriptBuilder()
		builder.AddData(pInput.RedeemScript)
		scriptSig, err = builder.Script()
		if err != nil {
			return err
		}
		if !cointainsWitnessScript {
			// Assumed p2sh-p2wkh
			// Here the witness is just (sig, pub) as for p2pkh case
			if len(sigs) != 1 || len(pubKeys) != 1 {
				return ErrNotFinalizable
			}
			witness, err = writePKHWitness(sigs[0], pubKeys[0])
			if err != nil {
				return err
			}
		} else {
			// Assumed p2sh-p2wsh with multisig.
			// To build the witness, we do exactly as for the native p2wsh case.
			witness, err = getMultisigScriptWitness(pInput.WitnessScript,
				pubKeys, sigs)
			if err != nil {
				return err
			}
		}
	}
	// At this point, a witness has been constructed,
	// and a scriptSig (if nested; else it's []).
	// Remove all fields other than witness utxo (01)
	// and finalscriptsig (07), finalscriptwitness (08)
	newInput := NewPsbtInput(nil, pInput.WitnessUtxo)
	if len(scriptSig) > 0 {
		newInput.FinalScriptSig = scriptSig
	}
	newInput.FinalScriptWitness = witness
	// overwrite the entry in the input list at the correct index
	p.Inputs[inIndex] = *newInput
	return nil
}
