// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package psbt is an implementation of Partially Signed Bitcoin
// Transactions (PSBT). The format is defined in BIP 174:
// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
package psbt

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"io"
	"sort"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// psbtMagicLength is the length of the magic bytes used to signal the start of
// a serialized PSBT packet.
const psbtMagicLength = 5

var (
	// psbtMagic is the separator
	psbtMagic = [psbtMagicLength]byte{0x70,
		0x73, 0x62, 0x74, 0xff, // = "psbt" + 0xff sep
	}
)

// MaxPsbtValueLength is the size of the largest transaction serialization
// that could be passed in a NonWitnessUtxo field. This is definitely
//less than 4M.
const MaxPsbtValueLength = 4000000

var (

	// ErrInvalidPsbtFormat is a generic error for any situation in which a
	// provided Psbt serialization does not conform to the rules of BIP174.
	ErrInvalidPsbtFormat = errors.New("Invalid PSBT serialization format")

	// ErrDuplicateKey indicates that a passed Psbt serialization is invalid
	// due to having the same key repeated in the same key-value pair.
	ErrDuplicateKey = errors.New("Invalid Psbt due to duplicate key")

	// ErrInvalidKeydata indicates that a key-value pair in the PSBT
	// serialization contains data in the key which is not valid.
	ErrInvalidKeydata = errors.New("Invalid key data")

	// ErrInvalidMagicBytes indicates that a passed Psbt serialization is invalid
	// due to having incorrect magic bytes.
	ErrInvalidMagicBytes = errors.New("Invalid Psbt due to incorrect magic bytes")

	// ErrInvalidRawTxSigned indicates that the raw serialized transaction in the
	// global section of the passed Psbt serialization is invalid because it
	// contains scriptSigs/witnesses (i.e. is fully or partially signed), which
	// is not allowed by BIP174.
	ErrInvalidRawTxSigned = errors.New("Invalid Psbt, raw transaction must " +
		"be unsigned.")

	// ErrInvalidPrevOutNonWitnessTransaction indicates that the transaction
	// hash (i.e. SHA256^2) of the fully serialized previous transaction
	// provided in the NonWitnessUtxo key-value field doesn't match the prevout
	// hash in the UnsignedTx field in the PSBT itself.
	ErrInvalidPrevOutNonWitnessTransaction = errors.New("Prevout hash does " +
		"not match the provided non-witness utxo serialization")

	// ErrInvalidSignatureForInput indicates that the signature the user is
	// trying to append to the PSBT is invalid, either because it does
	// not correspond to the previous transaction hash, or redeem script,
	// or witness script.
	// NOTE this does not include ECDSA signature checking.
	ErrInvalidSignatureForInput = errors.New("Signature does not correspond " +
		"to this input")

	// ErrInputAlreadyFinalized indicates that the PSBT passed to a Finalizer
	// already contains the finalized scriptSig or witness.
	ErrInputAlreadyFinalized = errors.New("Cannot finalize PSBT, finalized " +
		"scriptSig or scriptWitnes already exists")

	// ErrIncompletePSBT indicates that the Extractor object
	// was unable to successfully extract the passed Psbt struct because
	// it is not complete
	ErrIncompletePSBT = errors.New("PSBT cannot be extracted as it is " +
		"incomplete")

	// ErrNotFinalizable indicates that the PSBT struct does not have
	// sufficient data (e.g. signatures) for finalization
	ErrNotFinalizable = errors.New("PSBT is not finalizable")

	// ErrInvalidSigHashFlags indicates that a signature added to the PSBT
	// uses Sighash flags that are not in accordance with the requirement
	// according to the entry in PsbtInSighashType, or otherwise not the
	// default value (SIGHASH_ALL)
	ErrInvalidSigHashFlags = errors.New("Invalid Sighash Flags")

	// ErrUnsupportedScriptType indicates that the redeem script or
	// scriptwitness given is not supported by this codebase, or is otherwise
	// not valid.
	ErrUnsupportedScriptType = errors.New("Unsupported script type")
)

// Unknown is a struct encapsulating a key-value pair for which the key type is
// unknown by this package; these fields are allowed in both the 'Global' and
// the 'Input' section of a PSBT.
type Unknown struct {
	Key   []byte
	Value []byte
}




}

// Psbt is a set of 1 + N + M key-value pair lists, 1 global,
// defining the unsigned transaction structure with N inputs and M outputs.
// These key-value pairs can contain scripts, signatures,
// key derivations and other transaction-defining data.
type Psbt struct {
	UnsignedTx *wire.MsgTx // Deserialization of unsigned tx
	Inputs     []PInput
	Outputs    []POutput
	Unknowns   []Unknown // Data of unknown type at global scope
}

// validateUnsignedTx returns true if the transaction is unsigned.
// Note that more basic sanity requirements,
// such as the presence of inputs and outputs, is implicitly
// checked in the call to MsgTx.Deserialize()
func validateUnsignedTX(tx *wire.MsgTx) bool {
	for _, tin := range tx.TxIn {
		if len(tin.SignatureScript) != 0 || len(tin.Witness) != 0 {
			return false
		}
	}
	return true
}

// NewPsbtFromUnsignedTx creates a new Psbt struct, without
// any signatures (i.e. only the global section is non-empty).
func NewPsbtFromUnsignedTx(tx *wire.MsgTx) (*Psbt, error) {

	if !validateUnsignedTX(tx) {
		return nil, ErrInvalidRawTxSigned
	}

	inSlice := make([]PInput, len(tx.TxIn))
	outSlice := make([]POutput, len(tx.TxOut))
	unknownSlice := make([]Unknown, 0)

	retPsbt := Psbt{
		UnsignedTx: tx,
		Inputs:     inSlice,
		Outputs:    outSlice,
		Unknowns:   unknownSlice,
	}

	return &retPsbt, nil
}

// NewPsbt returns a new instance of a Psbt struct created
// by reading from a byte slice. If the format is invalid, an error
// is returned. If the argument b64 is true, the passed byte slice
// is decoded from base64 encoding before processing.
// NOTE To create a Psbt from one's own data, rather than reading
// in a serialization from a counterparty, one should use a psbt.Creator.
func NewPsbt(psbtBytes []byte, b64 bool) (*Psbt, error) {
	var err error
	if b64 {
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(psbtBytes)))
		_, err = base64.StdEncoding.Decode(decoded, psbtBytes)
		if err != nil {
			return nil, err
		}
		psbtBytes = decoded
	}
	r := bytes.NewReader(psbtBytes)
	// The Psbt struct does not store the fixed magic bytes,
	// but they must be present or the serialization must
	// be explicitly rejected.
	var magic [5]byte
	if _, err = io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if magic != psbtMagic {
		return nil, ErrInvalidMagicBytes
	}

	// Next we parse the GLOBAL section.
	// There is currently only 1 known key type, UnsignedTx.
	// We insist this exists first; unknowns are allowed, but
	// only after.
	keyint, keydata, err := getKey(r)
	if err != nil {
		return nil, err
	}
	if uint8(keyint) != PsbtGlobalUnsignedTx || keydata != nil {
		return nil, ErrInvalidPsbtFormat
	}
	value, err := wire.ReadVarBytes(r, 0, MaxPsbtValueLength,
		"PSBT value")
	if err != nil {
		return nil, err
	}

	// Attempt to deserialize the unsigned transaction.
	msgTx := wire.NewMsgTx(2)
	err = msgTx.Deserialize(bytes.NewReader(value))
	if err != nil {
		return nil, err
	}
	if !validateUnsignedTX(msgTx) {
		return nil, ErrInvalidRawTxSigned
	}

	// parse any unknowns that may be present, break at separator
	unknownSlice := make([]Unknown, 0)
	for {
		keyint, keydata, err := getKey(r)
		if err != nil {
			return nil, ErrInvalidPsbtFormat
		}
		if keyint == -1 {
			break
		}
		value, err := wire.ReadVarBytes(r, 0, MaxPsbtValueLength,
			"PSBT value")
		if err != nil {
			return nil, err
		}
		keyintanddata := []byte{byte(keyint)}
		keyintanddata = append(keyintanddata, keydata...)
		newUnknown := Unknown{
			Key:   keyintanddata,
			Value: value,
		}
		unknownSlice = append(unknownSlice, newUnknown)
	}

	// Next we parse the INPUT section
	inSlice := make([]PInput, len(msgTx.TxIn))

	for i := range msgTx.TxIn {
		input := PInput{}
		err = input.deserialize(r)
		if err != nil {
			return nil, err
		}
		inSlice[i] = input
	}

	//Next we parse the OUTPUT section
	outSlice := make([]POutput, len(msgTx.TxOut))

	for i := range msgTx.TxOut {
		output := POutput{}
		err = output.deserialize(r)
		if err != nil {
			return nil, err
		}
		outSlice[i] = output
	}

	// Populate the new Psbt object
	newPsbt := Psbt{
		UnsignedTx: msgTx,
		Inputs:     inSlice,
		Outputs:    outSlice,
		Unknowns:   unknownSlice,
	}
	// Extended sanity checking is applied here
	// to make sure the externally-passed Psbt follows
	// all the rules.
	if err = newPsbt.SanityCheck(); err != nil {
		return nil, err
	}

	return &newPsbt, nil
}

// Serialize creates a binary serialization of the referenced
// Psbt struct with lexicographical ordering (by key) of the subsections
func (p *Psbt) Serialize() ([]byte, error) {

	serPsbt := []byte{}
	serPsbt = append(serPsbt, psbtMagic[:]...)

	// Create serialization of unsignedtx
	serializedTx := bytes.NewBuffer(make([]byte, 0,
		p.UnsignedTx.SerializeSize()))
	if err := p.UnsignedTx.Serialize(serializedTx); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err := serializeKVPairWithType(&buf, PsbtGlobalUnsignedTx,
		nil, serializedTx.Bytes())
	if err != nil {
		return nil, err
	}
	serPsbt = append(serPsbt, buf.Bytes()...)
	serPsbt = append(serPsbt, 0x00)

	for _, pInput := range p.Inputs {
		var buf bytes.Buffer
		err := pInput.serialize(&buf)
		if err != nil {
			return nil, err
		}
		serPsbt = append(serPsbt, buf.Bytes()...)
		serPsbt = append(serPsbt, 0x00)
	}

	for _, pOutput := range p.Outputs {
		var buf bytes.Buffer
		err := pOutput.serialize(&buf)
		if err != nil {
			return nil, err
		}
		serPsbt = append(serPsbt, buf.Bytes()...)
		serPsbt = append(serPsbt, 0x00)
	}

	return serPsbt, nil
}

// B64Encode returns the base64 encoding of the serialization of
// the current PSBT, or an error if the encoding fails.
func (p *Psbt) B64Encode() (string, error) {
	raw, err := p.Serialize()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// IsComplete returns true only if all of the inputs are
// finalized; this is particularly important in that it decides
// whether the final extraction to a network serialized signed
// transaction will be possible.
func (p *Psbt) IsComplete() bool {
	for i := 0; i < len(p.UnsignedTx.TxIn); i++ {
		if !isFinalized(p, i) {
			return false
		}
	}
	return true
}

// SanityCheck checks conditions on a PSBT to ensure that it obeys the
// rules of BIP174, and returns true if so, false if not.
func (p *Psbt) SanityCheck() error {

	if !validateUnsignedTX(p.UnsignedTx) {
		return ErrInvalidRawTxSigned
	}

	for _, tin := range p.Inputs {
		if !tin.IsSane() {
			return ErrInvalidPsbtFormat
		}
	}

	return nil
}
