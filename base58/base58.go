// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58

import (
	"github.com/mr-tron/base58/base58"
)

var Encode = base58.Encode

func Decode(in string) (out []byte) {
	out, _ = base58.Decode(in)
	return
}
