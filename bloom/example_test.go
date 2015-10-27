// Copyright (c) 2014-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bloom_test

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/bloom"
)

// This example demonstrates how to create a new bloom filter, add a transaction
// hash to it, and check if the filter matches the transaction.
func ExampleNewBuilder() {
	rand.Seed(time.Now().UnixNano())
	tweak := rand.Uint32()

	// Create a new bloom filter intended to hold 10 elements with a 0.01%
	// false positive rate and does not include any automatic update
	// functionality when transactions are matched.
	builder := bloom.NewBuilder(10, tweak, 0.0001, wire.BloomUpdateNone)

	// Create a transaction hash and add it to the filter.  This particular
	// transaction is the first transaction in block 310,000 of the main
	// bitcoin block chain.
	txHashStr := "fd611c56ca0d378cdcd16244b45c2ba9588da3adac367c4ef43e808b280b8a45"
	txHash, err := wire.NewShaHashFromStr(txHashStr)
	if err != nil {
		fmt.Println(err)
		return
	}
	builder.AddShaHash(txHash)

	// Create a message from the bloom filter builder and send to a full node.
	// The full node then creates a Filter, which can check whether the
	// transaction matches filter.
	msg := builder.MsgFilterLoad()
	filter := bloom.LoadFilter(msg)

	// Show that the filter matches.
	matches := filter.Matches(txHash.Bytes())
	fmt.Println("Filter Matches?:", matches)

	// Output:
	// Filter Matches?: true
}
