package btcutil_test

import (
	"testing"

	"github.com/btcsuite/btcutil"
)

// TestSortTx tests SortTx function
func TestSortTx(t *testing.T) {
	//	 Use block 100,000 transaction 1.  Already sorted.
	testTx := Block100000.Transactions[1]
	sortedTx := btcutil.TxSort(testTx)

	testTxid := testTx.TxSha()
	sortedTxid := sortedTx.TxSha()
	if !testTxid.IsEqual(&sortedTxid) {
		t.Errorf("Sorted TxSha mismatch - got %v, want %v",
			testTxid.String(), sortedTxid.String())
	}
	if !btcutil.TxIsSorted(testTx) {
		t.Errorf("testTx %v is sorted but reported as unsorted",
			testTxid.String())
	}
}
