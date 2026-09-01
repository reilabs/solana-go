package zkprogram

import (
	"strings"
	"testing"

	"github.com/gagliardetto/solana-go/programs/zk-elgamal-proof/proofdata"
)

const NumProofTypes = 12

// newProofData returns a zero value of a proof data type.
func newProofData(t *testing.T, typ proofdata.ProofType) proofdata.ProofData {
	t.Helper()
	switch typ {
	case proofdata.ProofTypeZeroCiphertext:
		return new(proofdata.ZeroCiphertextProofData)
	case proofdata.ProofTypeCiphertextCiphertextEquality:
		return new(proofdata.CiphertextCiphertextEqualityProofData)
	case proofdata.ProofTypeCiphertextCommitmentEquality:
		return new(proofdata.CiphertextCommitmentEqualityProofData)
	case proofdata.ProofTypePubkeyValidity:
		return new(proofdata.PubkeyValidityProofData)
	case proofdata.ProofTypePercentageWithCap:
		return new(proofdata.PercentageWithCapProofData)
	case proofdata.ProofTypeBatchedRangeProofU64:
		return new(proofdata.BatchedRangeProofU64Data)
	case proofdata.ProofTypeBatchedRangeProofU128:
		return new(proofdata.BatchedRangeProofU128Data)
	case proofdata.ProofTypeBatchedRangeProofU256:
		return new(proofdata.BatchedRangeProofU256Data)
	case proofdata.ProofTypeGroupedCiphertext2HandlesValidity:
		return new(proofdata.GroupedCiphertext2HandlesValidityProofData)
	case proofdata.ProofTypeBatchedGroupedCiphertext2HandlesValidity:
		return new(proofdata.BatchedGroupedCiphertext2HandlesValidityProofData)
	case proofdata.ProofTypeGroupedCiphertext3HandlesValidity:
		return new(proofdata.GroupedCiphertext3HandlesValidityProofData)
	case proofdata.ProofTypeBatchedGroupedCiphertext3HandlesValidity:
		return new(proofdata.BatchedGroupedCiphertext3HandlesValidityProofData)
	}
	t.Fatalf("no proof data type for %s", typ)
	return nil
}

// fillProofData returns proof data of the given type whose every byte is
// distinct enough to catch a misordered or truncated serialization.
func fillProofData(t *testing.T, typ proofdata.ProofType) proofdata.ProofData {
	t.Helper()
	data := newProofData(t, typ)
	raw := make([]byte, len(data.Bytes()))
	for i := range raw {
		raw[i] = byte(i%251 + 1)
	}
	if err := data.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	return data
}

// errorContains fails the test unless err is non-nil and mentions substr.
func errorContains(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), substr) {
		t.Fatalf("err = %v, want it to mention %q", err, substr)
	}
}
