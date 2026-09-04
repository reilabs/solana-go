package token2022

import (
	"reflect"
	"strings"
	"testing"

	ag_binary "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/zk-elgamal-proof/proofdata"
	"github.com/gagliardetto/solana-go/programs/zk-elgamal-proof/zkprogram"
)

var (
	ctTokenAccount       = ctAddr(10)
	ctMint               = ctAddr(11)
	ctDestination        = ctAddr(12)
	ctAuthority          = ctAddr(13)
	ctMultisig           = []solana.PublicKey{ctAddr(14), ctAddr(15)}
	ctContextSingle      = ctAddr(20)
	ctContextEquality    = ctAddr(21)
	ctContextValidity    = ctAddr(22)
	ctContextFeeSigma    = ctAddr(23)
	ctContextFeeValidity = ctAddr(24)
	ctContextRange       = ctAddr(25)
	ctRegistry           = ctAddr(30)
	ctPayer              = ctAddr(31)
)

const (
	ctAmount            = uint64(0x1122334455667788)
	ctDecimals          = uint8(9)
	ctMaxPendingCounter = uint64(65536)
)

func TestConfidentialTransferDataRoundTrip(t *testing.T) {
	t.Parallel()
	instructions := []interface {
		MarshalBinary() ([]byte, error)
	}{
		ConfidentialTransferInitializeMintData{Authority: ctAddr(1), AutoApproveNewAccounts: true, AuditorElGamalPubkey: [32]byte{2, 3}},
		ConfidentialTransferUpdateMintData{AutoApproveNewAccounts: true, AuditorElGamalPubkey: [32]byte{4}},
		ConfidentialTransferConfigureAccountData{DecryptableZeroBalance: [36]byte{5}, MaximumPendingBalanceCreditCounter: 77, ProofInstructionOffset: -3},
		ConfidentialTransferEmptyAccountData{ProofInstructionOffset: 1},
		ConfidentialTransferDepositData{Amount: 123456789, Decimals: 6},
		ConfidentialTransferWithdrawData{Amount: 42, Decimals: 9, NewDecryptableAvailableBalance: [36]byte{6}, EqualityProofInstructionOffset: 1, RangeProofInstructionOffset: 2},
		ConfidentialTransferTransferData{NewSourceDecryptableAvailableBalance: [36]byte{7}, TransferAmountAuditorCiphertextLo: [64]byte{8}, TransferAmountAuditorCiphertextHi: [64]byte{9}, EqualityProofInstructionOffset: 1, CiphertextValidityProofInstructionOffset: 2, RangeProofInstructionOffset: 3},
		ConfidentialTransferApplyPendingBalanceData{ExpectedPendingBalanceCreditCounter: 11, NewDecryptableAvailableBalance: [36]byte{10}},
		ConfidentialTransferTransferWithFeeData{NewSourceDecryptableAvailableBalance: [36]byte{11}, TransferAmountAuditorCiphertextLo: [64]byte{12}, TransferAmountAuditorCiphertextHi: [64]byte{13}, EqualityProofInstructionOffset: 1, TransferAmountCiphertextValidityProofInstructionOffset: 2, FeeSigmaProofInstructionOffset: 3, FeeCiphertextValidityProofInstructionOffset: 4, RangeProofInstructionOffset: 5},
	}
	for _, original := range instructions {
		name := reflect.TypeOf(original).Name()
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, err := original.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			decoded := reflect.New(reflect.TypeOf(original))
			unmarshaler := decoded.Interface().(interface{ UnmarshalBinary([]byte) error })
			if err := unmarshaler.UnmarshalBinary(raw); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			if !reflect.DeepEqual(decoded.Elem().Interface(), original) {
				t.Errorf("round trip mismatch:\ngot  %+v\nwant %+v", decoded.Elem().Interface(), original)
			}
			if err := unmarshaler.UnmarshalBinary(raw[:len(raw)-1]); err == nil {
				t.Error("UnmarshalBinary accepted truncated data")
			}
			if err := unmarshaler.UnmarshalBinary(append(raw, 0)); err == nil {
				t.Error("UnmarshalBinary accepted oversized data")
			}
		})
	}
}

func TestConfidentialTransferTypedDecode(t *testing.T) {
	t.Parallel()
	inst := NewConfidentialTransferDepositInstruction(
		ctTokenAccount, ctMint, ctAmount, ctDecimals, ctAuthority, nil)
	built, err := inst.ValidateAndBuild()
	if err != nil {
		t.Fatalf("ValidateAndBuild: %v", err)
	}
	data, err := built.Data()
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	decoded, err := DecodeInstruction(built.Accounts(), data)
	if err != nil {
		t.Fatalf("DecodeInstruction: %v", err)
	}
	wrapper, ok := decoded.Impl.(*ConfidentialTransferExtension)
	if !ok {
		t.Fatalf("decoded to %T, want *ConfidentialTransferExtension", decoded.Impl)
	}
	deposit, ok := wrapper.Impl.(*ConfidentialTransferDepositData)
	if !ok {
		t.Fatalf("sub-instruction decoded to %T, want *ConfidentialTransferDepositData", wrapper.Impl)
	}
	if deposit.Amount != ctAmount || deposit.Decimals != ctDecimals {
		t.Errorf("decoded data = %+v, want amount %d decimals %d", deposit, ctAmount, ctDecimals)
	}
}

func TestConfidentialTransferDecodeRejectsMalformed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"wrong size", []byte{ConfidentialTransfer_Withdraw, 1, 2, 3}},
		{"data on dataless", []byte{ConfidentialTransfer_ApproveAccount, 1}},
		{"unknown sub-instruction", []byte{200}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var inst ConfidentialTransferExtension
			if err := inst.UnmarshalWithDecoder(ag_binary.NewBinDecoder(tc.data)); err == nil {
				t.Error("UnmarshalWithDecoder accepted malformed instruction")
			}
		})
	}
}

func TestConfidentialTransferOuterOffsetValidation(t *testing.T) {
	t.Parallel()
	_, err := NewConfidentialTransferConfigureAccountInstructions(
		ctTokenAccount, ctMint, ctDecryptableBalance(), ctMaxPendingCounter,
		ctAuthority, nil,
		zkprogram.ProofLocationOffset(2, &proofdata.PubkeyValidityProofData{}))
	if err == nil || !strings.Contains(err.Error(), "offset") {
		t.Errorf("offset 2 err = %v, want proof instruction offset error", err)
	}

	_, err = NewConfidentialTransferWithdrawInstructions(
		ctTokenAccount, ctMint, ctAmount, ctDecimals, ctDecryptableBalance(),
		ctAuthority, nil,
		zkprogram.ProofLocationOffset(1, &proofdata.CiphertextCommitmentEqualityProofData{}),
		zkprogram.ProofLocationOffset(3, &proofdata.BatchedRangeProofU64Data{}))
	if err == nil || !strings.Contains(err.Error(), "offset") {
		t.Errorf("offsets 1,3 err = %v, want proof instruction offset error", err)
	}

	// Context state first, then offset: the offset instruction is the only
	// appended one, so it must be 1.
	instructions, err := NewConfidentialTransferWithdrawInstructions(
		ctTokenAccount, ctMint, ctAmount, ctDecimals, ctDecryptableBalance(),
		ctAuthority, nil,
		zkprogram.ProofLocationContextState[*proofdata.CiphertextCommitmentEqualityProofData](ctContextEquality),
		zkprogram.ProofLocationOffset(1, &proofdata.BatchedRangeProofU64Data{}))
	if err != nil {
		t.Fatalf("context+offset(1): %v", err)
	}
	if len(instructions) != 2 {
		t.Errorf("context+offset(1) built %d instructions, want 2", len(instructions))
	}
}

func TestConfidentialTransferRejectsUnsetProofLocation(t *testing.T) {
	t.Parallel()
	var unset zkprogram.ProofLocation[*proofdata.ZeroCiphertextProofData]
	if _, err := NewConfidentialTransferEmptyAccountInstruction(
		ctTokenAccount, ctAuthority, nil, unset); err == nil {
		t.Error("builder accepted zero-value proof location")
	}
}

// TestConfidentialTransferMultisigSigners checks the authority only signs
// itself when there are no multisig signers.
func TestConfidentialTransferMultisigSigners(t *testing.T) {
	t.Parallel()
	single := NewConfidentialTransferDepositInstruction(
		ctTokenAccount, ctMint, ctAmount, ctDecimals, ctAuthority, nil)
	accounts := single.GetAccounts()
	authority := accounts[len(accounts)-1]
	if !authority.IsSigner {
		t.Error("authority is not a signer without multisig signers")
	}

	multi := NewConfidentialTransferDepositInstruction(
		ctTokenAccount, ctMint, ctAmount, ctDecimals, ctAuthority, ctMultisig)
	accounts = multi.GetAccounts()
	if got, want := len(accounts), 3+len(ctMultisig); got != want {
		t.Fatalf("got %d accounts, want %d", got, want)
	}
	if accounts[2].IsSigner {
		t.Error("multisig authority must not be a signer")
	}
	for i, signer := range accounts[3:] {
		if !signer.IsSigner {
			t.Errorf("multisig signer %d is not a signer", i)
		}
		if signer.PublicKey != ctMultisig[i] {
			t.Errorf("multisig signer %d = %s, want %s", i, signer.PublicKey, ctMultisig[i])
		}
	}
}
