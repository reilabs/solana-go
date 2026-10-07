package token2022

import (
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/zk-elgamal-proof/encryption"
	"github.com/gagliardetto/solana-go/programs/zk-elgamal-proof/proofdata"
	"github.com/stretchr/testify/require"
)

func TestConfidentialTransferFeeClientWithdrawWithheld(t *testing.T) {
	t.Parallel()
	forEachProofLocation(t, "FromMint", testClientWithdrawWithheldFromMint)
	forEachProofLocation(t, "FromAccounts", testClientWithdrawWithheldFromAccounts)

	// Only the withdraw withheld authority can decrypt the withheld amount.
	_, destination, withheld := makeWithheld(t)
	if _, err := ConfidentialTransferWithdrawWithheldTokensFromMint(
		ctDestination, ctMint, ctAuthority, nil, nil, withheld,
		destination, destination.Pubkey, ctDecryptableBalance); err == nil {
		t.Fatal("withdraw with the wrong keypair: got nil error")
	}
}

func testClientWithdrawWithheldFromMint(t *testing.T, areProofsInline bool) {
	authority, destination, withheld := makeWithheld(t)
	instructions, err := ConfidentialTransferWithdrawWithheldTokensFromMint(
		ctDestination, ctMint, ctAuthority, nil, orNil(areProofsInline, &ctContextSingle), withheld,
		authority, destination.Pubkey, ctDecryptableBalance)
	require.NoError(t, err)
	checkWithheldProof(t, instructions, areProofsInline, withheld, destination)
}

func testClientWithdrawWithheldFromAccounts(t *testing.T, areProofsInline bool) {
	authority, destination, withheld := makeWithheld(t)
	instructions, err := ConfidentialTransferWithdrawWithheldTokensFromAccounts(
		ctDestination, ctMint, ctAuthority, nil, orNil(areProofsInline, &ctContextSingle), withheld,
		authority, destination.Pubkey, ctDecryptableBalance, ctfSources)
	require.NoError(t, err)
	checkWithheldProof(t, instructions, areProofsInline, withheld, destination)
	for _, source := range ctfSources {
		if !solana.AccountMetaSlice(instructions[0].Accounts()).GetKeys().Has(source) {
			t.Errorf("source account %s missing from the instruction accounts", source)
		}
	}
}

// makeWithheld returns fresh withdraw withheld authority and destination keypairs, and clientAmount withheld under the authority.
func makeWithheld(t *testing.T) (authority, destination *encryption.ElGamalKeypair, withheldFee encryption.ElGamalCiphertext) {
	t.Helper()
	authority, destination = genKeyPair(t), genKeyPair(t)
	withheldFee, err := authority.Pubkey.Encrypt(clientAmount)
	require.NoError(t, err)
	return authority, destination, withheldFee
}

// checkWithheldProof checks the proof of a withdraw withheld operation.
func checkWithheldProof(
	t *testing.T, instructions []solana.Instruction, areProofsInline bool,
	withheld encryption.ElGamalCiphertext, destination *encryption.ElGamalKeypair,
) {
	t.Helper()
	inlinedProofData := checkClientProofs(t, instructions, areProofsInline, ciphertextEqualityProofs)
	if !areProofsInline {
		return
	}
	proof := inlinedProofData[0].(*proofdata.CiphertextCiphertextEqualityProofData)
	if proof.Context.FirstCiphertext != withheld {
		t.Error("proof is not over the withheld amount")
	}
	if got, err := destination.DecryptU32(proof.Context.SecondCiphertext); err != nil || got != clientAmount {
		t.Errorf("destination ciphertext decrypts to (%d, %v), want (%d, nil)", got, err, clientAmount)
	}
}
