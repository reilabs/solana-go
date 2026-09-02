package token2022

import (
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/zk-elgamal-proof/proofdata"
	"github.com/gagliardetto/solana-go/programs/zk-elgamal-proof/zkprogram"
)

// newConfidentialTransferInstruction assembles a ConfidentialTransfer sub-instruction
func newConfidentialTransferInstruction(
	subInstruction uint8,
	rawData []byte,
	accounts solana.AccountMetaSlice,
	authority solana.PublicKey,
	multisigSigners []solana.PublicKey,
) *ConfidentialTransferExtension {
	authorityMeta := solana.Meta(authority)
	// Authority signs absent of multisig signers
	if len(multisigSigners) == 0 {
		authorityMeta.SIGNER()
	}
	ct_instruction := &ConfidentialTransferExtension{
		SubInstruction: subInstruction,
		RawData:        rawData,
		Accounts:       append(accounts, authorityMeta),
		Signers:        make(solana.AccountMetaSlice, 0, len(multisigSigners)),
	}
	for _, signer := range multisigSigners {
		ct_instruction.Signers = append(ct_instruction.Signers, solana.Meta(signer).SIGNER())
	}
	return ct_instruction
}

// resolveProofLocation resolves a proof location to the account the consuming
// instruction carries for it and the offset to embed in the instruction data:
func resolveProofLocation[T proofdata.ProofData](
	location zkprogram.ProofLocation[T],
) (*solana.AccountMeta, int8, error) {
	if err := location.Validate(); err != nil {
		return nil, 0, err
	}
	// Embedded proofs return non-zero offset and the sysVarInstructionsAccount
	if location.IsInstructionOffset() {
		return solana.Meta(solana.SysVarInstructionsPubkey), location.InstructionOffset(), nil
	}
	// Context-state reciept return zero offset and the account holding the receipt
	return solana.Meta(location.ContextStateAccount()), 0, nil
}

// appendVerifyProofInstruction appends the VerifyProof instruction for a proof
// location in the instruction offset form.
//
// Callers must pass a slice whose element at index 0 is the consuming instruction,
// followed only by previously appended verify instructions.
func appendVerifyProofInstruction[T proofdata.ProofData](
	instructions []solana.Instruction,
	proofInstruction zkprogram.ProofInstruction,
	location zkprogram.ProofLocation[T],
) ([]solana.Instruction, error) {
	if !location.IsInstructionOffset() {
		return instructions, nil
	}
	expectedOffset := int8(len(instructions))
	if offset := location.InstructionOffset(); offset != expectedOffset {
		return nil, fmt.Errorf("token2022: proof instruction offset is %d, want %d", offset, expectedOffset)
	}
	verifyInstruction, err := proofInstruction.EncodeVerifyProof(nil, location.ProofData())
	if err != nil {
		return nil, err
	}
	return append(instructions, verifyInstruction), nil
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}
