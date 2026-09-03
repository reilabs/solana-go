package token2022

import (
	"github.com/gagliardetto/solana-go"
)

// Create a `EnableConfidentialCreditsInstruction`.
func NewConfidentialTransferEnableConfidentialCreditsInstruction(
	tokenAccount solana.PublicKey,
	authority solana.PublicKey,
	multisigSigners []solana.PublicKey,
) *ConfidentialTransferExtension {
	return newBalanceCreditsInstruction(ConfidentialTransfer_EnableConfidentialCredits,
		tokenAccount, authority, multisigSigners)
}

// Create a `DisableConfidentialCreditsInstruction`.
func NewConfidentialTransferDisableConfidentialCreditsInstruction(
	tokenAccount solana.PublicKey,
	authority solana.PublicKey,
	multisigSigners []solana.PublicKey,
) *ConfidentialTransferExtension {
	return newBalanceCreditsInstruction(ConfidentialTransfer_DisableConfidentialCredits,
		tokenAccount, authority, multisigSigners)
}

// Create a `EnableNonConfidentialCreditsInstruction`.
func NewConfidentialTransferEnableNonConfidentialCreditsInstruction(
	tokenAccount solana.PublicKey,
	authority solana.PublicKey,
	multisigSigners []solana.PublicKey,
) *ConfidentialTransferExtension {
	return newBalanceCreditsInstruction(ConfidentialTransfer_EnableNonConfidentialCredits,
		tokenAccount, authority, multisigSigners)
}

// Create a `DisableNonConfidentialCreditsInstruction`.
func NewConfidentialTransferDisableNonConfidentialCreditsInstruction(
	tokenAccount solana.PublicKey,
	authority solana.PublicKey,
	multisigSigners []solana.PublicKey,
) *ConfidentialTransferExtension {
	return newBalanceCreditsInstruction(ConfidentialTransfer_DisableNonConfidentialCredits,
		tokenAccount, authority, multisigSigners)
}

func newBalanceCreditsInstruction(
	subInstruction uint8,
	tokenAccount solana.PublicKey,
	authority solana.PublicKey,
	multisigSigners []solana.PublicKey,
) *ConfidentialTransferExtension {
	return newConfidentialTransferInstruction(
		subInstruction,
		nil,
		solana.AccountMetaSlice{
			solana.Meta(tokenAccount).WRITE(),
		},
		authority,
		multisigSigners,
	)
}
