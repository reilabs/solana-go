package encryption

import "github.com/gagliardetto/solana-go/programs/zk-elgamal-proof/internal/bridge"

// NewAeKey generates a random AES-GCM-SIV key.
func NewAeKey() (AeKey, error) {
	return bridge.InvokeWith[AeKey]("ae_key_new_rand")
}

// Encrypt produces the encryption of amount.
func (k AeKey) Encrypt(amount uint64) (AeCiphertext, error) {
	return bridge.InvokeWith[AeCiphertext]("ae_encrypt", k, bridge.Scalar(amount))
}

// Decrypt recovers the amount from an AE ciphertext.
func (k AeKey) Decrypt(ct AeCiphertext) (uint64, error) {
	amount, err := bridge.InvokeWith[bridge.Scalar]("ae_decrypt", k, ct)
	return uint64(amount), err
}
