// serpent/crypto.go
package serpent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	// AES-GCM specific constants
	gcmNonceSize = 12 // GCM recommends 12 bytes nonce
	gcmTagSize   = 16 // GCM tag size
)

// EncryptWithAESGCM encrypts plaintext using AES-GCM with a given key and associated data.
// It generates a random nonce. Returns nonce || ciphertext || tag.
func EncryptWithAESGCM(key, plaintext, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, associatedData)
	return ciphertext, nil
}

// DecryptWithAESGCM decrypts ciphertext (nonce || ciphertext || tag) using AES-GCM.
func DecryptWithAESGCM(key, ciphertextWithNonce, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertextWithNonce) < gcmNonceSize {
		return nil, errors.New("serpent: ciphertext too short for GCM nonce")
	}

	nonce := ciphertextWithNonce[:gcmNonceSize]
	ciphertext := ciphertextWithNonce[gcmNonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, err // Decryption or authentication failed
	}

	return plaintext, nil
}
