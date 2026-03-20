// auth/crypto.go — Cryptographic helpers for iocscan auth.
//
// Provides:
//   - LoadOrCreateSecret()  load or generate the 32-byte AES encryption key
//   - Encrypt()             AES-256-GCM authenticated encryption
//   - Decrypt()             AES-256-GCM decryption + authentication
//   - HashPassword()        bcrypt cost-12 password hashing
//   - CheckPassword()       bcrypt comparison
//
// The encryption key is stored at ~/.iocscan.secret (chmod 600).
// If the file is lost all stored API keys become unrecoverable — users
// must re-enter them. The file must be backed up alongside the database.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost = 12
	keySize    = 32 // AES-256
)

// secretPath returns the path to the encryption key file.
func secretPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".iocscan.secret"), nil
}

// LoadOrCreateSecret loads the 32-byte encryption key from ~/.iocscan.secret.
// If the file does not exist a new random key is generated and saved.
// The file is created with mode 0600 — readable only by the current user.
func LoadOrCreateSecret() ([]byte, error) {
	path, err := secretPath()
	if err != nil {
		return nil, err
	}

	// Try to load existing key.
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != keySize {
			return nil, fmt.Errorf("corrupt secret file %s: expected %d bytes, got %d", path, keySize, len(data))
		}
		return data, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading secret file %s: %w", path, err)
	}

	// Generate a new random key.
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generating encryption key: %w", err)
	}

	// Write with restricted permissions — owner read/write only.
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("saving secret file %s: %w", path, err)
	}

	fmt.Printf("🔑 Encryption key created at %s — back this file up!\n", path)
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the provided key.
// Returns ciphertext as: [12-byte nonce][encrypted+tag].
// Returns nil for empty plaintext (no point encrypting an empty key).
func Encrypt(plaintext string, key []byte) ([]byte, error) {
	if plaintext == "" {
		return nil, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Generate a random nonce — never reuse a nonce with the same key.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Seal appends the encrypted ciphertext + auth tag after the nonce.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext produced by Encrypt.
// Returns empty string for nil/empty ciphertext.
func Decrypt(ciphertext []byte, key []byte) (string, error) {
	if len(ciphertext) == 0 {
		return "", nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// This fires if the key is wrong or the ciphertext was tampered with.
		return "", fmt.Errorf("decryption failed (wrong key or tampered data): %w", err)
	}

	return string(plaintext), nil
}

// HashPassword hashes a plaintext password using bcrypt at cost 12.
// ~300ms per call — intentional, prevents brute-force attacks.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword returns true if password matches the bcrypt hash.
// Constant-time comparison — safe against timing attacks.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
