// Package crypto seals and opens secrets at rest with AES-256-GCM (ADR-0006).
//
// The 32-byte master key lives in DATA_DIR/secret.key (mode 0600), generated on
// first start and loaded thereafter. Sealed output is base64(nonce ‖ ciphertext);
// a fresh random nonce is used per message. The key is never logged.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// KeyFileName is the master key filename inside the data directory.
const KeyFileName = "secret.key"

// keySize is 32 bytes, selecting AES-256.
const keySize = 32

// Box seals and opens secrets with a key-bound AEAD.
type Box struct {
	aead cipher.AEAD
}

// NewBox loads the master key from DATA_DIR/secret.key, generating it (0600) on
// first start, and returns a Box ready to Seal and Open.
func NewBox(dataDir string) (*Box, error) {
	key, err := loadOrCreateKey(dataDir)
	if err != nil {
		return nil, err
	}
	return newBox(key)
}

func newBox(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext and returns base64(nonce ‖ ciphertext+tag).
func (b *Box) Seal(plaintext []byte) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("crypto: generate nonce: %w", err)
	}
	sealed := b.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal. It errors on invalid base64, on input too short to contain
// a nonce, and on failed authentication (tampered ciphertext or wrong key).
func (b *Box) Open(ciphertext string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode: %w", err)
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	nonce, sealed := raw[:ns], raw[ns:]
	plaintext, err := b.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: open failed (tampered or wrong key): %w", err)
	}
	return plaintext, nil
}

// loadOrCreateKey reads DATA_DIR/secret.key, or generates a fresh 32-byte key
// (mode 0600) if it does not yet exist.
func loadOrCreateKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, KeyFileName)

	key, err := loadKey(path)
	switch {
	case err == nil:
		// The key must stay owner-only at rest: tighten a loosened mode rather
		// than trust it as found.
		if err := ensureKeyPerm(path); err != nil {
			return nil, err
		}
		return key, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}

	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("crypto: create data dir: %w", err)
	}
	return createKey(path)
}

// loadKey reads and validates an existing key file. A read error (including
// fs.ErrNotExist) is wrapped but preserved for errors.Is at the call site.
func loadKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: read key: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("crypto: %s has %d bytes, want %d", path, len(key), keySize)
	}
	return key, nil
}

// createKey generates a fresh key and publishes it atomically: it is written to
// a temp file first, then hard-linked into place. link(2) fails with EEXIST if
// the key already exists, so concurrent first-starts converge on a single key
// (the losers adopt the winner's), and the final path only ever appears as a
// fully-written file — a reader can never observe a partial key. The explicit
// Chmod forces 0600 regardless of the process umask, and Sync flushes before the
// key is linked into place.
func createKey(path string) ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("crypto: generate key: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), KeyFileName+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("crypto: create temp key: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("crypto: write temp key: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("crypto: chmod temp key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("crypto: sync temp key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("crypto: close temp key: %w", err)
	}

	switch err := os.Link(tmp.Name(), path); {
	case err == nil:
		return key, nil
	case errors.Is(err, fs.ErrExist):
		return loadKey(path) // lost the race; adopt the winner's complete key
	default:
		return nil, fmt.Errorf("crypto: link key: %w", err)
	}
}

// ensureKeyPerm tightens the key file back to 0600 if its mode grants any group
// or other access.
func ensureKeyPerm(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("crypto: stat key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("crypto: tighten key perm: %w", err)
		}
	}
	return nil
}
