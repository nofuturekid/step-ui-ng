package crypto_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nofuturekid/step-ui-ng/internal/crypto"
)

// Acceptance (spec/0002 FR-1): "Given a fresh data dir, When the app starts, Then
// secret.key is created (0600)." NewBox must create a 32-byte key file with 0600
// permissions inside the data dir.
func TestNewBoxCreatesKeyFile0600(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fresh")

	if _, err := crypto.NewBox(dir); err != nil {
		t.Fatalf("NewBox: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("secret.key not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("secret.key mode = %o, want 600", perm)
	}
	if info.Size() != 32 {
		t.Fatalf("secret.key size = %d, want 32 (AES-256 key)", info.Size())
	}
}

// Acceptance (spec/0002): "Given a value, When I Seal then Open it, Then I get the
// original bytes back."
func TestSealOpenRoundTrip(t *testing.T) {
	box, err := crypto.NewBox(t.TempDir())
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}

	want := []byte("super-secret provisioner password \x00\xff with binary")
	ct, err := box.Seal(want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := box.Open(ct)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, want)
	}
}

// Acceptance (spec/0002): "Given a ciphertext with one byte flipped, When I Open
// it, Then it errors." Also covers FR-3 short ciphertext.
func TestOpenRejectsTamperedAndShort(t *testing.T) {
	box, err := crypto.NewBox(t.TempDir())
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	ct, err := box.Seal([]byte("authentic message"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Flip one byte of the (decoded) ciphertext and re-encode: GCM must reject it.
	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := box.Open(tampered); err == nil {
		t.Fatal("Open accepted a tampered ciphertext, want error")
	}

	// A too-short input (no room for nonce) must error, not panic.
	short := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
	if _, err := box.Open(short); err == nil {
		t.Fatal("Open accepted a too-short ciphertext, want error")
	}

	// Non-base64 input must error too.
	if _, err := box.Open("!!!not base64!!!"); err == nil {
		t.Fatal("Open accepted invalid base64, want error")
	}
}

// Acceptance (spec/0002): "Given an existing secret.key, When the app restarts,
// Then previously sealed values still open." The key must persist across reloads.
func TestKeyPersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()

	box1, err := crypto.NewBox(dir)
	if err != nil {
		t.Fatalf("first NewBox: %v", err)
	}
	want := []byte("persisted secret")
	ct, err := box1.Seal(want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Simulate a restart: a new Box loading the same on-disk key.
	box2, err := crypto.NewBox(dir)
	if err != nil {
		t.Fatalf("second NewBox: %v", err)
	}
	got, err := box2.Open(ct)
	if err != nil {
		t.Fatalf("Open after reload: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("reload mismatch: got %q, want %q", got, want)
	}
}

// Sealing the same plaintext twice must yield different ciphertexts: a fresh
// random nonce per message is required for AES-GCM security (no nonce reuse).
func TestSealUsesFreshNoncePerMessage(t *testing.T) {
	box, err := crypto.NewBox(t.TempDir())
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	msg := []byte("same plaintext")
	a, err := box.Seal(msg)
	if err != nil {
		t.Fatalf("Seal a: %v", err)
	}
	b, err := box.Seal(msg)
	if err != nil {
		t.Fatalf("Seal b: %v", err)
	}
	if a == b {
		t.Fatal("identical ciphertexts for the same plaintext: nonce is being reused")
	}
}

// A value sealed under one master key must not open under a different key: this
// is the cross-instance isolation property of ADR-0006 (each data dir has its
// own key). Two fresh data dirs yield two independent random keys.
func TestOpenRejectsWrongKey(t *testing.T) {
	boxA, err := crypto.NewBox(t.TempDir())
	if err != nil {
		t.Fatalf("NewBox A: %v", err)
	}
	boxB, err := crypto.NewBox(t.TempDir())
	if err != nil {
		t.Fatalf("NewBox B: %v", err)
	}

	ct, err := boxA.Seal([]byte("isolation matters"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := boxB.Open(ct); err == nil {
		t.Fatal("Open under the wrong key succeeded, want error")
	}
}

// A key file of the wrong length must be rejected, not silently accepted. A
// 16-byte file is the dangerous case: aes.NewCipher would otherwise treat it as
// a valid AES-128 key, silently downgrading the cipher.
func TestNewBoxRejectsWrongSizeKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, crypto.KeyFileName), make([]byte, 16), 0o600); err != nil {
		t.Fatalf("seed short key: %v", err)
	}
	if _, err := crypto.NewBox(dir); err == nil {
		t.Fatal("NewBox accepted a 16-byte key, want error")
	}
}

// The key must stay owner-only at rest (FR-1, ADR-0006). If an existing key file
// is found with looser permissions, NewBox must tighten it back to 0600 rather
// than trust it as-is.
func TestKeyPermissionsRepairedOnLoad(t *testing.T) {
	dir := t.TempDir()
	if _, err := crypto.NewBox(dir); err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	path := filepath.Join(dir, crypto.KeyFileName)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("loosen perms: %v", err)
	}

	if _, err := crypto.NewBox(dir); err != nil {
		t.Fatalf("reload NewBox: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key perm after reload = %o, want 600 (not repaired)", perm)
	}
}

// Concurrent first-starts against one fresh data dir must converge on a single
// key: no start may end up holding an in-memory key that differs from the one on
// disk (which would make its sealed secrets unrecoverable). Regression guard for
// the atomic (O_EXCL) key creation.
func TestConcurrentNewBoxConvergesOnOneKey(t *testing.T) {
	dir := t.TempDir()

	const n = 32
	boxes := make([]*crypto.Box, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range boxes {
		go func(i int) {
			defer wg.Done()
			box, err := crypto.NewBox(dir)
			if err != nil {
				t.Errorf("NewBox[%d]: %v", i, err)
				return
			}
			boxes[i] = box
		}(i)
	}
	wg.Wait()

	// A ciphertext sealed by any one box must open under every other box: they
	// all share the same on-disk key.
	ref, err := boxes[0].Seal([]byte("converged"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for i, box := range boxes {
		if box == nil {
			t.Fatalf("box[%d] is nil", i)
		}
		got, err := box.Open(ref)
		if err != nil {
			t.Fatalf("box[%d] could not open the shared ciphertext (keys diverged): %v", i, err)
		}
		if string(got) != "converged" {
			t.Fatalf("box[%d] opened to %q, want %q", i, got, "converged")
		}
	}
}
