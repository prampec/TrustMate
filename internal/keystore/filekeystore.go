package keystore

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // KiB
	argon2Threads = 4
	argon2KeyLen  = 32 // AES-256
	saltLen       = 16
)

// keyFile is the on-disk, JSON-encoded encrypted key envelope.
type keyFile struct {
	Version      int       `json:"version"`
	KeyAlgorithm Algorithm `json:"key_algorithm"`
	KDF          string    `json:"kdf"`
	Salt         []byte    `json:"salt"`
	Nonce        []byte    `json:"nonce"`
	Ciphertext   []byte    `json:"ciphertext"`
	CreatedAt    time.Time `json:"created_at"`
}

// FileKeyStore is the v1 keystore: one AES-256-GCM-encrypted file per
// key, the encryption key derived per-file via Argon2id from a shared
// passphrase (the KEK). See docs/design.md's Security section: the
// passphrase is supplied at startup, never stored alongside the key.
type FileKeyStore struct {
	dir        string
	passphrase []byte

	mu     sync.Mutex
	cached map[KeyRef]crypto.Signer
}

// NewFileKeyStore opens (creating if necessary) a file-backed keystore
// rooted at dir, encrypting/decrypting with passphrase.
func NewFileKeyStore(dir string, passphrase []byte) (*FileKeyStore, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("keystore: empty passphrase")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keystore: creating dir %s: %w", dir, err)
	}
	return &FileKeyStore{
		dir:        dir,
		passphrase: passphrase,
		cached:     make(map[KeyRef]crypto.Signer),
	}, nil
}

func (f *FileKeyStore) path(ref KeyRef) string {
	return filepath.Join(f.dir, string(ref)+".json")
}

func (f *FileKeyStore) Exists(ctx context.Context, ref KeyRef) (bool, error) {
	_, err := os.Stat(f.path(ref))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (f *FileKeyStore) Generate(ctx context.Context, ref KeyRef, alg Algorithm) (crypto.Signer, error) {
	exists, err := f.Exists(ctx, ref)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("keystore: key %q already exists", ref)
	}

	signer, der, err := generateKey(alg)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("keystore: generating salt: %w", err)
	}
	gcm, err := newGCM(f.passphrase, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keystore: generating nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, der, nil)

	kf := keyFile{
		Version:      1,
		KeyAlgorithm: alg,
		KDF:          "argon2id",
		Salt:         salt,
		Nonce:        nonce,
		Ciphertext:   ciphertext,
		CreatedAt:    time.Now().UTC(),
	}
	if err := writeKeyFileAtomic(f.path(ref), kf); err != nil {
		return nil, err
	}

	f.mu.Lock()
	f.cached[ref] = signer
	f.mu.Unlock()
	return signer, nil
}

func (f *FileKeyStore) Get(ctx context.Context, ref KeyRef) (crypto.Signer, error) {
	f.mu.Lock()
	if s, ok := f.cached[ref]; ok {
		f.mu.Unlock()
		return s, nil
	}
	f.mu.Unlock()

	data, err := os.ReadFile(f.path(ref))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("keystore: key %q not found", ref)
		}
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("keystore: decoding key %q: %w", ref, err)
	}

	gcm, err := newGCM(f.passphrase, kf.Salt)
	if err != nil {
		return nil, err
	}
	der, err := gcm.Open(nil, kf.Nonce, kf.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("keystore: decrypting key %q: %w", ref, err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("keystore: parsing key %q: %w", ref, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("keystore: key %q is not a signer", ref)
	}

	f.mu.Lock()
	f.cached[ref] = signer
	f.mu.Unlock()
	return signer, nil
}

func generateKey(alg Algorithm) (crypto.Signer, []byte, error) {
	var (
		signer crypto.Signer
		err    error
	)
	switch alg {
	case AlgorithmECDSAP256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgorithmRSA2048:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, nil, fmt.Errorf("keystore: unsupported algorithm %q", alg)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("keystore: generating %s key: %w", alg, err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, nil, fmt.Errorf("keystore: marshalling key: %w", err)
	}
	return signer, der, nil
}

func newGCM(passphrase, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keystore: building cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: building GCM: %w", err)
	}
	return gcm, nil
}

func writeKeyFileAtomic(path string, kf keyFile) error {
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return fmt.Errorf("keystore: encoding key file: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("keystore: writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("keystore: renaming %s to %s: %w", tmp, path, err)
	}
	return nil
}
