package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// keyTypes are the algorithms the assistant may request; RSA below 3072
// bits is deliberately absent.
var keyTypes = map[string]func() (crypto.Signer, error){
	"ecdsa-p256": func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
	"ecdsa-p384": func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) },
	"rsa-3072":   func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) },
	"rsa-4096":   func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 4096) },
}

const defaultKeyType = "ecdsa-p256"

// The assistant only picks a base name, never a path: that keeps every
// write confined to --output-dir regardless of what the model asks for.
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

func validateName(name string) error {
	if !safeName.MatchString(name) {
		return fmt.Errorf("name %q must be 1-100 characters of letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	return nil
}

// generateKeyAndCSR returns the PEM-encoded private key and a CSR for it.
func generateKeyAndCSR(keyType, commonName string, dnsNames []string) (keyPEM, csrPEM []byte, err error) {
	if keyType == "" {
		keyType = defaultKeyType
	}
	gen, ok := keyTypes[keyType]
	if !ok {
		return nil, nil, fmt.Errorf("unsupported key_type %q (use ecdsa-p256, ecdsa-p384, rsa-3072 or rsa-4096)", keyType)
	}
	key, err := gen()
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// writeNew creates dir/name with the given mode, refusing to overwrite an
// existing file so a model-chosen name can't clobber earlier key material.
func (t *toolset) writeNew(name string, data []byte, mode os.FileMode) (string, error) {
	if err := os.MkdirAll(t.outputDir, 0o700); err != nil {
		return "", fmt.Errorf("creating output directory: %w", err)
	}
	path := filepath.Join(t.outputDir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("%s already exists; choose a different name", path)
	}
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// checkFree fails early if any of the named outputs already exist, so an
// issuance isn't performed server-side only to fail on the local write.
func (t *toolset) checkFree(names ...string) error {
	for _, n := range names {
		path := filepath.Join(t.outputDir, n)
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; choose a different name", path)
		}
	}
	return nil
}
