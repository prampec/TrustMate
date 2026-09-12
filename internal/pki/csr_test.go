package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/profiles"
)

func genCSR(t *testing.T, cn string, dnsNames []string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return pemBytes, key
}

func TestParseCSRRoundTrip(t *testing.T) {
	pemBytes, key := genCSR(t, "test-signer", []string{"signer.example.test"})
	csr, err := ParseCSR(pemBytes)
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	if csr.Subject.CommonName != "test-signer" {
		t.Errorf("Subject.CommonName = %q, want test-signer", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "signer.example.test" {
		t.Errorf("DNSNames = %v, want [signer.example.test]", csr.DNSNames)
	}
	if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		t.Error("parsed CSR public key does not match the key that signed it")
	}
}

func TestParseCSRAcceptsRawDER(t *testing.T) {
	pemBytes, _ := genCSR(t, "der-signer", nil)
	block, _ := pem.Decode(pemBytes)
	if _, err := ParseCSR(block.Bytes); err != nil {
		t.Fatalf("ParseCSR on raw DER: %v", err)
	}
}

func TestParseCSRRejectsTamperedSignature(t *testing.T) {
	pemBytes, _ := genCSR(t, "tampered", nil)
	block, _ := pem.Decode(pemBytes)
	der := append([]byte{}, block.Bytes...)
	der[len(der)-1] ^= 0xFF // flip a byte inside the signature
	if _, err := ParseCSR(der); err == nil {
		t.Fatal("ParseCSR on tampered signature returned nil error, want error")
	}
}

func TestParseCSRRejectsMalformedInput(t *testing.T) {
	if _, err := ParseCSR([]byte("not a csr")); err == nil {
		t.Fatal("ParseCSR on garbage input returned nil error, want error")
	}
}

func TestParseCSRFeedsIntoIssueLeaf(t *testing.T) {
	pemBytes, _ := genCSR(t, "doc-signer", []string{"docs.example.test"})
	csr, err := ParseCSR(pemBytes)
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}

	rootSigner := genSigner(t)
	now := time.Now()
	root, err := SelfSignedCA(CertRequest{
		Subject:   pkix.Name{CommonName: "Test Root"},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, rootSigner)
	if err != nil {
		t.Fatalf("SelfSignedCA: %v", err)
	}

	interSigner := genSigner(t)
	inter, err := IssueCA(CertRequest{
		Subject:     pkix.Name{CommonName: "Test Intermediate"},
		PublicKey:   interSigner.Public(),
		NotBefore:   now,
		NotAfter:    now.Add(time.Hour),
		IsCA:        true,
		PathLenZero: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, Issuer{Cert: root, Signer: rootSigner})
	if err != nil {
		t.Fatalf("IssueCA: %v", err)
	}

	leaf, err := IssueLeaf(profiles.DocumentSigning(), csr.Subject, csr.PublicKey,
		Issuer{Cert: inter, Signer: interSigner}, now, now.Add(time.Hour), csr.DNSNames)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("leaf from CSR does not verify through intermediate to root: %v", err)
	}
	if leaf.Subject.CommonName != "doc-signer" {
		t.Errorf("leaf.Subject.CommonName = %q, want doc-signer", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "docs.example.test" {
		t.Errorf("leaf.DNSNames = %v, want [docs.example.test]", leaf.DNSNames)
	}
}
