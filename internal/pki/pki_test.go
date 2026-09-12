package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/profiles"
)

func genSigner(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestGenerateSerialFormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		s, err := GenerateSerial()
		if err != nil {
			t.Fatalf("GenerateSerial: %v", err)
		}
		if s.Sign() <= 0 {
			t.Fatalf("serial %v is not positive", s)
		}
		if s.BitLen() > serialBytes*8-1 {
			t.Fatalf("serial %v exceeds %d bits (top bit not cleared?)", s, serialBytes*8-1)
		}
		key := s.String()
		if seen[key] {
			t.Fatalf("duplicate serial generated: %v", s)
		}
		seen[key] = true
	}
}

func TestSelfSignedCA(t *testing.T) {
	signer := genSigner(t)
	now := time.Now()
	root, err := SelfSignedCA(CertRequest{
		Subject:   pkix.Name{CommonName: "Test Root"},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, signer)
	if err != nil {
		t.Fatalf("SelfSignedCA: %v", err)
	}

	if !root.IsCA {
		t.Error("root.IsCA = false, want true")
	}
	if root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("root missing KeyUsageCertSign")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Errorf("root does not verify against itself: %v", err)
	}
	if len(root.SubjectKeyId) == 0 {
		t.Error("root.SubjectKeyId is empty")
	}
}

func TestIssueCAChainsToRootAndGatesExtensions(t *testing.T) {
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
		CRLURL:      "https://example.test/v1/crl/intermediate.crl",
		OCSPURL:     "https://example.test/v1/ocsp",
	}, Issuer{Cert: root, Signer: rootSigner})
	if err != nil {
		t.Fatalf("IssueCA: %v", err)
	}

	if !inter.MaxPathLenZero {
		t.Error("intermediate MaxPathLenZero = false, want true")
	}
	if string(inter.AuthorityKeyId) != string(root.SubjectKeyId) {
		t.Error("intermediate AuthorityKeyId does not match root SubjectKeyId")
	}
	if len(inter.CRLDistributionPoints) != 1 || inter.CRLDistributionPoints[0] != "https://example.test/v1/crl/intermediate.crl" {
		t.Errorf("intermediate CRLDistributionPoints = %v", inter.CRLDistributionPoints)
	}
	if len(inter.OCSPServer) != 1 || inter.OCSPServer[0] != "https://example.test/v1/ocsp" {
		t.Errorf("intermediate OCSPServer = %v", inter.OCSPServer)
	}

	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := inter.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("intermediate does not verify against root: %v", err)
	}

	// Revocation disabled -> no CDP/OCSP extensions.
	inter2, err := IssueCA(CertRequest{
		Subject:     pkix.Name{CommonName: "Test Intermediate 2"},
		PublicKey:   interSigner.Public(),
		NotBefore:   now,
		NotAfter:    now.Add(time.Hour),
		IsCA:        true,
		PathLenZero: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, Issuer{Cert: root, Signer: rootSigner})
	if err != nil {
		t.Fatalf("IssueCA (no revocation): %v", err)
	}
	if len(inter2.CRLDistributionPoints) != 0 || len(inter2.OCSPServer) != 0 {
		t.Errorf("expected no CDP/OCSP extensions, got CRL=%v OCSP=%v", inter2.CRLDistributionPoints, inter2.OCSPServer)
	}
}

func TestIssueLeafChainsToRootThroughIntermediate(t *testing.T) {
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

	leafSigner := genSigner(t)
	profile := profiles.Default()
	leaf, err := IssueLeaf(profile, pkix.Name{CommonName: "admin"}, leafSigner.Public(),
		Issuer{Cert: inter, Signer: interSigner}, now, now.Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	found := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Errorf("leaf.ExtKeyUsage = %v, want to contain ClientAuth", leaf.ExtKeyUsage)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("leaf does not verify through intermediate to root: %v", err)
	}
}
