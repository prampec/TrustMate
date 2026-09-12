package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

func TestBuildTemplateCriticalExtKeyUsage(t *testing.T) {
	now := time.Now()
	tmpl, err := buildTemplate(CertRequest{
		Subject:             pkix.Name{CommonName: "Test TSA"},
		NotBefore:           now,
		NotAfter:            now.Add(time.Hour),
		ExtKeyUsage:         []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CriticalExtKeyUsage: true,
	})
	if err != nil {
		t.Fatalf("buildTemplate: %v", err)
	}
	if len(tmpl.ExtKeyUsage) != 0 {
		t.Errorf("tmpl.ExtKeyUsage = %v, want empty (critical EKU goes through ExtraExtensions instead)", tmpl.ExtKeyUsage)
	}
	if len(tmpl.ExtraExtensions) != 1 {
		t.Fatalf("tmpl.ExtraExtensions = %v, want exactly one extension", tmpl.ExtraExtensions)
	}
	ext := tmpl.ExtraExtensions[0]
	if !ext.Id.Equal(oidExtKeyUsage) {
		t.Errorf("extension OID = %v, want %v", ext.Id, oidExtKeyUsage)
	}
	if !ext.Critical {
		t.Error("extension not marked critical")
	}
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil {
		t.Fatalf("asn1.Unmarshal(ExtraExtensions[0].Value): %v", err)
	}
	if len(oids) != 1 || !oids[0].Equal(extKeyUsageOIDs[x509.ExtKeyUsageTimeStamping]) {
		t.Errorf("decoded OIDs = %v, want exactly {id-kp-timeStamping}", oids)
	}
}

func TestIssueLeafCriticalExtKeyUsageRoundTrips(t *testing.T) {
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

	tsaSigner := genSigner(t)
	tsaCert, err := IssueLeaf(profiles.TSA(), pkix.Name{CommonName: "Test TSA"}, tsaSigner.Public(),
		Issuer{Cert: inter, Signer: interSigner}, now, now.Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	if len(tsaCert.ExtKeyUsage) != 1 || tsaCert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		t.Errorf("tsaCert.ExtKeyUsage = %v, want exactly {ExtKeyUsageTimeStamping}", tsaCert.ExtKeyUsage)
	}
	var criticalFound bool
	for _, ext := range tsaCert.Extensions {
		if ext.Id.Equal(oidExtKeyUsage) {
			if !ext.Critical {
				t.Error("parsed EKU extension is not marked critical")
			}
			criticalFound = true
		}
	}
	if !criticalFound {
		t.Fatal("parsed certificate has no EKU extension")
	}
}
