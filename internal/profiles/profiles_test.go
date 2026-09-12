package profiles

import (
	"crypto/x509"
	"testing"
)

func TestDefaultProfileIsClientAuth(t *testing.T) {
	p := Default()
	if p.Name == "" {
		t.Error("Default().Name is empty")
	}
	found := false
	for _, eku := range p.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Errorf("Default().ExtKeyUsage = %v, want to contain ClientAuth", p.ExtKeyUsage)
	}
}

func TestServerTLSProfileIsServerAuth(t *testing.T) {
	p := ServerTLS()
	if p.Name == "" {
		t.Error("ServerTLS().Name is empty")
	}
	found := false
	for _, eku := range p.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			found = true
		}
	}
	if !found {
		t.Errorf("ServerTLS().ExtKeyUsage = %v, want to contain ServerAuth", p.ExtKeyUsage)
	}
}

func TestProfilesHaveDistinctNames(t *testing.T) {
	if Default().Name == ServerTLS().Name {
		t.Error("Default() and ServerTLS() profiles have the same Name")
	}
}

func TestDocumentSigningProfileUsage(t *testing.T) {
	p := DocumentSigning()
	if p.KeyUsage&x509.KeyUsageDigitalSignature == 0 || p.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		t.Errorf("DocumentSigning().KeyUsage = %v, want DigitalSignature|ContentCommitment", p.KeyUsage)
	}
	if !p.EnableOCSP || !p.EnableCRL {
		t.Errorf("DocumentSigning() EnableOCSP=%v EnableCRL=%v, want both true", p.EnableOCSP, p.EnableCRL)
	}
}

func TestAllHasDistinctNames(t *testing.T) {
	all := All()
	seen := map[string]bool{}
	for _, p := range all {
		if seen[p.Name] {
			t.Errorf("All() has a duplicate name %q", p.Name)
		}
		seen[p.Name] = true
	}
	if len(all) != 4 {
		t.Errorf("len(All()) = %d, want 4", len(all))
	}
}

func TestTSAProfileIsCriticalTimeStampingOnly(t *testing.T) {
	p := TSA()
	if p.Name == "" {
		t.Error("TSA().Name is empty")
	}
	if !p.CriticalEKU {
		t.Error("TSA().CriticalEKU = false, want true (RFC 3161 section 2.3)")
	}
	if len(p.ExtKeyUsage) != 1 || p.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		t.Errorf("TSA().ExtKeyUsage = %v, want exactly {ExtKeyUsageTimeStamping}", p.ExtKeyUsage)
	}
}

func TestLookup(t *testing.T) {
	if _, ok := Lookup("document-signing"); !ok {
		t.Error("Lookup(\"document-signing\") not found")
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("Lookup(\"nope\") found, want not found")
	}
}

func TestWithIssuerURLsAlwaysSetsAIA(t *testing.T) {
	p := Default().WithIssuerURLs("https://ca.example.com", false)
	if p.AIATemplate != "https://ca.example.com/v1/ca/intermediate.pem" {
		t.Errorf("AIATemplate = %q, want AIA caIssuers URL", p.AIATemplate)
	}
	if p.CDPTemplate != "" || p.OCSPTemplate != "" {
		t.Errorf("CDPTemplate/OCSPTemplate = %q/%q, want both empty (revocation disabled)", p.CDPTemplate, p.OCSPTemplate)
	}
}

func TestWithIssuerURLsGatesOnRevocationEnabledAndProfileFlags(t *testing.T) {
	// ServerTLS has EnableCRL/EnableOCSP == false, so even with
	// revocationEnabled == true, CDP/OCSP stay unset.
	p := ServerTLS().WithIssuerURLs("https://ca.example.com", true)
	if p.CDPTemplate != "" || p.OCSPTemplate != "" {
		t.Errorf("ServerTLS CDPTemplate/OCSPTemplate = %q/%q, want both empty (profile doesn't enable them)", p.CDPTemplate, p.OCSPTemplate)
	}

	d := DocumentSigning().WithIssuerURLs("https://ca.example.com", true)
	if d.CDPTemplate != "https://ca.example.com/v1/crl/intermediate.crl" {
		t.Errorf("DocumentSigning CDPTemplate = %q, want CRL URL", d.CDPTemplate)
	}
	if d.OCSPTemplate != "https://ca.example.com/v1/ocsp" {
		t.Errorf("DocumentSigning OCSPTemplate = %q, want OCSP URL", d.OCSPTemplate)
	}

	d2 := DocumentSigning().WithIssuerURLs("https://ca.example.com", false)
	if d2.CDPTemplate != "" || d2.OCSPTemplate != "" {
		t.Errorf("DocumentSigning with revocationEnabled=false: CDPTemplate/OCSPTemplate = %q/%q, want both empty", d2.CDPTemplate, d2.OCSPTemplate)
	}
}
