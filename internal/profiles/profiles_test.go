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
