package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/store"
)

func openTest(t *testing.T) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trustmate.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenAndPing(t *testing.T) {
	db := openTest(t)
	if err := db.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trustmate.db")
	db1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	db1.Close()

	db2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open (reapplying migrations): %v", err)
	}
	defer db2.Close()
	if err := db2.Ping(context.Background()); err != nil {
		t.Fatalf("Ping after reopen: %v", err)
	}
}

func TestCertificateRepositoryCRUD(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	repo := db.Certificates()

	now := time.Now().UTC().Truncate(time.Second)
	root := store.CertificateRecord{
		Serial:    "aa",
		Kind:      store.CertKindRoot,
		Subject:   "CN=Root",
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
		PEM:       []byte("root-pem"),
		KeyRef:    "root",
		CreatedAt: now,
	}
	if err := repo.Create(ctx, root); err != nil {
		t.Fatalf("Create root: %v", err)
	}

	leaf := store.CertificateRecord{
		Serial:       "bb",
		Kind:         store.CertKindLeaf,
		ProfileName:  "server-tls",
		Subject:      "CN=server",
		IssuerSerial: "aa",
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		PEM:          []byte("leaf-pem"),
		KeyRef:       "server-tls",
		CreatedAt:    now.Add(time.Second),
	}
	if err := repo.Create(ctx, leaf); err != nil {
		t.Fatalf("Create leaf: %v", err)
	}

	got, err := repo.GetBySerial(ctx, "aa")
	if err != nil {
		t.Fatalf("GetBySerial: %v", err)
	}
	if got.Subject != "CN=Root" || got.Kind != store.CertKindRoot {
		t.Errorf("GetBySerial returned %+v", got)
	}

	roots, err := repo.FindByKind(ctx, store.CertKindRoot)
	if err != nil {
		t.Fatalf("FindByKind(root): %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("FindByKind(root) = %d rows, want 1", len(roots))
	}

	leaves, err := repo.FindByKind(ctx, store.CertKindLeaf)
	if err != nil {
		t.Fatalf("FindByKind(leaf): %v", err)
	}
	if len(leaves) != 1 || leaves[0].IssuerSerial != "aa" {
		t.Fatalf("FindByKind(leaf) = %+v", leaves)
	}

	latest, err := repo.GetLatestByProfile(ctx, "server-tls")
	if err != nil {
		t.Fatalf("GetLatestByProfile: %v", err)
	}
	if latest.Serial != "bb" {
		t.Errorf("GetLatestByProfile returned serial %q, want bb", latest.Serial)
	}

	if _, err := repo.GetBySerial(ctx, "does-not-exist"); err != store.ErrNotFound {
		t.Errorf("GetBySerial(missing) error = %v, want store.ErrNotFound", err)
	}
}

func TestProfileRepositoryVersioning(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	repo := db.Profiles()

	now := time.Now().UTC().Truncate(time.Second)
	if err := repo.Upsert(ctx, store.ProfileRecord{Name: "default", Version: 1, Data: []byte("v1"), CreatedAt: now}); err != nil {
		t.Fatalf("Upsert v1: %v", err)
	}
	if err := repo.Upsert(ctx, store.ProfileRecord{Name: "default", Version: 2, Data: []byte("v2"), CreatedAt: now.Add(time.Second)}); err != nil {
		t.Fatalf("Upsert v2: %v", err)
	}

	got, err := repo.Get(ctx, "default")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version != 2 || string(got.Data) != "v2" {
		t.Errorf("Get returned %+v, want version 2 / data v2", got)
	}

	all, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("List returned %d rows, want 2", len(all))
	}

	if _, err := repo.Get(ctx, "missing"); err != store.ErrNotFound {
		t.Errorf("Get(missing) error = %v, want store.ErrNotFound", err)
	}
}

func TestAuditRepositoryAppendAndList(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	repo := db.Audit()

	for i := 0; i < 3; i++ {
		if err := repo.Append(ctx, store.AuditEntry{
			Timestamp: time.Now().UTC(),
			Actor:     "bootstrap",
			Action:    "issue",
			Target:    "cert",
			Detail:    "detail",
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	entries, err := repo.List(ctx, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("List returned %d entries, want 3", len(entries))
	}
	// Most recent first.
	if entries[0].ID < entries[1].ID {
		t.Errorf("List is not ordered most-recent-first: %+v", entries)
	}

	limited, err := repo.List(ctx, 2)
	if err != nil {
		t.Fatalf("List(limit=2): %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("List(limit=2) returned %d entries, want 2", len(limited))
	}
}
