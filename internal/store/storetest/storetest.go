// Package storetest is a shared behavioral contract test suite for
// store.Store implementations. internal/store/sqlite and
// internal/store/postgres both run it against a fresh store instance so
// the two backends can't silently drift in behavior (e.g. Revoke's
// already-revoked semantics, or GetLatestByProfile's tiebreak rule).
// Backend-specific concerns (Open, migration idempotency, connection
// pooling) stay in each package's own tests -- this suite only exercises
// store.Store's documented behavior.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/store"
)

// Run executes the full contract suite against db, which must be freshly
// created (or truncated) so the fixed literal identifiers used below
// don't collide with leftover rows from a previous run.
func Run(t *testing.T, db store.Store) {
	t.Helper()
	t.Run("CertificateRepositoryCRUD", func(t *testing.T) { testCertificateRepositoryCRUD(t, db) })
	t.Run("GetLatestByProfileBreaksTiesByInsertionOrder", func(t *testing.T) { testGetLatestByProfileTiebreak(t, db) })
	t.Run("ProfileRepositoryVersioning", func(t *testing.T) { testProfileRepositoryVersioning(t, db) })
	t.Run("CertificateRepositoryRevoke", func(t *testing.T) { testCertificateRepositoryRevoke(t, db) })
	t.Run("ClientRoleRepository", func(t *testing.T) { testClientRoleRepository(t, db) })
	t.Run("AuditRepositoryAppendAndList", func(t *testing.T) { testAuditRepositoryAppendAndList(t, db) })
	t.Run("ACMERepositories", func(t *testing.T) { testACMERepositories(t, db) })
}

func testCertificateRepositoryCRUD(t *testing.T, db store.Store) {
	ctx := context.Background()
	repo := db.Certificates()

	now := time.Now().UTC().Truncate(time.Second)
	root := store.CertificateRecord{
		Serial:    "storetest-aa",
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
		Serial:       "storetest-bb",
		Kind:         store.CertKindLeaf,
		ProfileName:  "server-tls",
		Subject:      "CN=server",
		IssuerSerial: "storetest-aa",
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		PEM:          []byte("leaf-pem"),
		KeyRef:       "server-tls",
		CreatedAt:    now.Add(time.Second),
	}
	if err := repo.Create(ctx, leaf); err != nil {
		t.Fatalf("Create leaf: %v", err)
	}

	got, err := repo.GetBySerial(ctx, "storetest-aa")
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
	if len(leaves) != 1 || leaves[0].IssuerSerial != "storetest-aa" {
		t.Fatalf("FindByKind(leaf) = %+v", leaves)
	}

	latest, err := repo.GetLatestByProfile(ctx, "server-tls")
	if err != nil {
		t.Fatalf("GetLatestByProfile: %v", err)
	}
	if latest.Serial != "storetest-bb" {
		t.Errorf("GetLatestByProfile returned serial %q, want storetest-bb", latest.Serial)
	}

	if _, err := repo.GetBySerial(ctx, "does-not-exist"); err != store.ErrNotFound {
		t.Errorf("GetBySerial(missing) error = %v, want store.ErrNotFound", err)
	}
}

func testGetLatestByProfileTiebreak(t *testing.T, db store.Store) {
	ctx := context.Background()
	repo := db.Certificates()

	// Same created_at timestamp on both rows -- created_at only has
	// second-level precision, so this is a realistic tie (e.g. two TSA
	// identity rows from a rotation within the same wall-clock second),
	// not a contrived one.
	now := time.Now().UTC().Truncate(time.Second)
	if err := repo.Create(ctx, store.CertificateRecord{
		Serial: "storetest-tsa-1", Kind: store.CertKindLeaf, ProfileName: "storetest-tsa", Subject: "CN=tsa-1",
		NotBefore: now, NotAfter: now.Add(time.Hour), PEM: []byte("pem-1"), KeyRef: "tsa", CreatedAt: now,
	}); err != nil {
		t.Fatalf("Create(tsa-1): %v", err)
	}
	if err := repo.Create(ctx, store.CertificateRecord{
		Serial: "storetest-tsa-2", Kind: store.CertKindLeaf, ProfileName: "storetest-tsa", Subject: "CN=tsa-2",
		NotBefore: now, NotAfter: now.Add(time.Hour), PEM: []byte("pem-2"), KeyRef: "tsa-2", CreatedAt: now,
	}); err != nil {
		t.Fatalf("Create(tsa-2): %v", err)
	}

	latest, err := repo.GetLatestByProfile(ctx, "storetest-tsa")
	if err != nil {
		t.Fatalf("GetLatestByProfile: %v", err)
	}
	if latest.Serial != "storetest-tsa-2" {
		t.Errorf("GetLatestByProfile returned serial %q, want %q (the later-inserted row)", latest.Serial, "storetest-tsa-2")
	}
}

func testProfileRepositoryVersioning(t *testing.T, db store.Store) {
	ctx := context.Background()
	repo := db.Profiles()

	now := time.Now().UTC().Truncate(time.Second)
	if err := repo.Upsert(ctx, store.ProfileRecord{Name: "storetest-default", Version: 1, Data: []byte("v1"), CreatedAt: now}); err != nil {
		t.Fatalf("Upsert v1: %v", err)
	}
	if err := repo.Upsert(ctx, store.ProfileRecord{Name: "storetest-default", Version: 2, Data: []byte("v2"), CreatedAt: now.Add(time.Second)}); err != nil {
		t.Fatalf("Upsert v2: %v", err)
	}

	got, err := repo.Get(ctx, "storetest-default")
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
	found := 0
	for _, rec := range all {
		if rec.Name == "storetest-default" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("List contains %d storetest-default rows, want 2", found)
	}

	if _, err := repo.Get(ctx, "storetest-missing"); err != store.ErrNotFound {
		t.Errorf("Get(missing) error = %v, want store.ErrNotFound", err)
	}
}

func testCertificateRepositoryRevoke(t *testing.T, db store.Store) {
	ctx := context.Background()
	repo := db.Certificates()

	now := time.Now().UTC().Truncate(time.Second)
	if err := repo.Create(ctx, store.CertificateRecord{
		Serial: "storetest-cc", Kind: store.CertKindLeaf, Subject: "CN=leaf",
		NotBefore: now, NotAfter: now.Add(time.Hour), PEM: []byte("leaf-pem"), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	revokedAt := now.Add(time.Minute)
	if err := repo.Revoke(ctx, "storetest-cc", "keyCompromise", revokedAt); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := repo.GetBySerial(ctx, "storetest-cc")
	if err != nil {
		t.Fatalf("GetBySerial: %v", err)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, revokedAt)
	}
	if got.RevocationReason != "keyCompromise" {
		t.Errorf("RevocationReason = %q, want keyCompromise", got.RevocationReason)
	}

	if err := repo.Revoke(ctx, "storetest-cc", "superseded", now); err != store.ErrAlreadyRevoked {
		t.Errorf("second Revoke error = %v, want ErrAlreadyRevoked", err)
	}
	if err := repo.Revoke(ctx, "does-not-exist", "unspecified", now); err != store.ErrNotFound {
		t.Errorf("Revoke(missing) error = %v, want ErrNotFound", err)
	}

	revoked, err := repo.FindRevoked(ctx)
	if err != nil {
		t.Fatalf("FindRevoked: %v", err)
	}
	found := false
	for _, rec := range revoked {
		if rec.Serial == "storetest-cc" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FindRevoked = %+v, want an entry for serial storetest-cc", revoked)
	}
}

func testClientRoleRepository(t *testing.T, db store.Store) {
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	if err := db.Certificates().Create(ctx, store.CertificateRecord{
		Serial: "storetest-dd", Kind: store.CertKindLeaf, Subject: "CN=client",
		NotBefore: now, NotAfter: now.Add(time.Hour), PEM: []byte("client-pem"), CreatedAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	repo := db.ClientRoles()
	if err := repo.Assign(ctx, store.ClientRoleRecord{CertSerial: "storetest-dd", Role: store.RoleManager, CreatedAt: now}); err != nil {
		t.Fatalf("Assign: %v", err)
	}

	got, err := repo.Get(ctx, "storetest-dd")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Role != store.RoleManager {
		t.Errorf("Role = %q, want manager", got.Role)
	}

	// Assign is upsert-by-serial: reassigning to admin replaces the role.
	if err := repo.Assign(ctx, store.ClientRoleRecord{CertSerial: "storetest-dd", Role: store.RoleAdmin, CreatedAt: now}); err != nil {
		t.Fatalf("re-Assign: %v", err)
	}
	got, err = repo.Get(ctx, "storetest-dd")
	if err != nil {
		t.Fatalf("Get after re-Assign: %v", err)
	}
	if got.Role != store.RoleAdmin {
		t.Errorf("Role after re-Assign = %q, want admin", got.Role)
	}

	if _, err := repo.Get(ctx, "does-not-exist"); err != store.ErrNotFound {
		t.Errorf("Get(missing) error = %v, want ErrNotFound", err)
	}
}

func testAuditRepositoryAppendAndList(t *testing.T, db store.Store) {
	ctx := context.Background()
	repo := db.Audit()

	for i := 0; i < 3; i++ {
		if err := repo.Append(ctx, store.AuditEntry{
			Timestamp: time.Now().UTC(),
			Actor:     "storetest",
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
	if len(entries) < 3 {
		t.Fatalf("List returned %d entries, want at least 3", len(entries))
	}
	// Most recent first.
	if entries[0].ID < entries[1].ID {
		t.Errorf("List is not ordered most-recent-first: %+v", entries[:2])
	}

	limited, err := repo.List(ctx, 2)
	if err != nil {
		t.Fatalf("List(limit=2): %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("List(limit=2) returned %d entries, want 2", len(limited))
	}
}

func testACMERepositories(t *testing.T, db store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	eabRepo := db.ACMEEABTokens()
	eab := store.ACMEEABTokenRecord{
		KeyID:     "storetest-eab-1",
		HMACKey:   []byte("hmac-secret"),
		Role:      store.RoleManager,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := eabRepo.Create(ctx, eab); err != nil {
		t.Fatalf("ACMEEABTokens().Create: %v", err)
	}
	got, err := eabRepo.Get(ctx, eab.KeyID)
	if err != nil {
		t.Fatalf("ACMEEABTokens().Get: %v", err)
	}
	if got.Consumed || got.Role != store.RoleManager || string(got.HMACKey) != "hmac-secret" {
		t.Errorf("ACMEEABTokens().Get returned %+v", got)
	}
	if err := eabRepo.MarkConsumed(ctx, eab.KeyID, now); err != nil {
		t.Fatalf("ACMEEABTokens().MarkConsumed: %v", err)
	}
	got, err = eabRepo.Get(ctx, eab.KeyID)
	if err != nil {
		t.Fatalf("ACMEEABTokens().Get after consume: %v", err)
	}
	if !got.Consumed {
		t.Error("ACMEEABTokens().Get after MarkConsumed: Consumed = false, want true")
	}
	// MarkConsumed is the actual single-use gate (see its doc comment):
	// a second claim on the same token must fail distinctly from "not
	// found", since the token does exist -- it's just already spent.
	if err := eabRepo.MarkConsumed(ctx, eab.KeyID, now); err != store.ErrAlreadyConsumed {
		t.Errorf("second MarkConsumed error = %v, want ErrAlreadyConsumed", err)
	}
	if err := eabRepo.MarkConsumed(ctx, "storetest-eab-missing", now); err != store.ErrNotFound {
		t.Errorf("MarkConsumed(missing) error = %v, want ErrNotFound", err)
	}
	if _, err := eabRepo.Get(ctx, "storetest-eab-missing"); err != store.ErrNotFound {
		t.Errorf("Get(missing) error = %v, want ErrNotFound", err)
	}

	expiredEAB := store.ACMEEABTokenRecord{
		KeyID:     "storetest-eab-expired",
		HMACKey:   []byte("hmac-secret"),
		Role:      store.RoleManager,
		CreatedAt: now,
		ExpiresAt: now.Add(-time.Minute), // already expired
	}
	if err := eabRepo.Create(ctx, expiredEAB); err != nil {
		t.Fatalf("ACMEEABTokens().Create (expired): %v", err)
	}
	if err := eabRepo.MarkConsumed(ctx, expiredEAB.KeyID, now); err != store.ErrAlreadyConsumed {
		t.Errorf("MarkConsumed on an expired token error = %v, want ErrAlreadyConsumed", err)
	}

	acctRepo := db.ACMEAccounts()
	acct := store.ACMEAccountRecord{
		ID:            "storetest-acct-1",
		JWKThumbprint: "storetest-thumbprint-1",
		PublicKeyJWK:  []byte(`{"kty":"EC"}`),
		Role:          store.RoleManager,
		EABKeyID:      eab.KeyID,
		CreatedAt:     now,
	}
	if err := acctRepo.Create(ctx, acct); err != nil {
		t.Fatalf("ACMEAccounts().Create: %v", err)
	}
	byID, err := acctRepo.GetByID(ctx, acct.ID)
	if err != nil {
		t.Fatalf("ACMEAccounts().GetByID: %v", err)
	}
	if byID.JWKThumbprint != acct.JWKThumbprint {
		t.Errorf("GetByID returned %+v", byID)
	}
	byThumb, err := acctRepo.GetByThumbprint(ctx, acct.JWKThumbprint)
	if err != nil {
		t.Fatalf("ACMEAccounts().GetByThumbprint: %v", err)
	}
	if byThumb.ID != acct.ID {
		t.Errorf("GetByThumbprint returned %+v", byThumb)
	}
	if _, err := acctRepo.GetByThumbprint(ctx, "storetest-missing-thumbprint"); err != store.ErrNotFound {
		t.Errorf("GetByThumbprint(missing) error = %v, want ErrNotFound", err)
	}
	// Create is the actual single-account-per-key guarantee under a
	// concurrent-request race (see ACMEAccountRepository.Create's doc
	// comment): a second Create for the same thumbprint must fail
	// distinctly, not silently duplicate or generically error.
	if err := acctRepo.Create(ctx, store.ACMEAccountRecord{
		ID:            "storetest-acct-2",
		JWKThumbprint: acct.JWKThumbprint,
		PublicKeyJWK:  []byte(`{"kty":"EC"}`),
		Role:          store.RoleManager,
		EABKeyID:      eab.KeyID,
		CreatedAt:     now,
	}); err != store.ErrAlreadyExists {
		t.Errorf("Create with a duplicate thumbprint error = %v, want ErrAlreadyExists", err)
	}

	orderRepo := db.ACMEOrders()
	order := store.ACMEOrderRecord{
		ID:         "storetest-order-1",
		AccountID:  acct.ID,
		Identifier: "CN=storetest-client",
		Status:     store.ACMEOrderStatusReady,
		CreatedAt:  now,
	}
	if err := orderRepo.Create(ctx, order); err != nil {
		t.Fatalf("ACMEOrders().Create: %v", err)
	}
	gotOrder, err := orderRepo.Get(ctx, order.ID)
	if err != nil {
		t.Fatalf("ACMEOrders().Get: %v", err)
	}
	if gotOrder.Status != store.ACMEOrderStatusReady || gotOrder.CertSerial != "" {
		t.Errorf("ACMEOrders().Get returned %+v", gotOrder)
	}
	// A CAS against the wrong fromStatus must not apply -- this is the
	// actual claim guarantee handleACMEFinalize depends on to keep two
	// concurrent finalize calls from both issuing a certificate.
	applied, err := orderRepo.UpdateStatus(ctx, order.ID, store.ACMEOrderStatusProcessing, store.ACMEOrderStatusValid, "storetest-wrong-cas")
	if err != nil {
		t.Fatalf("ACMEOrders().UpdateStatus (wrong fromStatus): %v", err)
	}
	if applied {
		t.Error("UpdateStatus with the wrong fromStatus applied, want applied=false")
	}
	gotOrder, err = orderRepo.Get(ctx, order.ID)
	if err != nil {
		t.Fatalf("ACMEOrders().Get after rejected CAS: %v", err)
	}
	if gotOrder.Status != store.ACMEOrderStatusReady || gotOrder.CertSerial != "" {
		t.Errorf("order changed despite rejected CAS: %+v", gotOrder)
	}

	applied, err = orderRepo.UpdateStatus(ctx, order.ID, store.ACMEOrderStatusReady, store.ACMEOrderStatusValid, "storetest-cert-serial")
	if err != nil {
		t.Fatalf("ACMEOrders().UpdateStatus: %v", err)
	}
	if !applied {
		t.Error("UpdateStatus with the correct fromStatus did not apply")
	}
	gotOrder, err = orderRepo.Get(ctx, order.ID)
	if err != nil {
		t.Fatalf("ACMEOrders().Get after update: %v", err)
	}
	if gotOrder.Status != store.ACMEOrderStatusValid || gotOrder.CertSerial != "storetest-cert-serial" {
		t.Errorf("ACMEOrders().Get after UpdateStatus returned %+v", gotOrder)
	}
	if _, err := orderRepo.UpdateStatus(ctx, "storetest-order-missing", store.ACMEOrderStatusReady, store.ACMEOrderStatusValid, ""); err != store.ErrNotFound {
		t.Errorf("UpdateStatus(missing) error = %v, want ErrNotFound", err)
	}

	nonceRepo := db.ACMENonces()
	nonce, err := nonceRepo.Issue(ctx, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("ACMENonces().Issue: %v", err)
	}
	if nonce == "" {
		t.Fatal("ACMENonces().Issue returned an empty nonce")
	}
	ok, err := nonceRepo.ConsumeIfValid(ctx, nonce, now)
	if err != nil {
		t.Fatalf("ACMENonces().ConsumeIfValid: %v", err)
	}
	if !ok {
		t.Error("ConsumeIfValid on a freshly issued nonce = false, want true")
	}
	// A nonce is single-use: consuming it again must fail.
	ok, err = nonceRepo.ConsumeIfValid(ctx, nonce, now)
	if err != nil {
		t.Fatalf("second ACMENonces().ConsumeIfValid: %v", err)
	}
	if ok {
		t.Error("ConsumeIfValid on an already-consumed nonce = true, want false")
	}

	expired, err := nonceRepo.Issue(ctx, now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("ACMENonces().Issue (expired): %v", err)
	}
	ok, err = nonceRepo.ConsumeIfValid(ctx, expired, now)
	if err != nil {
		t.Fatalf("ACMENonces().ConsumeIfValid (expired): %v", err)
	}
	if ok {
		t.Error("ConsumeIfValid on an expired nonce = true, want false")
	}
}
