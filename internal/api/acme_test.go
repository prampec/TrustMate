package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/prampec/trustmate/internal/acme"
	"github.com/prampec/trustmate/internal/store"
)

// acmeTestClient is a minimal, from-scratch ACME client used only to
// exercise the server against a real implementation of the wire
// protocol (JWS signing, EAB binding, nonce chaining) rather than
// testing handlers in isolation. Mirrors what a real ACME client
// library (certbot, lego, acme.sh) would do, scoped to what
// TestACMEEnrollmentEndToEnd needs.
type acmeTestClient struct {
	t          *testing.T
	router     http.Handler
	accountKey *ecdsa.PrivateKey
	jwk        []byte // canonical JWK for accountKey.Public(), reused verbatim in EAB payload and outer header
	kid        string // set once new-account succeeds
	nonce      string
}

func newACMETestClient(t *testing.T, router http.Handler) *acmeTestClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := acme.PublicKeyToJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &acmeTestClient{t: t, router: router, accountKey: key, jwk: jwk}
}

func (c *acmeTestClient) fetchNonce() {
	c.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/acme/new-nonce", nil)
	rec := httptest.NewRecorder()
	c.router.ServeHTTP(rec, req)
	nonce := rec.Header().Get("Replay-Nonce")
	if nonce == "" {
		c.t.Fatal("new-nonce did not return a Replay-Nonce header")
	}
	c.nonce = nonce
}

// sign builds a flattened-JSON ES256 JWS over payload, using c.kid if
// set (an existing account) or c.jwk otherwise (new-account, which
// carries the account's own key rather than referencing one).
func (c *acmeTestClient) sign(url string, payload []byte) []byte {
	c.t.Helper()
	header := map[string]any{"alg": "ES256", "nonce": c.nonce, "url": url}
	if c.kid != "" {
		header["kid"] = c.kid
	} else {
		header["jwk"] = json.RawMessage(c.jwk)
	}
	return signFlattenedJWS(c.t, header, payload, func(signingInput []byte) []byte {
		digest := sha256.Sum256(signingInput)
		r, s, err := ecdsa.Sign(rand.Reader, c.accountKey, digest[:])
		if err != nil {
			c.t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig
	})
}

// post signs payload for url, POSTs it to path, consumes the response's
// Replay-Nonce for the next call, and returns the decoded response
// (fatal on a non-2xx status).
func (c *acmeTestClient) post(url, path string, payload []byte) (*httptest.ResponseRecorder, map[string]any) {
	c.t.Helper()
	if c.nonce == "" {
		c.fetchNonce()
	}
	body := c.sign(url, payload)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/jose+json")
	rec := httptest.NewRecorder()
	c.router.ServeHTTP(rec, req)
	if nonce := rec.Header().Get("Replay-Nonce"); nonce != "" {
		c.nonce = nonce
	}
	if rec.Code < 200 || rec.Code >= 300 {
		c.t.Fatalf("POST %s: status %d, body %s", path, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if rec.Body.Len() > 0 && strings.Contains(rec.Header().Get("Content-Type"), "json") {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			c.t.Fatalf("decoding response: %v", err)
		}
	}
	return rec, out
}

func signFlattenedJWS(t *testing.T, header map[string]any, payload []byte, sign func([]byte) []byte) []byte {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding
	protected := b64.EncodeToString(headerJSON)
	payloadB64 := b64.EncodeToString(payload)
	signingInput := []byte(protected + "." + payloadB64)
	sig := sign(signingInput)

	out, err := json.Marshal(map[string]string{
		"protected": protected,
		"payload":   payloadB64,
		"signature": b64.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func genCSRDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// issueTestEABToken calls the admin-only enrollment-start endpoint and
// returns the key id and raw (decoded) HMAC key.
func issueTestEABToken(t *testing.T, deps Deps, router http.Handler, role store.ClientRole) (keyID string, hmacKey []byte) {
	t.Helper()
	rec := postJSON(t, router, "/v1/acme/eab-tokens", issueEABTokenRequest{Role: string(role)}, adminCert(t, deps))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/acme/eab-tokens: status %d, body %s", rec.Code, rec.Body.String())
	}
	var resp issueEABTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	key, err := base64.RawURLEncoding.DecodeString(resp.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	return resp.KeyID, key
}

// newAccount drives RFC 8555 section 7.3 end to end, including the
// External Account Binding inner JWS, and records the resulting account
// URL as c.kid for subsequent requests.
func (c *acmeTestClient) newAccount(deps Deps, eabKeyID string, eabHMACKey []byte) {
	c.t.Helper()
	newAccountURL := acmeURL(deps, "new-account")

	eabBody := signFlattenedJWS(c.t, map[string]any{
		"alg": "HS256",
		"kid": eabKeyID,
		"url": newAccountURL,
	}, c.jwk, func(signingInput []byte) []byte {
		mac := hmac.New(sha256.New, eabHMACKey)
		mac.Write(signingInput)
		return mac.Sum(nil)
	})

	payload, err := json.Marshal(map[string]any{
		"termsOfServiceAgreed":   true,
		"externalAccountBinding": json.RawMessage(eabBody),
	})
	if err != nil {
		c.t.Fatal(err)
	}

	rec, _ := c.post(newAccountURL, "/v1/acme/new-account", payload)
	loc := rec.Header().Get("Location")
	if loc == "" {
		c.t.Fatal("new-account response has no Location header")
	}
	c.kid = loc
}

func TestACMEEnrollmentEndToEnd(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableACME: true})
	router := NewRouter(deps, nil)

	eabKeyID, eabHMACKey := issueTestEABToken(t, deps, router, store.RoleManager)

	client := newACMETestClient(t, router)
	client.newAccount(deps, eabKeyID, eabHMACKey)

	newOrderURL := acmeURL(deps, "new-order")
	orderPayload, err := json.Marshal(map[string]any{
		"identifiers": []acmeIdentifier{{Type: acmeIdentifierType, Value: "acme-test-client"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	orderRec, orderResp := client.post(newOrderURL, "/v1/acme/new-order", orderPayload)
	if orderResp["status"] != "ready" {
		t.Fatalf("new-order status = %v, want ready", orderResp["status"])
	}
	orderLoc := orderRec.Header().Get("Location")
	if orderLoc == "" {
		t.Fatal("new-order response has no Location header")
	}
	orderID := orderLoc[strings.LastIndex(orderLoc, "/")+1:]
	finalizeURL := acmeURL(deps, "order/"+orderID+"/finalize")
	finalizePath := "/v1/acme/order/" + orderID + "/finalize"

	// GET the synthesized authorization -- clients that walk
	// order.authorizations before finalizing must see it as already
	// valid (see this package's acme.go doc comment).
	authzReq := httptest.NewRequest(http.MethodGet, "/v1/acme/authorization/"+orderID, nil)
	authzRec := httptest.NewRecorder()
	router.ServeHTTP(authzRec, authzReq)
	var authz map[string]any
	if err := json.Unmarshal(authzRec.Body.Bytes(), &authz); err != nil {
		t.Fatal(err)
	}
	if authz["status"] != "valid" {
		t.Fatalf("authorization status = %v, want valid", authz["status"])
	}

	csrDER := genCSRDER(t, "acme-test-client")
	finalizePayload, err := json.Marshal(map[string]string{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, finalizeResp := client.post(finalizeURL, finalizePath, finalizePayload)
	if finalizeResp["status"] != "valid" {
		t.Fatalf("finalize response status = %v, want valid", finalizeResp["status"])
	}
	certURL, _ := finalizeResp["certificate"].(string)
	if certURL == "" {
		t.Fatal("finalize response has no certificate URL")
	}

	certPath := "/v1/acme/certificate/" + orderID
	certReq := httptest.NewRequest(http.MethodGet, certPath, nil)
	certRec := httptest.NewRecorder()
	router.ServeHTTP(certRec, certReq)
	if certRec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d", certPath, certRec.Code)
	}
	if ct := certRec.Header().Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Errorf("certificate Content-Type = %q, want application/pem-certificate-chain", ct)
	}
	if !bytes.Contains(certRec.Body.Bytes(), []byte("BEGIN CERTIFICATE")) {
		t.Fatal("certificate response does not contain a PEM certificate")
	}

	// The issued certificate must carry the role the EAB token was
	// bound to (manager), proving finalize threaded EABToken.Role
	// through Account.Role to the certificate's client_roles entry.
	roles, err := deps.Store.ClientRoles().List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range roles {
		if r.Role == store.RoleManager {
			cert, err := deps.Store.Certificates().GetBySerial(t.Context(), r.CertSerial)
			if err != nil {
				t.Fatal(err)
			}
			if cert.Subject == "CN=acme-test-client" {
				found = true
			}
		}
	}
	if !found {
		t.Error("no manager-role certificate with subject CN=acme-test-client found in client_roles")
	}
}

func TestACMENewAccountRejectsReusedNonce(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableACME: true})
	router := NewRouter(deps, nil)
	eabKeyID, eabHMACKey := issueTestEABToken(t, deps, router, store.RoleManager)

	client := newACMETestClient(t, router)
	client.fetchNonce()
	reusedNonce := client.nonce

	newAccountURL := acmeURL(deps, "new-account")
	eabBody := signFlattenedJWS(t, map[string]any{"alg": "HS256", "kid": eabKeyID, "url": newAccountURL}, client.jwk, func(signingInput []byte) []byte {
		mac := hmac.New(sha256.New, eabHMACKey)
		mac.Write(signingInput)
		return mac.Sum(nil)
	})
	payload, err := json.Marshal(map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": json.RawMessage(eabBody)})
	if err != nil {
		t.Fatal(err)
	}

	body := client.sign(newAccountURL, payload)
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/acme/new-account", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	first := post()
	if first.Code != http.StatusCreated {
		t.Fatalf("first new-account: status %d, body %s", first.Code, first.Body.String())
	}

	client.nonce = reusedNonce
	body = client.sign(newAccountURL, payload) // re-sign with the same (already-consumed) nonce
	second := post()
	if second.Code != http.StatusBadRequest {
		t.Fatalf("new-account with a reused nonce: status %d, want 400", second.Code)
	}
}

func TestACMENewAccountRejectsWrongEABKey(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableACME: true})
	router := NewRouter(deps, nil)
	eabKeyID, _ := issueTestEABToken(t, deps, router, store.RoleManager)
	wrongKey := []byte("not-the-right-hmac-key-at-all!!")

	client := newACMETestClient(t, router)
	client.fetchNonce()
	newAccountURL := acmeURL(deps, "new-account")
	eabBody := signFlattenedJWS(t, map[string]any{"alg": "HS256", "kid": eabKeyID, "url": newAccountURL}, client.jwk, func(signingInput []byte) []byte {
		mac := hmac.New(sha256.New, wrongKey)
		mac.Write(signingInput)
		return mac.Sum(nil)
	})
	payload, err := json.Marshal(map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": json.RawMessage(eabBody)})
	if err != nil {
		t.Fatal(err)
	}
	body := client.sign(newAccountURL, payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/acme/new-account", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("new-account with wrong EAB HMAC key: status %d, want 401, body %s", rec.Code, rec.Body.String())
	}
}

// TestACMENewAccountEABSingleUseUnderConcurrency is the regression test
// for the race a code review caught: ACMEEABTokenRepository.MarkConsumed
// must be the atomic single-use gate, not a best-effort bookkeeping
// update performed after account creation. Many concurrent new-account
// requests presenting the same EAB token (each from its own account
// key) must yield exactly one successful account, not one per goroutine.
func TestACMENewAccountEABSingleUseUnderConcurrency(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableACME: true})
	router := NewRouter(deps, nil)
	eabKeyID, eabHMACKey := issueTestEABToken(t, deps, router, store.RoleManager)
	newAccountURL := acmeURL(deps, "new-account")

	const attempts = 8
	var wg sync.WaitGroup
	var successCount int32
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := newACMETestClient(t, router)
			client.fetchNonce()

			eabBody := signFlattenedJWS(t, map[string]any{"alg": "HS256", "kid": eabKeyID, "url": newAccountURL}, client.jwk, func(signingInput []byte) []byte {
				mac := hmac.New(sha256.New, eabHMACKey)
				mac.Write(signingInput)
				return mac.Sum(nil)
			})
			payload, err := json.Marshal(map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": json.RawMessage(eabBody)})
			if err != nil {
				t.Error(err)
				return
			}
			body := client.sign(newAccountURL, payload)
			req := httptest.NewRequest(http.MethodPost, "/v1/acme/new-account", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code == http.StatusCreated {
				atomic.AddInt32(&successCount, 1)
			} else if rec.Code != http.StatusUnauthorized {
				t.Errorf("unexpected status %d, body %s", rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Errorf("successful new-account count under concurrent single-use EAB redemption = %d, want exactly 1", successCount)
	}
}

// TestACMENewAccountSameKeyDifferentEABTokensUnderConcurrency is the
// regression test for the race a code review caught: the GetByThumbprint
// idempotency check in handleACMENewAccount runs before either request's
// Create has committed, so two concurrent new-account requests for the
// same account key -- each carrying its own, independently valid EAB
// token -- can both pass that check and both attempt to create an
// account. Exactly one must win; every other request must come back with
// the winner's account (RFC 8555 section 7.3.1 idempotency), never a
// 500.
func TestACMENewAccountSameKeyDifferentEABTokensUnderConcurrency(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableACME: true})
	router := NewRouter(deps, nil)
	newAccountURL := acmeURL(deps, "new-account")

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := acme.PublicKeyToJWK(&accountKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 8
	type result struct {
		code     int
		location string
	}
	results := make([]result, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		eabKeyID, eabHMACKey := issueTestEABToken(t, deps, router, store.RoleManager)
		wg.Add(1)
		go func(i int, eabKeyID string, eabHMACKey []byte) {
			defer wg.Done()

			nonceReq := httptest.NewRequest(http.MethodGet, "/v1/acme/new-nonce", nil)
			nonceRec := httptest.NewRecorder()
			router.ServeHTTP(nonceRec, nonceReq)
			nonce := nonceRec.Header().Get("Replay-Nonce")

			eabBody := signFlattenedJWS(t, map[string]any{"alg": "HS256", "kid": eabKeyID, "url": newAccountURL}, jwk, func(signingInput []byte) []byte {
				mac := hmac.New(sha256.New, eabHMACKey)
				mac.Write(signingInput)
				return mac.Sum(nil)
			})
			payload, err := json.Marshal(map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": json.RawMessage(eabBody)})
			if err != nil {
				t.Error(err)
				return
			}
			header := map[string]any{"alg": "ES256", "nonce": nonce, "url": newAccountURL, "jwk": json.RawMessage(jwk)}
			body := signFlattenedJWS(t, header, payload, func(signingInput []byte) []byte {
				digest := sha256.Sum256(signingInput)
				r, s, err := ecdsa.Sign(rand.Reader, accountKey, digest[:])
				if err != nil {
					t.Error(err)
					return nil
				}
				sig := make([]byte, 64)
				r.FillBytes(sig[:32])
				s.FillBytes(sig[32:])
				return sig
			})

			req := httptest.NewRequest(http.MethodPost, "/v1/acme/new-account", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			results[i] = result{code: rec.Code, location: rec.Header().Get("Location")}
		}(i, eabKeyID, eabHMACKey)
	}
	wg.Wait()

	locations := map[string]bool{}
	for i, r := range results {
		if r.code != http.StatusCreated && r.code != http.StatusOK {
			t.Errorf("attempt %d: status %d, want 201 (won the race) or 200 (idempotent), body/location %+v", i, r.code, r)
			continue
		}
		if r.location == "" {
			t.Errorf("attempt %d: no Location header", i)
			continue
		}
		locations[r.location] = true
	}
	if len(locations) != 1 {
		t.Errorf("distinct account Location headers returned across %d concurrent requests for the same key = %d (%v), want exactly 1", attempts, len(locations), locations)
	}
}

// TestACMEFinalizeSingleIssuanceUnderConcurrency is the regression test
// for the race a code review caught: handleACMEFinalize's order-claiming
// step used to be a plain read-then-write Update, which let two
// concurrent finalize calls for the same order (e.g. a client retry
// racing the original) both observe status "ready" and both issue a
// certificate. UpdateStatus's compare-and-swap must let only one claim
// win, so no matter how the responses land (some finalize outright, some
// hit the idempotent-retry "already valid" branch, some lose the claim
// with orderNotReady), exactly one certificate must ever get issued for
// the order.
func TestACMEFinalizeSingleIssuanceUnderConcurrency(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableACME: true})
	router := NewRouter(deps, nil)

	eabKeyID, eabHMACKey := issueTestEABToken(t, deps, router, store.RoleManager)
	client := newACMETestClient(t, router)
	client.newAccount(deps, eabKeyID, eabHMACKey)

	newOrderURL := acmeURL(deps, "new-order")
	orderPayload, err := json.Marshal(map[string]any{
		"identifiers": []acmeIdentifier{{Type: acmeIdentifierType, Value: "acme-finalize-race-client"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	orderRec, _ := client.post(newOrderURL, "/v1/acme/new-order", orderPayload)
	orderLoc := orderRec.Header().Get("Location")
	orderID := orderLoc[strings.LastIndex(orderLoc, "/")+1:]
	finalizeURL := acmeURL(deps, "order/"+orderID+"/finalize")
	finalizePath := "/v1/acme/order/" + orderID + "/finalize"

	csrDER := genCSRDER(t, "acme-finalize-race-client")
	finalizePayload, err := json.Marshal(map[string]string{"csr": base64.RawURLEncoding.EncodeToString(csrDER)})
	if err != nil {
		t.Fatal(err)
	}

	// Pre-sign every attempt's request body (each with its own fresh
	// nonce) before spawning goroutines, so the race is purely between
	// the server's concurrent handling of otherwise-identical finalize
	// requests, not test-side request construction.
	const attempts = 8
	bodies := make([][]byte, attempts)
	for i := range bodies {
		nonceReq := httptest.NewRequest(http.MethodGet, "/v1/acme/new-nonce", nil)
		nonceRec := httptest.NewRecorder()
		router.ServeHTTP(nonceRec, nonceReq)
		nonce := nonceRec.Header().Get("Replay-Nonce")

		header := map[string]any{"alg": "ES256", "nonce": nonce, "url": finalizeURL, "kid": client.kid}
		bodies[i] = signFlattenedJWS(t, header, finalizePayload, func(signingInput []byte) []byte {
			digest := sha256.Sum256(signingInput)
			r, s, err := ecdsa.Sign(rand.Reader, client.accountKey, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			sig := make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
			return sig
		})
	}

	results := make([]int, attempts)
	var wg sync.WaitGroup
	for i, body := range bodies {
		wg.Add(1)
		go func(i int, body []byte) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, finalizePath, bytes.NewReader(body))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			results[i] = rec.Code
		}(i, body)
	}
	wg.Wait()

	for i, code := range results {
		// 200: finalized outright, or hit the idempotent "already valid"
		// retry branch. 403 (orderNotReady): lost the claim race, or saw
		// the order mid-"processing". Anything else (a 500, in
		// particular) is the bug this test guards against.
		if code != http.StatusOK && code != http.StatusForbidden {
			t.Errorf("attempt %d: status %d, want 200 or 403", i, code)
		}
	}

	certs, err := deps.Store.Certificates().FindByKind(t.Context(), store.CertKindLeaf)
	if err != nil {
		t.Fatal(err)
	}
	issued := 0
	for _, c := range certs {
		if c.Subject == "CN=acme-finalize-race-client" {
			issued++
		}
	}
	if issued != 1 {
		t.Errorf("certificates issued for the order raced by %d concurrent finalize calls = %d, want exactly 1", attempts, issued)
	}
}

func TestACMEDirectory(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableACME: true})
	router := NewRouter(deps, nil)

	rec := getAs(t, router, "/v1/acme/directory", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var dir map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &dir); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"newNonce", "newAccount", "newOrder"} {
		if _, ok := dir[key]; !ok {
			t.Errorf("directory missing %q", key)
		}
	}
}

func TestACMEModuleDisabledByDefault(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)
	rec := getAs(t, router, "/v1/acme/directory", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /v1/acme/directory with ACME disabled: status %d, want 404", rec.Code)
	}
}
