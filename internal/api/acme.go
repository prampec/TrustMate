// ACME (RFC 8555) handlers: automated certificate enrollment via
// External Account Binding rather than domain-validated http-01/dns-01
// challenges. TrustMate's certificates are role-bound API-access client
// certs (see store.ClientRole), not domain-validated web certs, so an
// admin vouching for a requester out-of-band (the same trust boundary
// POST /v1/clients already uses) is what "authorization" means here --
// ACME automates the *mechanics* of enrollment/renewal on top of that,
// not a new authorization decision. See internal/acme for the
// underlying JWS/JWK primitives and docs/design.md's Phase 5 roadmap
// entry.
//
// Deliberate deviations from strict RFC 8555 conformance, given TrustMate
// has no domain-validation concept to anchor the usual authorization
// flow to:
//   - Orders skip "pending": EAB already proved authorization when the
//     account was created, so an order is "ready" (no challenges to
//     complete) the instant it's created.
//   - Order identifiers use a custom "trustmate-client" type (RFC 8555
//     allows extensible identifier types) whose value is the requested
//     certificate's subject common name.
//   - GET /v1/acme/order/{id}, GET /v1/acme/authorization/{id}, and
//     GET /v1/acme/certificate/{id} are plain, unauthenticated GETs
//     rather than RFC 8555's POST-as-GET -- these only ever return
//     already-public-once-issued information (an order's status, or a
//     certificate that's also servable via GET /v1/certificates/{serial}
//     once issued), so the extra request-signing round trip buys nothing
//     here.
package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/prampec/trustmate/internal/acme"
	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/store"
)

const (
	acmeNonceTTL       = 5 * time.Minute
	acmeEABTokenTTL    = 24 * time.Hour
	acmeOrderExpiresIn = 24 * time.Hour // informational only, in the "expires" field
)

func acmeURL(deps Deps, path string) string {
	return deps.PublicBaseURL + "/v1/acme/" + path
}

// issueAndAttachNonce sets the Replay-Nonce header every ACME response
// (success or error) must carry, per RFC 8555 section 6.5.1.
func issueAndAttachNonce(ctx context.Context, w http.ResponseWriter, deps Deps) {
	nonce, err := deps.Store.ACMENonces().Issue(ctx, time.Now().Add(acmeNonceTTL))
	if err != nil {
		return // best-effort: an issuance failure here shouldn't mask the real response
	}
	w.Header().Set("Replay-Nonce", nonce)
}

// acmeProblem writes an RFC 8555 section 6.7 problem+json error body.
// problemType is suffixed onto the standard "urn:ietf:params:acme:error:"
// prefix (e.g. "badNonce", "malformed", "unauthorized").
func acmeProblem(ctx context.Context, w http.ResponseWriter, deps Deps, status int, problemType, detail string) {
	issueAndAttachNonce(ctx, w, deps)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"type":   "urn:ietf:params:acme:error:" + problemType,
		"detail": detail,
	})
}

func randomACMEID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("acme: generating id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// handleACMEDirectory serves RFC 8555 section 7.1.1's directory object,
// the entry point every ACME client fetches first.
func handleACMEDirectory(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"newNonce":   acmeURL(deps, "new-nonce"),
			"newAccount": acmeURL(deps, "new-account"),
			"newOrder":   acmeURL(deps, "new-order"),
			"meta": map[string]any{
				"externalAccountRequired": true,
			},
		})
	}
}

func handleACMENewNonce(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := deps.Store.ACMENonces().Issue(r.Context(), time.Now().Add(acmeNonceTTL))
		if err != nil {
			deps.Logger.Error("issuing acme nonce failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.Header().Set("Replay-Nonce", nonce)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, errors.New("empty body")
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("empty body")
	}
	return data, nil
}

// verifiedJWS parses body as a flattened JWS, consumes and validates its
// nonce, and checks its header's "url" field matches expectedURL (RFC
// 8555 section 6.4's anti-replay-across-endpoints binding). It does not
// verify the signature -- callers do that once they've resolved which
// key the request claims to be signed by (a fresh "jwk", for
// new-account, or a "kid" naming an existing account).
func verifiedJWS(r *http.Request, w http.ResponseWriter, deps Deps, expectedURL string) (*acme.JWS, bool) {
	body, err := readBody(r)
	if err != nil {
		acmeProblem(r.Context(), w, deps, http.StatusBadRequest, "malformed", "reading request body")
		return nil, false
	}
	jws, err := acme.ParseJWS(body)
	if err != nil {
		acmeProblem(r.Context(), w, deps, http.StatusBadRequest, "malformed", err.Error())
		return nil, false
	}
	ok, err := deps.Store.ACMENonces().ConsumeIfValid(r.Context(), jws.Header.Nonce, time.Now())
	if err != nil {
		deps.Logger.Error("consuming acme nonce failed", "err", err)
		acmeProblem(r.Context(), w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
		return nil, false
	}
	if !ok {
		acmeProblem(r.Context(), w, deps, http.StatusBadRequest, "badNonce", "invalid, reused, or expired nonce")
		return nil, false
	}
	if jws.Header.URL != expectedURL {
		acmeProblem(r.Context(), w, deps, http.StatusBadRequest, "malformed", "JWS url header does not match the request URL")
		return nil, false
	}
	return jws, true
}

type acmeNewAccountPayload struct {
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
}

func acmeAccountResponse() map[string]any {
	return map[string]any{
		"status":               "valid",
		"contact":              []string{},
		"termsOfServiceAgreed": true,
	}
}

// handleACMENewAccount implements RFC 8555 section 7.3: a fresh account
// key signs the outer JWS (carrying its own "jwk", since no account
// exists yet to reference by "kid"), and section 7.3.4's External
// Account Binding -- an inner HS256 JWS, signed with an admin-issued
// one-time HMAC key, whose payload is the same outer JWK -- stands in
// for domain validation as this server's authorization check.
func handleACMENewAccount(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		jws, ok := verifiedJWS(r, w, deps, acmeURL(deps, "new-account"))
		if !ok {
			return
		}
		if len(jws.Header.JWK) == 0 {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "malformed", "new-account JWS must carry a jwk header (fresh account key, not kid)")
			return
		}
		accountPub, err := acme.JWKPublicKey(jws.Header.JWK)
		if err != nil {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "malformed", err.Error())
			return
		}
		if err := jws.Verify(accountPub); err != nil {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		var payload acmeNewAccountPayload
		if err := json.Unmarshal(jws.Payload, &payload); err != nil {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "malformed", "decoding new-account payload: "+err.Error())
			return
		}
		if len(payload.ExternalAccountBinding) == 0 {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "externalAccountRequired", "externalAccountBinding is required")
			return
		}

		thumbprint, err := acme.Thumbprint(accountPub)
		if err != nil {
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}

		// Idempotency: RFC 8555 section 7.3.1 -- retrying new-account
		// with an already-registered key returns the existing account.
		if existing, err := deps.Store.ACMEAccounts().GetByThumbprint(ctx, thumbprint); err == nil {
			w.Header().Set("Location", acmeURL(deps, "account/"+existing.ID))
			issueAndAttachNonce(ctx, w, deps)
			writeJSON(w, http.StatusOK, acmeAccountResponse())
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			deps.Logger.Error("looking up acme account failed", "err", err)
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}

		eabJWS, err := acme.ParseJWS(payload.ExternalAccountBinding)
		if err != nil {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "malformed", "parsing externalAccountBinding: "+err.Error())
			return
		}
		if eabJWS.Header.URL != jws.Header.URL {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "malformed", "externalAccountBinding url does not match the outer JWS")
			return
		}
		// RFC 8555 section 7.3.4: the EAB payload must be exactly the
		// outer JWS's jwk, byte for byte.
		if string(eabJWS.Payload) != string(jws.Header.JWK) {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "malformed", "externalAccountBinding payload does not match the account jwk")
			return
		}

		eabToken, err := deps.Store.ACMEEABTokens().Get(ctx, eabJWS.Header.Kid)
		if errors.Is(err, store.ErrNotFound) {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "unauthorized", "unknown externalAccountBinding key id")
			return
		}
		if err != nil {
			deps.Logger.Error("looking up acme eab token failed", "err", err)
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}
		if eabToken.Consumed {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "unauthorized", "externalAccountBinding key has already been used")
			return
		}
		if time.Now().After(eabToken.ExpiresAt) {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "unauthorized", "externalAccountBinding key has expired")
			return
		}
		if err := eabJWS.VerifyHMAC(eabToken.HMACKey); err != nil {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		// Atomically claim the token -- this, not the Consumed/expiry
		// checks above, is the actual single-use guarantee. Those
		// earlier checks are only a fast-fail optimization (skip HMAC
		// verification for an obviously-spent token); without this
		// claim gating account creation, two concurrent requests
		// presenting the same token could both pass every check above
		// and both create an account. See ACMEEABTokenRepository.MarkConsumed's
		// doc comment.
		now := time.Now().UTC()
		if err := deps.Store.ACMEEABTokens().MarkConsumed(ctx, eabToken.KeyID, now); err != nil {
			if errors.Is(err, store.ErrAlreadyConsumed) {
				acmeProblem(ctx, w, deps, http.StatusUnauthorized, "unauthorized", "externalAccountBinding key has already been used or has expired")
				return
			}
			deps.Logger.Error("claiming acme eab token failed", "err", err)
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}

		id, err := randomACMEID()
		if err != nil {
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}
		account := store.ACMEAccountRecord{
			ID:            id,
			JWKThumbprint: thumbprint,
			PublicKeyJWK:  jws.Header.JWK,
			Role:          eabToken.Role,
			EABKeyID:      eabToken.KeyID,
			CreatedAt:     now,
		}
		if err := deps.Store.ACMEAccounts().Create(ctx, account); err != nil {
			if errors.Is(err, store.ErrAlreadyExists) {
				// Lost a race with a concurrent new-account request for
				// the same account key (the GetByThumbprint idempotency
				// check above ran before either request had created
				// anything). Per RFC 8555 section 7.3.1, hand back the
				// account that won rather than erroring -- this request's
				// own EAB token was still legitimately consumed above; it
				// just isn't the one this account ended up tied to.
				existing, err := deps.Store.ACMEAccounts().GetByThumbprint(ctx, thumbprint)
				if err != nil {
					deps.Logger.Error("acme new-account: recovering from concurrent create race failed", "err", err)
					acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
					return
				}
				w.Header().Set("Location", acmeURL(deps, "account/"+existing.ID))
				issueAndAttachNonce(ctx, w, deps)
				writeJSON(w, http.StatusOK, acmeAccountResponse())
				return
			}
			deps.Logger.Error("creating acme account failed", "err", err)
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}
		if err := deps.Store.Audit().Append(ctx, store.AuditEntry{
			Timestamp: now,
			Actor:     r.RemoteAddr,
			Action:    "acme-new-account",
			Target:    account.ID,
			Detail:    string(eabToken.Role),
		}); err != nil {
			deps.Logger.Error("writing audit entry failed", "err", err)
		}
		if deps.Metrics != nil {
			deps.Metrics.ACMEAccountsTotal.Inc()
		}

		w.Header().Set("Location", acmeURL(deps, "account/"+account.ID))
		issueAndAttachNonce(ctx, w, deps)
		writeJSON(w, http.StatusCreated, acmeAccountResponse())
	}
}

// resolveACMEAccount validates jws against the account named by its
// "kid" header (an account URL, .../v1/acme/account/{id}), the
// authentication method RFC 8555 uses for every request after
// new-account.
func resolveACMEAccount(ctx context.Context, deps Deps, jws *acme.JWS) (store.ACMEAccountRecord, error) {
	prefix := acmeURL(deps, "account/")
	if !strings.HasPrefix(jws.Header.Kid, prefix) {
		return store.ACMEAccountRecord{}, fmt.Errorf("kid does not identify an account")
	}
	id := strings.TrimPrefix(jws.Header.Kid, prefix)
	account, err := deps.Store.ACMEAccounts().GetByID(ctx, id)
	if err != nil {
		return store.ACMEAccountRecord{}, err
	}
	pub, err := acme.JWKPublicKey(account.PublicKeyJWK)
	if err != nil {
		return store.ACMEAccountRecord{}, err
	}
	if err := jws.Verify(pub); err != nil {
		return store.ACMEAccountRecord{}, err
	}
	return account, nil
}

type acmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type acmeNewOrderPayload struct {
	Identifiers []acmeIdentifier `json:"identifiers"`
}

// acmeIdentifierType is TrustMate's custom ACME identifier type (RFC
// 8555 permits identifier types beyond "dns") -- its value is the
// requested certificate's subject common name, since these are
// role-bound client-access certs, not domain-validated ones.
const acmeIdentifierType = "trustmate-client"

func handleACMENewOrder(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		jws, ok := verifiedJWS(r, w, deps, acmeURL(deps, "new-order"))
		if !ok {
			return
		}
		account, err := resolveACMEAccount(ctx, deps, jws)
		if errors.Is(err, store.ErrNotFound) {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "accountDoesNotExist", "unknown account")
			return
		}
		if err != nil {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		var payload acmeNewOrderPayload
		if err := json.Unmarshal(jws.Payload, &payload); err != nil {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "malformed", "decoding new-order payload: "+err.Error())
			return
		}
		if len(payload.Identifiers) != 1 || payload.Identifiers[0].Type != acmeIdentifierType || payload.Identifiers[0].Value == "" {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "malformed", fmt.Sprintf("exactly one identifier of type %q with a non-empty value is required", acmeIdentifierType))
			return
		}

		id, err := randomACMEID()
		if err != nil {
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}
		order := store.ACMEOrderRecord{
			ID:         id,
			AccountID:  account.ID,
			Identifier: payload.Identifiers[0].Value,
			// "ready", not "pending": the EAB token that created this
			// account already proved authorization -- see this file's
			// package doc comment.
			Status:    store.ACMEOrderStatusReady,
			CreatedAt: time.Now().UTC(),
		}
		if err := deps.Store.ACMEOrders().Create(ctx, order); err != nil {
			deps.Logger.Error("creating acme order failed", "err", err)
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}
		if deps.Metrics != nil {
			deps.Metrics.ACMEOrdersTotal.WithLabelValues("created").Inc()
		}

		w.Header().Set("Location", acmeURL(deps, "order/"+order.ID))
		issueAndAttachNonce(ctx, w, deps)
		writeJSON(w, http.StatusCreated, acmeOrderResponse(deps, order))
	}
}

func acmeOrderResponse(deps Deps, order store.ACMEOrderRecord) map[string]any {
	resp := map[string]any{
		"status":         order.Status,
		"expires":        order.CreatedAt.Add(acmeOrderExpiresIn).Format(time.RFC3339),
		"identifiers":    []acmeIdentifier{{Type: acmeIdentifierType, Value: order.Identifier}},
		"authorizations": []string{acmeURL(deps, "authorization/"+order.ID)},
		"finalize":       acmeURL(deps, "order/"+order.ID+"/finalize"),
	}
	if order.Status == store.ACMEOrderStatusValid {
		resp["certificate"] = acmeURL(deps, "certificate/"+order.ID)
	}
	return resp
}

// getOrderOr404 looks up the ACME order named by id, translating store
// errors the way every handler below needs: ErrNotFound becomes a 404
// ACME problem document, any other error is logged and becomes a 500.
// notFoundDetail lets callers say "order" or "authorization" in that
// response, since handleACMEGetAuthorization shares this same order
// lookup underneath its authorization framing.
func getOrderOr404(w http.ResponseWriter, r *http.Request, deps Deps, id, notFoundDetail string) (store.ACMEOrderRecord, bool) {
	order, err := deps.Store.ACMEOrders().Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		acmeProblem(r.Context(), w, deps, http.StatusNotFound, "malformed", notFoundDetail+" not found")
		return store.ACMEOrderRecord{}, false
	}
	if err != nil {
		deps.Logger.Error("looking up acme order failed", "err", err)
		acmeProblem(r.Context(), w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
		return store.ACMEOrderRecord{}, false
	}
	return order, true
}

func handleACMEGetOrder(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		order, ok := getOrderOr404(w, r, deps, r.PathValue("id"), "order")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, acmeOrderResponse(deps, order))
	}
}

// handleACMEGetAuthorization synthesizes an already-valid authorization
// for the order sharing its id -- see this file's package doc comment:
// TrustMate has one authorization per order, auto-valid, with no
// challenges to complete.
func handleACMEGetAuthorization(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		order, ok := getOrderOr404(w, r, deps, r.PathValue("id"), "authorization")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":     "valid",
			"identifier": acmeIdentifier{Type: acmeIdentifierType, Value: order.Identifier},
			"challenges": []any{},
		})
	}
}

type acmeFinalizePayload struct {
	CSR string `json:"csr"`
}

// handleACMEFinalize implements RFC 8555 section 7.4: the account
// submits a CSR (base64url DER, not PEM) for an order already in
// "ready" status, and this handler issues the certificate through the
// same path POST /v1/clients uses (issueLeafCertificate in
// internal/api/certificates.go), binding the issued cert to the
// account's role -- the role its originating EAB token carried.
func handleACMEFinalize(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		orderID := r.PathValue("id")
		jws, ok := verifiedJWS(r, w, deps, acmeURL(deps, "order/"+orderID+"/finalize"))
		if !ok {
			return
		}
		account, err := resolveACMEAccount(ctx, deps, jws)
		if errors.Is(err, store.ErrNotFound) {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "accountDoesNotExist", "unknown account")
			return
		}
		if err != nil {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		order, ok := getOrderOr404(w, r, deps, orderID, "order")
		if !ok {
			return
		}
		if order.AccountID != account.ID {
			acmeProblem(ctx, w, deps, http.StatusUnauthorized, "unauthorized", "order does not belong to this account")
			return
		}
		if order.Status == store.ACMEOrderStatusValid {
			// Idempotent retry: finalize already succeeded, hand back
			// the same order rather than re-issuing.
			issueAndAttachNonce(ctx, w, deps)
			writeJSON(w, http.StatusOK, acmeOrderResponse(deps, order))
			return
		}
		if order.Status != store.ACMEOrderStatusReady {
			// Covers both a concurrent finalize already in flight
			// (status "processing") and a prior finalize that issued a
			// certificate but failed to record it (see below) -- either
			// way, this request must not also issue a certificate.
			acmeProblem(ctx, w, deps, http.StatusForbidden, "orderNotReady", "order is not ready to be finalized")
			return
		}

		var payload acmeFinalizePayload
		if err := json.Unmarshal(jws.Payload, &payload); err != nil {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "malformed", "decoding finalize payload: "+err.Error())
			return
		}
		der, err := base64.RawURLEncoding.DecodeString(payload.CSR)
		if err != nil {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "badCSR", "csr is not valid base64url")
			return
		}
		csr, err := pki.ParseCSR(der)
		if err != nil {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "badCSR", "invalid CSR: "+err.Error())
			return
		}
		if csr.Subject.CommonName != order.Identifier {
			acmeProblem(ctx, w, deps, http.StatusBadRequest, "badCSR", "CSR common name does not match the order's identifier")
			return
		}

		// Claim the order (ready -> processing) before issuing anything,
		// via a compare-and-swap on the current status rather than a
		// plain read-then-write: the order.Status == "ready" check above
		// only proves that *this* Get saw "ready" a moment ago, not that
		// no other request (a client retry racing the original, say) is
		// claiming it right now too. UpdateStatus's WHERE status =
		// fromStatus makes only one concurrent claim win; the loser gets
		// applied=false and must not issue a certificate. If the store
		// write that should follow issuance (below) never lands -- a
		// crash, a dropped connection -- the order is left in
		// "processing", so a client retry hits the orderNotReady check
		// above instead of silently issuing a second certificate for the
		// same order. A stuck "processing" order needs operator attention
		// to resolve, but that's a far safer failure mode than double
		// issuance.
		claimed, err := deps.Store.ACMEOrders().UpdateStatus(ctx, order.ID, store.ACMEOrderStatusReady, store.ACMEOrderStatusProcessing, order.CertSerial)
		if err != nil {
			deps.Logger.Error("acme finalize: claiming order failed", "order", order.ID, "err", err)
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}
		if !claimed {
			// Lost the race: another request claimed this order between
			// our Get above and this CAS.
			acmeProblem(ctx, w, deps, http.StatusForbidden, "orderNotReady", "order is not ready to be finalized")
			return
		}

		profile := profiles.Default().WithIssuerURLs(deps.PublicBaseURL, deps.ModuleConfig.EnableRevocation)
		now := time.Now()
		rec, err := issueLeafCertificate(ctx, deps, profile, csr.Subject, csr.PublicKey, csr.DNSNames, now, "acme:"+account.ID, "acme-issue", order.ID)
		if err != nil {
			deps.Logger.Error("acme finalize: issuing certificate failed", "order", order.ID, "err", err)
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}
		if err := assignRoleOrRevoke(ctx, deps, rec, account.Role, now); err != nil {
			deps.Logger.Error("acme finalize: assigning client role failed", "serial", rec.Serial, "err", err)
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}
		// Only now, with the certificate actually usable (issued and
		// role-assigned, not compensating-revoked), does this count as a
		// finalized order -- see internal/api/certificates.go's
		// CertificatesIssuedTotal for the same ordering concern.
		if deps.Metrics != nil {
			deps.Metrics.CertificatesIssuedTotal.WithLabelValues(profile.Name).Inc()
		}

		recorded, err := deps.Store.ACMEOrders().UpdateStatus(ctx, order.ID, store.ACMEOrderStatusProcessing, store.ACMEOrderStatusValid, rec.Serial)
		if err != nil {
			deps.Logger.Error("acme finalize: recording issued certificate failed", "order", order.ID, "serial", rec.Serial, "err", err)
			acmeProblem(ctx, w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}
		if !recorded {
			// This request holds the only "processing" claim on this
			// order (nothing else can have moved it out of "processing"),
			// so losing this CAS would mean the order's status changed
			// out from under us unexpectedly -- log it as the invariant
			// violation it would be, but still return success to the
			// client: the certificate was issued and is usable either way.
			deps.Logger.Error("acme finalize: order was not in processing status when recording issuance", "order", order.ID, "serial", rec.Serial)
		}
		order.Status = store.ACMEOrderStatusValid
		order.CertSerial = rec.Serial
		if deps.Metrics != nil {
			deps.Metrics.ACMEOrdersTotal.WithLabelValues("finalized").Inc()
		}

		issueAndAttachNonce(ctx, w, deps)
		writeJSON(w, http.StatusOK, acmeOrderResponse(deps, order))
	}
}

func handleACMECertificate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		order, err := deps.Store.ACMEOrders().Get(r.Context(), r.PathValue("id"))
		if errors.Is(err, store.ErrNotFound) || (err == nil && order.Status != store.ACMEOrderStatusValid) {
			acmeProblem(r.Context(), w, deps, http.StatusNotFound, "malformed", "certificate not found")
			return
		}
		if err != nil {
			deps.Logger.Error("looking up acme order failed", "err", err)
			acmeProblem(r.Context(), w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}

		cert, err := deps.Store.Certificates().GetBySerial(r.Context(), order.CertSerial)
		if err != nil {
			deps.Logger.Error("looking up acme-issued certificate failed", "serial", order.CertSerial, "err", err)
			acmeProblem(r.Context(), w, deps, http.StatusInternalServerError, "serverInternal", "internal error")
			return
		}

		// RFC 8555 section 7.4.2: application/pem-certificate-chain,
		// leaf first, then the rest of the chain. Uses
		// deps.IntermediateIssuer directly -- the actual signer this
		// leaf was issued under -- rather than querying every
		// CertKindIntermediate row in the store: once intermediate
		// rotation exists (as TSA rotation already does, see
		// internal/tsa), querying by kind would return every historical
		// intermediate, not just the one that issued this leaf.
		chain := append([]byte{}, cert.PEM...)
		chain = append(chain, encodeCertPEM(deps.IntermediateIssuer.Cert.Raw)...)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(chain)
	}
}

type issueEABTokenRequest struct {
	Role string `json:"role"`
}

type issueEABTokenResponse struct {
	KeyID     string    `json:"key_id"`
	HMACKey   string    `json:"hmac_key"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// handleIssueEABToken is the admin-only, non-ACME endpoint that starts
// the enrollment flow: an admin vouches for a future ACME client by
// minting a one-time External Account Binding credential, the same
// out-of-band trust decision POST /v1/clients makes directly. Requires
// admin role -- see internal/api/auth.go.
func handleIssueEABToken(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req issueEABTokenRequest
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "malformed JSON body")
				return
			}
		}
		if req.Role == "" {
			req.Role = string(store.RoleManager)
		}
		role := store.ClientRole(req.Role)
		if role != store.RoleAdmin && role != store.RoleManager {
			writeError(w, http.StatusBadRequest, "role must be \"admin\" or \"manager\"")
			return
		}

		keyID, err := randomACMEID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		hmacKey := make([]byte, 32)
		if _, err := rand.Read(hmacKey); err != nil {
			deps.Logger.Error("generating acme eab hmac key failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		now := time.Now().UTC()
		rec := store.ACMEEABTokenRecord{
			KeyID:     keyID,
			HMACKey:   hmacKey,
			Role:      role,
			CreatedAt: now,
			ExpiresAt: now.Add(acmeEABTokenTTL),
		}
		if err := deps.Store.ACMEEABTokens().Create(r.Context(), rec); err != nil {
			deps.Logger.Error("creating acme eab token failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if err := deps.Store.Audit().Append(r.Context(), store.AuditEntry{
			Timestamp: now,
			Actor:     r.RemoteAddr,
			Action:    "acme-eab-token-issue",
			Target:    keyID,
			Detail:    string(role),
		}); err != nil {
			deps.Logger.Error("writing audit entry failed", "err", err)
		}

		writeJSON(w, http.StatusCreated, issueEABTokenResponse{
			KeyID:     keyID,
			HMACKey:   base64.RawURLEncoding.EncodeToString(hmacKey),
			Role:      string(role),
			ExpiresAt: rec.ExpiresAt,
		})
	}
}
