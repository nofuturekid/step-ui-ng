package ca_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.step.sm/crypto/jose"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
)

// --- Provisioner OTT revoke flow (FR-1) -------------------------------------
//
// The mock CA publishes the same JWK provisioner as the sign flow and exposes
// POST /1.0/revoke. It re-implements step-ca's JWK revoke authorization: it
// parses the OTT, verifies the JWS signature against the PUBLISHED PUBLIC JWK,
// checks iss == provisioner name and aud == {ca}/1.0/revoke, and — the revoke
// crux — that the token SUBJECT equals the serial being revoked (step-ca
// rejects a token whose subject and serial do not match). It also asserts the
// request carries passive:true and the reason/reasonCode. Only then does it
// report success. A flag makes it reject so the failure path is testable.

const revokeProvName = "ui-jwk"
const revokeProvPassword = "provisioner-pass-1234"

// revokeCA is a mock CA for the OTT revoke flow.
type revokeCA struct {
	url         string
	fingerprint string
	reject      bool // when true, /1.0/revoke returns 500 (CA failure)
	// captured request material so tests can assert what the client sent.
	lastSerial     string
	lastReason     string
	lastReasonCode int
	lastPassive    bool
	lastOTTSub     string
	called         bool
}

// startRevokeCA stands up the mock CA: GET /roots, GET /provisioners (the JWK
// provisioner), and POST /1.0/revoke (verifies the OTT + serial/reason).
func startRevokeCA(t *testing.T, reject bool) *revokeCA {
	t.Helper()
	pub, encKey := buildSignProvisioner(t)

	c := &revokeCA{reject: reject}

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsCert := srv.Certificate()
	c.url = srv.URL
	sum := sha256.Sum256(tlsCert.Raw)
	c.fingerprint = hex.EncodeToString(sum[:])

	wantAud := c.url + "/1.0/revoke"

	mux := http.NewServeMux()
	mux.HandleFunc("/roots", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rootsJSON(tlsCert)))
	})
	mux.HandleFunc("GET /provisioners", func(w http.ResponseWriter, _ *http.Request) {
		pubBytes, _ := pub.MarshalJSON()
		body := `{"provisioners":[{"type":"JWK","name":"` + revokeProvName + `","key":` +
			string(pubBytes) + `,"encryptedKey":"` + encKey + `"}]}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("POST /1.0/revoke", func(w http.ResponseWriter, r *http.Request) {
		c.called = true
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var req struct {
			Serial     string `json:"serial"`
			OTT        string `json:"ott"`
			ReasonCode int    `json:"reasonCode"`
			Reason     string `json:"reason"`
			Passive    bool   `json:"passive"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"message":"bad request"}`, http.StatusBadRequest)
			return
		}
		c.lastSerial = req.Serial
		c.lastReason = req.Reason
		c.lastReasonCode = req.ReasonCode
		c.lastPassive = req.Passive

		// (1) Parse + verify the OTT against the published public JWK.
		jwt, err := jose.ParseSigned(req.OTT)
		if err != nil {
			http.Error(w, `{"message":"bad token"}`, http.StatusUnauthorized)
			return
		}
		var claims jose.Claims
		if err := jwt.Claims(pub.Public(), &claims); err != nil {
			http.Error(w, `{"message":"invalid token signature"}`, http.StatusUnauthorized)
			return
		}
		// (2) iss == provisioner name, aud == revoke URL.
		if err := claims.ValidateWithLeeway(jose.Expected{
			Issuer:   revokeProvName,
			Audience: jose.Audience{wantAud},
			Time:     time.Now().UTC(),
		}, time.Minute); err != nil {
			http.Error(w, `{"message":"invalid claims"}`, http.StatusUnauthorized)
			return
		}
		c.lastOTTSub = claims.Subject
		// (3) The revoke crux: token subject must equal the serial being revoked.
		if claims.Subject != req.Serial {
			http.Error(w, `{"message":"token subject and serial number do not match"}`, http.StatusUnauthorized)
			return
		}

		// (4) Configurable failure path: the CA rejects the revoke.
		if c.reject {
			http.Error(w, `{"message":"certificate with serial number not found"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	srv.Config.Handler = mux
	return c
}

// --- Acceptance: revoke by serial succeeds and carries the right token -------

func TestRevokeCertSucceeds(t *testing.T) {
	c := startRevokeCA(t, false)
	const serial = "123456789"

	err := ca.RevokeCert(context.Background(), ca.RevokeParams{
		CAURL:           c.url,
		Fingerprint:     c.fingerprint,
		ProvisionerName: revokeProvName,
		Password:        revokeProvPassword,
		Serial:          serial,
		Reason:          "key compromise",
		ReasonCode:      1,
	})
	if err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	if !c.called {
		t.Fatal("CA never received the revoke request")
	}
	if c.lastSerial != serial {
		t.Fatalf("CA saw serial %q, want %q", c.lastSerial, serial)
	}
	// The OTT subject must equal the serial (step-ca's revoke contract).
	if c.lastOTTSub != serial {
		t.Fatalf("OTT subject seen by CA = %q, want the serial %q", c.lastOTTSub, serial)
	}
	if c.lastReason != "key compromise" || c.lastReasonCode != 1 {
		t.Fatalf("CA saw reason %q code %d, want 'key compromise'/1", c.lastReason, c.lastReasonCode)
	}
	// Step-CA only implements passive revocation; passive must be true.
	if !c.lastPassive {
		t.Fatal("revoke request must set passive:true")
	}
}

// --- Acceptance: CA rejects the revoke → a clear, matchable error -----------

func TestRevokeCertCARejects(t *testing.T) {
	c := startRevokeCA(t, true)

	err := ca.RevokeCert(context.Background(), ca.RevokeParams{
		CAURL:           c.url,
		Fingerprint:     c.fingerprint,
		ProvisionerName: revokeProvName,
		Password:        revokeProvPassword,
		Serial:          "987654321",
		Reason:          "superseded",
		ReasonCode:      4,
	})
	if !errors.Is(err, ca.ErrRevokeFailed) {
		t.Fatalf("err = %v, want ErrRevokeFailed when the CA rejects", err)
	}
	if !c.called {
		t.Fatal("CA never received the revoke request")
	}
}

// --- The wrong provisioner password cannot decrypt the signing key ----------

func TestRevokeCertWrongPassword(t *testing.T) {
	c := startRevokeCA(t, false)

	err := ca.RevokeCert(context.Background(), ca.RevokeParams{
		CAURL:           c.url,
		Fingerprint:     c.fingerprint,
		ProvisionerName: revokeProvName,
		Password:        "wrong-password",
		Serial:          "123",
		Reason:          "unspecified",
	})
	if !errors.Is(err, ca.ErrProvisionerKey) {
		t.Fatalf("err = %v, want ErrProvisionerKey for the wrong password", err)
	}
}

// --- An empty serial is rejected before any CA round-trip -------------------

func TestRevokeCertEmptySerial(t *testing.T) {
	err := ca.RevokeCert(context.Background(), ca.RevokeParams{
		CAURL:           "https://127.0.0.1:1",
		Fingerprint:     "deadbeef",
		ProvisionerName: revokeProvName,
		Password:        revokeProvPassword,
		Serial:          "",
		Reason:          "unspecified",
	})
	if !errors.Is(err, ca.ErrRevokeInvalid) {
		t.Fatalf("err = %v, want ErrRevokeInvalid for an empty serial", err)
	}
}
