package certs_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/nofuturekid/step-ui-ng/internal/ca"
	"github.com/nofuturekid/step-ui-ng/internal/certs"
)

// seedIssuedCert issues a server-strategy cert via the fake signer so a revoke/renew
// has a real row (serial, CN, SANs, sealed key) to act on. Returns the cert.
func seedIssuedCert(t *testing.T, svc *certs.Service, cn string, sans []string) certs.Certificate {
	t.Helper()
	cert, err := svc.Issue(context.Background(), certs.IssueParams{
		Actor:           "seed",
		ProvisionerName: "ui-jwk",
		Password:        "pass",
		CAURL:           "https://ca.test",
		Fingerprint:     "fp",
		CN:              cn,
		SANs:            sans,
		ValidityDays:    30,
		Format:          certs.FormatPEM,
	})
	if err != nil {
		t.Fatalf("seed Issue %q: %v", cn, err)
	}
	return cert
}

func storedStatus(t *testing.T, db *sql.DB, id int64) string {
	t.Helper()
	var status string
	if err := db.QueryRow(`SELECT status FROM certificates WHERE id = ?`, id).Scan(&status); err != nil {
		t.Fatalf("read status for id %d: %v", id, err)
	}
	return status
}

func auditCount(t *testing.T, db *sql.DB, action string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatalf("count audit %q: %v", action, err)
	}
	return n
}

// --- Acceptance: revoke calls the CA AND sets status only on CA success ------

func TestRevokeSucceedsCallsCAAndMarksRevoked(t *testing.T) {
	svc, db, _, revoker := testService(t)
	cert := seedIssuedCert(t, svc, "revoke.test", nil)

	err := svc.Revoke(context.Background(), certs.RevokeParams{
		Actor:           "alice",
		ID:              cert.ID,
		ProvisionerName: "ui-jwk",
		Password:        "pass",
		CAURL:           "https://ca.test",
		Fingerprint:     "fp",
		Reason:          "key compromise",
		ReasonCode:      1,
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// The CA received the revoke call, by serial.
	if revoker.calls != 1 {
		t.Fatalf("CA revoke calls = %d, want 1", revoker.calls)
	}
	if revoker.lastSerial != cert.Serial {
		t.Fatalf("CA saw serial %q, want %q", revoker.lastSerial, cert.Serial)
	}
	if revoker.lastReason != "key compromise" {
		t.Fatalf("CA saw reason %q, want 'key compromise'", revoker.lastReason)
	}
	// Local status flipped to revoked ONLY because the CA succeeded.
	if s := storedStatus(t, db, cert.ID); s != "revoked" {
		t.Fatalf("local status = %q, want revoked after CA success", s)
	}
	// Audit event recorded with the session actor (FR-4).
	if auditCount(t, db, "revoke") != 1 {
		t.Fatal("expected one 'revoke' audit event")
	}
	if who := lastAuditWho(t, db, "revoke"); who != "alice" {
		t.Fatalf("revoke audit who = %q, want alice", who)
	}
}

// --- Acceptance: CA rejects → local status UNCHANGED, no audit, error shown --
//
// This is the atomicity crux (the predecessor's bug): on a CA failure the local
// row must NOT flip to revoked. If the implementation ever updated status before
// (or regardless of) the CA result, this test fails.
func TestRevokeCARejectsLeavesStatusUnchanged(t *testing.T) {
	svc, db, _, revoker := testService(t)
	revoker.err = ca.ErrRevokeFailed // make the CA reject
	cert := seedIssuedCert(t, svc, "reject.test", nil)

	err := svc.Revoke(context.Background(), certs.RevokeParams{
		Actor:           "alice",
		ID:              cert.ID,
		ProvisionerName: "ui-jwk",
		Password:        "pass",
		CAURL:           "https://ca.test",
		Fingerprint:     "fp",
		Reason:          "superseded",
		ReasonCode:      4,
	})
	if !errors.Is(err, ca.ErrRevokeFailed) {
		t.Fatalf("err = %v, want ca.ErrRevokeFailed surfaced", err)
	}
	if revoker.calls != 1 {
		t.Fatalf("CA revoke calls = %d, want 1 (it must be attempted)", revoker.calls)
	}
	// The local row is UNCHANGED — still its original (valid) status.
	if s := storedStatus(t, db, cert.ID); s == "revoked" {
		t.Fatal("local status flipped to revoked despite CA failure (atomicity violated)")
	}
	if s := storedStatus(t, db, cert.ID); s != "valid" {
		t.Fatalf("local status = %q, want unchanged 'valid'", s)
	}
	// No audit event for a failed revoke.
	if n := auditCount(t, db, "revoke"); n != 0 {
		t.Fatalf("revoke audit events = %d, want 0 on CA failure", n)
	}
}

// --- Guard rail: cannot revoke an already-revoked cert (FR-3) ----------------

func TestRevokeAlreadyRevokedIsRefused(t *testing.T) {
	svc, db, _, revoker := testService(t)
	cert := seedIssuedCert(t, svc, "twice.test", nil)

	// First revoke succeeds.
	if err := svc.Revoke(context.Background(), certs.RevokeParams{
		Actor: "alice", ID: cert.ID, Reason: "unspecified",
		CAURL: "https://ca.test", Fingerprint: "fp", ProvisionerName: "ui-jwk", Password: "pass",
	}); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	callsAfterFirst := revoker.calls

	// Second revoke must be refused locally, WITHOUT a CA round-trip.
	err := svc.Revoke(context.Background(), certs.RevokeParams{
		Actor: "alice", ID: cert.ID, Reason: "unspecified",
		CAURL: "https://ca.test", Fingerprint: "fp", ProvisionerName: "ui-jwk", Password: "pass",
	})
	if !errors.Is(err, certs.ErrAlreadyRevoked) {
		t.Fatalf("err = %v, want certs.ErrAlreadyRevoked", err)
	}
	if revoker.calls != callsAfterFirst {
		t.Fatalf("CA was called again for an already-revoked cert (calls %d → %d)", callsAfterFirst, revoker.calls)
	}
	_ = db
}

// --- Guard rail: a reason is required (FR-3) ---------------------------------

func TestRevokeRequiresReason(t *testing.T) {
	svc, _, _, revoker := testService(t)
	cert := seedIssuedCert(t, svc, "noreason.test", nil)

	err := svc.Revoke(context.Background(), certs.RevokeParams{
		Actor: "alice", ID: cert.ID, Reason: "   ", // blank
		CAURL: "https://ca.test", Fingerprint: "fp", ProvisionerName: "ui-jwk", Password: "pass",
	})
	if !errors.Is(err, certs.ErrReasonRequired) {
		t.Fatalf("err = %v, want certs.ErrReasonRequired for a blank reason", err)
	}
	if revoker.calls != 0 {
		t.Fatal("CA must not be called when the reason is missing")
	}
}

// --- Acceptance: renew with 30 days → new cert, same CN/SANs, ~30d validity --

func TestRenewReissuesSameSubjectWithChosenValidity(t *testing.T) {
	svc, db, signer, _ := testService(t)
	orig := seedIssuedCert(t, svc, "renew.test", []string{"www.renew.test"})

	const renewDays = 30
	renewed, err := svc.Renew(context.Background(), certs.RenewParams{
		Actor:           "bob",
		ID:              orig.ID,
		ProvisionerName: "ui-jwk",
		Password:        "pass",
		CAURL:           "https://ca.test",
		Fingerprint:     "fp",
		ValidityDays:    renewDays,
	})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}

	// Same CN.
	if renewed.CN != "renew.test" {
		t.Fatalf("renewed CN = %q, want renew.test", renewed.CN)
	}
	// Same SANs (CN + the extra SAN), and it is a NEW row.
	if renewed.ID == orig.ID {
		t.Fatal("renew must store a NEW inventory row, not overwrite the original")
	}
	if !containsStr(renewed.SANs, "renew.test") || !containsStr(renewed.SANs, "www.renew.test") {
		t.Fatalf("renewed SANs = %v, want renew.test + www.renew.test", renewed.SANs)
	}
	// The signer was asked for the chosen validity (not hard-coded elsewhere).
	if signer.lastDays != renewDays {
		t.Fatalf("signer asked for %d days, want %d (chosen validity)", signer.lastDays, renewDays)
	}
	// not_after ≈ now + 30d (within a day tolerance for the fake signer).
	want := time.Now().Add(renewDays * 24 * time.Hour)
	got := time.Unix(renewed.NotAfter, 0)
	if diff := got.Sub(want); diff > 24*time.Hour || diff < -24*time.Hour {
		t.Fatalf("renewed not_after = %v, want ≈ %v (±1d)", got, want)
	}

	// The renewed cert appears in the inventory as a stored row.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates WHERE id = ?`, renewed.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("renewed cert not stored (n=%d, err=%v)", n, err)
	}
	// Audit event recorded with the session actor (FR-4).
	if auditCount(t, db, "renew") != 1 {
		t.Fatal("expected one 'renew' audit event")
	}
	if who := lastAuditWho(t, db, "renew"); who != "bob" {
		t.Fatalf("renew audit who = %q, want bob", who)
	}
}

// --- Renew validity bound: an over-max request is surfaced as the CA error ---
//
// The provisioner's max is enforced at the CA; the domain forwards the requested
// validity and surfaces ca.ErrSignRejected unchanged when the CA rejects it. We
// make the fake signer reject to model the over-max case.
func TestRenewOverProvisionerMaxRejected(t *testing.T) {
	svc, db, signer, _ := testService(t)
	orig := seedIssuedCert(t, svc, "overmax.test", nil)
	signer.err = ca.ErrSignRejected // model the provisioner-max rejection

	_, err := svc.Renew(context.Background(), certs.RenewParams{
		Actor: "bob", ID: orig.ID, ValidityDays: 36500, // absurdly long
		ProvisionerName: "ui-jwk", Password: "pass",
		CAURL: "https://ca.test", Fingerprint: "fp",
	})
	if !errors.Is(err, ca.ErrSignRejected) {
		t.Fatalf("err = %v, want ca.ErrSignRejected for over-max validity", err)
	}
	// No renew audit event on failure.
	if n := auditCount(t, db, "renew"); n != 0 {
		t.Fatalf("renew audit events = %d, want 0 on CA rejection", n)
	}
}

// --- Renew/revoke of a missing row → ErrNotFound ----------------------------

func TestRevokeAndRenewNotFound(t *testing.T) {
	svc, _, _, _ := testService(t)
	if err := svc.Revoke(context.Background(), certs.RevokeParams{
		Actor: "a", ID: 9999, Reason: "x",
		CAURL: "https://ca.test", Fingerprint: "fp", ProvisionerName: "p", Password: "pass",
	}); !errors.Is(err, certs.ErrNotFound) {
		t.Fatalf("Revoke missing = %v, want ErrNotFound", err)
	}
	if _, err := svc.Renew(context.Background(), certs.RenewParams{
		Actor: "a", ID: 9999, ValidityDays: 30,
		CAURL: "https://ca.test", Fingerprint: "fp", ProvisionerName: "p", Password: "pass",
	}); !errors.Is(err, certs.ErrNotFound) {
		t.Fatalf("Renew missing = %v, want ErrNotFound", err)
	}
}

// lastAuditWho returns the who of the newest audit row for action.
func lastAuditWho(t *testing.T, db *sql.DB, action string) string {
	t.Helper()
	var who string
	if err := db.QueryRow(`SELECT who FROM audit_events WHERE action = ? ORDER BY id DESC LIMIT 1`, action).Scan(&who); err != nil {
		t.Fatalf("read audit who %q: %v", action, err)
	}
	return who
}
