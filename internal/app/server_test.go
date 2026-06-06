package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Acceptance (spec/0001-foundation.md): GET /healthz returns 200 and the version.
func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(NewHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field = %q, want ok", body["status"])
	}
	if body["version"] != Version {
		t.Fatalf("version field = %q, want %q", body["version"], Version)
	}
}
