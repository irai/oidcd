package server

import "testing"

func TestResolveAzureTenantIssuer(t *testing.T) {
	issuer, ok := resolveAzureTenantIssuer("https://login.microsoftonline.com/common/v2.0", "abc123")
	if !ok {
		t.Fatalf("expected azure issuer rewrite to trigger")
	}
	want := "https://login.microsoftonline.com/abc123/v2.0"
	if issuer != want {
		t.Fatalf("issuer mismatch: got %q want %q", issuer, want)
	}

	issuer, ok = resolveAzureTenantIssuer("https://login.microsoftonline.com/{tenant}/v2.0", "abc123")
	if !ok || issuer != want {
		t.Fatalf("placeholder issuer mismatch: got %q (ok=%v) want %q", issuer, ok, want)
	}

	issuer, ok = resolveAzureTenantIssuer("https://example.com/oidc", "abc123")
	if ok {
		t.Fatalf("did not expect rewrite for non-Azure issuer")
	}
	if issuer != "https://example.com/oidc" {
		t.Fatalf("issuer should remain unchanged, got %q", issuer)
	}
}
