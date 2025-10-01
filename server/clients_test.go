package server

import "testing"

func TestNewClientRegistrySetsPublicFlag(t *testing.T) {
	cfgs := []ClientConfig{{
		ClientID:     "web",
		ClientSecret: "",
		RedirectURIs: []string{"http://localhost/callback"},
		Scopes:       []string{"openid", "profile"},
	}}

	registry, err := NewClientRegistry(cfgs)
	if err != nil {
		t.Fatalf("NewClientRegistry returned error: %v", err)
	}

	client, ok := registry.Get("web")
	if !ok {
		t.Fatalf("client not registered")
	}
	if !client.Public {
		t.Fatalf("expected client to be marked public when secret absent")
	}
}

func TestAuthenticateValidatesSecret(t *testing.T) {
	cfgs := []ClientConfig{{
		ClientID:     "svc",
		ClientSecret: "topsecret",
	}}

	registry, err := NewClientRegistry(cfgs)
	if err != nil {
		t.Fatalf("registry init: %v", err)
	}

	if _, err := registry.Authenticate("svc", "wrong"); err == nil {
		t.Fatalf("expected error for invalid secret")
	}

	client, err := registry.Authenticate("svc", "topsecret")
	if err != nil {
		t.Fatalf("expected successful authentication: %v", err)
	}
	if client.Public {
		t.Fatalf("confidential client should not be marked public")
	}
}

func TestClientScopeAndAudienceHelpers(t *testing.T) {
	client := &Client{
		ClientID:     "svc",
		Scopes:       []string{"openid", "profile", "email"},
		Audiences:    []string{"api://default"},
		RedirectURIs: []string{"https://app/callback"},
	}

	if !client.ValidRedirect("https://app/callback") {
		t.Fatalf("expected redirect to be valid")
	}
	if client.ValidRedirect("https://other/callback") {
		t.Fatalf("unexpected redirect accepted")
	}

	if !client.ValidateScopes("openid email") {
		t.Fatalf("expected scopes to be accepted")
	}
	if client.ValidateScopes("openid admin") {
		t.Fatalf("unexpected scope accepted")
	}

	gotAud := client.ResolveAudience("", "fallback")
	if gotAud != "api://default" {
		t.Fatalf("audience resolution mismatch: got %q", gotAud)
	}

	explicit := client.ResolveAudience("api://requested", "fallback")
	if explicit != "api://requested" {
		t.Fatalf("explicit audience should be honoured")
	}
}
