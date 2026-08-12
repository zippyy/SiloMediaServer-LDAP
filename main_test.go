package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/config"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/ldapauth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestManifestIsValid(t *testing.T) {
	manifest, err := publicmanifest.Load(manifestJSON)
	if err != nil {
		t.Fatalf("manifest is invalid: %v", err)
	}
	for _, capability := range manifest.GetCapabilities() {
		if capability.GetType() == "request_router.v1" {
			t.Fatalf("LDAP advertises unsupported media request capability %q", capability.GetId())
		}
		if capability.GetType() == "auth_provider.v1" {
			authProvider := capability.GetAuthProvider()
			if got := authProvider.GetConnectionTest().GetConfigKeys(); len(got) != 1 || got[0] != config.EntryKey {
				t.Fatalf("connection-test config keys = %#v, want [%s]", got, config.EntryKey)
			}
			roles := authProvider.GetManagedRoles().GetSupportedRoles()
			if len(roles) != 2 || roles[0] != pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_USER || roles[1] != pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_ADMIN {
				t.Fatalf("managed roles = %#v, want user/admin", roles)
			}
		}
	}
}

func TestAuthenticateEmitsTypedManagedRoleOnlyWhenEnabled(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		wantRole pluginv1.ManagedSiloRole
	}{
		{name: "disabled", role: ""},
		{name: "normal user", role: "user", wantRole: pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_USER},
		{name: "administrator", role: "admin", wantRole: pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_ADMIN},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := testAuthServer()
			auth.SetAuthenticator(&stubDirectoryAuthenticator{user: &ldapauth.User{
				Subject: "entryuuid:1", DisplayName: "Alice", Email: "alice@example.com", Role: test.role,
			}})
			response, err := auth.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{CapabilityId: "ldap", Username: "alice", Password: "password"})
			if err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}
			if response.GetClaims() != nil {
				t.Fatalf("typed response emitted legacy claims: %#v", response.GetClaims().AsMap())
			}
			if got := response.GetManagedSiloRole().GetRole(); got != test.wantRole {
				t.Fatalf("managed role = %v, want %v", got, test.wantRole)
			}
		})
	}
}

func TestAuthenticateRejectsUnsupportedDirectoryRole(t *testing.T) {
	auth := testAuthServer()
	auth.SetAuthenticator(&stubDirectoryAuthenticator{user: &ldapauth.User{Subject: "entryuuid:1", Role: "owner"}})
	_, err := auth.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{CapabilityId: "ldap", Username: "alice", Password: "password"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("Authenticate() error = %v, want Internal", err)
	}
}

func TestConfigurationConnectionCheckReturnsStableStageOnly(t *testing.T) {
	entry := testConfigEntry(t)
	server := &configurationServer{newTester: func(config.Config) directoryConnectionTester {
		return stubConnectionTester{err: &ldapauth.StageError{
			Stage: ldapauth.StageDirectorySearch,
			Err:   errors.New("secret directory details"),
		}}
	}}
	response, err := server.TestConnection(context.Background(), &pluginv1.AuthProviderTestConnectionRequest{
		CapabilityId: "ldap",
		Config:       []*pluginv1.ConfigEntry{entry},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetOk() || strings.Contains(response.GetMessage(), "secret") || !strings.Contains(response.GetMessage(), string(ldapauth.StageDirectorySearch)) {
		t.Fatalf("connection response = %#v", response)
	}
}

func TestConfigurationConnectionCheckRejectsWrongCapability(t *testing.T) {
	server := &configurationServer{}
	_, err := server.TestConnection(context.Background(), &pluginv1.AuthProviderTestConnectionRequest{CapabilityId: "other"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("TestConnection() error = %v, want InvalidArgument", err)
	}
}

func TestAuthenticateDoesNotExposeDirectoryError(t *testing.T) {
	auth := testAuthServer()
	auth.SetAuthenticator(&stubDirectoryAuthenticator{
		authErr: &ldapauth.StageError{Stage: ldapauth.StageUserSearch, Err: errors.New("search base ou=secret,dc=example,dc=com rejected")},
	})
	_, err := auth.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{CapabilityId: "ldap", Username: "alice", Password: "password"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Authenticate() error = %v, want Unavailable", err)
	}
	if strings.Contains(status.Convert(err).Message(), "ou=secret") {
		t.Fatalf("caller-facing error disclosed directory details: %v", err)
	}
}

func TestAuthenticateCapabilityRouting(t *testing.T) {
	t.Run("explicit expected capability", func(t *testing.T) {
		auth := testAuthServer()
		auth.SetAuthenticator(&stubDirectoryAuthenticator{})
		if _, err := auth.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{CapabilityId: "ldap"}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("legacy empty capability is accepted for singleton manifest", func(t *testing.T) {
		auth := testAuthServer()
		auth.SetAuthenticator(&stubDirectoryAuthenticator{})
		if _, err := auth.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unknown capability fails before directory access", func(t *testing.T) {
		auth := testAuthServer()
		stub := &stubDirectoryAuthenticator{}
		auth.SetAuthenticator(stub)
		_, err := auth.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{CapabilityId: "oidc"})
		if status.Code(err) != codes.InvalidArgument || stub.calls != 0 {
			t.Fatalf("Authenticate() error=%v calls=%d, want InvalidArgument and no directory access", err, stub.calls)
		}
	})

	t.Run("legacy empty capability is ambiguous for multiple providers", func(t *testing.T) {
		auth := testAuthServer()
		auth.manifest.Capabilities = append(auth.manifest.Capabilities, &pluginv1.CapabilityDescriptor{Type: "auth_provider.v1", Id: "oidc"})
		stub := &stubDirectoryAuthenticator{}
		auth.SetAuthenticator(stub)
		_, err := auth.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{})
		if status.Code(err) != codes.InvalidArgument || stub.calls != 0 {
			t.Fatalf("Authenticate() error=%v calls=%d, want InvalidArgument and no directory access", err, stub.calls)
		}
	})
}

type stubDirectoryAuthenticator struct {
	user    *ldapauth.User
	authErr error
	calls   int
}

type stubConnectionTester struct{ err error }

func (s stubConnectionTester) TestConnection(context.Context) error { return s.err }

func testConfigEntry(t *testing.T) *pluginv1.ConfigEntry {
	t.Helper()
	value, err := structpb.NewStruct(map[string]any{
		"url":                      "ldaps://ldap.example.com:636",
		"base_dn":                  "dc=example,dc=com",
		"user_filter":              "(uid={username})",
		"subject_attribute":        "entryUUID",
		"timeout_seconds":          10,
		"allow_insecure_plaintext": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &pluginv1.ConfigEntry{Key: config.EntryKey, Value: value}
}

func (s *stubDirectoryAuthenticator) Authenticate(context.Context, string, string) (*ldapauth.User, error) {
	s.calls++
	if s.authErr != nil {
		return nil, s.authErr
	}
	if s.user != nil {
		return s.user, nil
	}
	return &ldapauth.User{Subject: "entryuuid:1"}, nil
}

func testAuthServer() *authServer {
	return &authServer{manifest: &pluginv1.PluginManifest{Capabilities: []*pluginv1.CapabilityDescriptor{{
		Type: "auth_provider.v1",
		Id:   "ldap",
	}}}}
}
