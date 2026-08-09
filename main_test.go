package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/hostcontract"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/ldapauth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		metadata := capability.GetMetadata().AsMap()
		if _, ok := metadata["connection_test"]; ok {
			t.Fatal("LDAP advertises an SDK-unsupported auth connection test")
		}
	}
}

func TestAuthenticateEmitsManagedRoleContractOnlyWhenEnabled(t *testing.T) {
	tests := []struct {
		name       string
		role       string
		wantClaims bool
	}{
		{name: "disabled", role: "", wantClaims: false},
		{name: "normal user", role: "user", wantClaims: true},
		{name: "administrator", role: "admin", wantClaims: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &authServer{}
			auth.SetAuthenticator(&stubDirectoryAuthenticator{user: &ldapauth.User{
				Subject: "entryuuid:1", DisplayName: "Alice", Email: "alice@example.com", Role: test.role,
			}})
			response, err := auth.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{Username: "alice", Password: "password"})
			if err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}
			if !test.wantClaims {
				if response.GetClaims() != nil {
					t.Fatalf("disabled role sync emitted claims: %#v", response.GetClaims().AsMap())
				}
				return
			}
			claims := response.GetClaims().AsMap()
			if claims[hostcontract.RoleContractClaim] != hostcontract.ManagedRoleV1 ||
				claims[hostcontract.RoleManagedClaim] != true || claims[hostcontract.RoleClaim] != test.role {
				t.Fatalf("managed role claims = %#v", claims)
			}
		})
	}
}

func TestAuthenticateDoesNotExposeDirectoryError(t *testing.T) {
	auth := &authServer{}
	auth.SetAuthenticator(&stubDirectoryAuthenticator{
		authErr: &ldapauth.StageError{Stage: ldapauth.StageUserSearch, Err: errors.New("search base ou=secret,dc=example,dc=com rejected")},
	})
	_, err := auth.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{Username: "alice", Password: "password"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Authenticate() error = %v, want Unavailable", err)
	}
	if strings.Contains(status.Convert(err).Message(), "ou=secret") {
		t.Fatalf("caller-facing error disclosed directory details: %v", err)
	}
}

type stubDirectoryAuthenticator struct {
	user    *ldapauth.User
	authErr error
}

func (s *stubDirectoryAuthenticator) Authenticate(context.Context, string, string) (*ldapauth.User, error) {
	if s.authErr != nil {
		return nil, s.authErr
	}
	if s.user != nil {
		return s.user, nil
	}
	return &ldapauth.User{Subject: "entryuuid:1"}, nil
}
