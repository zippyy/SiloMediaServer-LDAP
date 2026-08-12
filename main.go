package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/capability"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimedefault"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/config"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/ldapauth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var version string

//go:embed manifest.json
var manifestJSON []byte

type runtimeServer struct {
	runtimedefault.Server

	manifest *pluginv1.PluginManifest
	auth     *authServer
}

type directoryAuthenticator interface {
	Authenticate(context.Context, string, string) (*ldapauth.User, error)
}

type directoryConnectionTester interface {
	TestConnection(context.Context) error
}

type configurationServer struct {
	pluginv1.UnimplementedAuthProviderConfigurationServer
	newTester func(config.Config) directoryConnectionTester
}

func (s *configurationServer) TestConnection(
	ctx context.Context,
	req *pluginv1.AuthProviderTestConnectionRequest,
) (*pluginv1.AuthProviderTestConnectionResponse, error) {
	if req.GetCapabilityId() != "ldap" {
		return nil, status.Error(codes.InvalidArgument, "unknown authentication capability")
	}
	cfg, configured, err := config.Decode(req.GetConfig())
	if err != nil || !configured {
		return nil, status.Error(codes.InvalidArgument, "invalid LDAP configuration")
	}
	newTester := s.newTester
	if newTester == nil {
		newTester = func(cfg config.Config) directoryConnectionTester { return ldapauth.New(cfg) }
	}
	if err := newTester(cfg).TestConnection(ctx); err != nil {
		stage := ldapauth.FailureStage(err)
		slog.ErrorContext(ctx, "LDAP connection check failed", "stage", stage, "error", err)
		return &pluginv1.AuthProviderTestConnectionResponse{
			Ok:      false,
			Message: fmt.Sprintf("LDAP connection check failed during %s.", stage),
		}, nil
	}
	return &pluginv1.AuthProviderTestConnectionResponse{
		Ok:      true,
		Message: "LDAP connection check succeeded.",
	}, nil
}

func (s *runtimeServer) GetManifest(context.Context, *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	return &pluginv1.GetManifestResponse{
		Manifest: proto.Clone(s.manifest).(*pluginv1.PluginManifest),
	}, nil
}

func (s *runtimeServer) Configure(_ context.Context, req *pluginv1.ConfigureRequest) (*pluginv1.ConfigureResponse, error) {
	cfg, configured, err := config.Decode(req.GetConfig())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid LDAP configuration: %v", err)
	}
	if !configured {
		s.auth.SetAuthenticator(nil)
		return &pluginv1.ConfigureResponse{}, nil
	}
	s.auth.SetAuthenticator(ldapauth.New(cfg))
	return &pluginv1.ConfigureResponse{}, nil
}

type authServer struct {
	pluginv1.UnimplementedAuthProviderServer

	mu            sync.RWMutex
	manifest      *pluginv1.PluginManifest
	authenticator directoryAuthenticator
}

func (s *authServer) SetAuthenticator(authenticator directoryAuthenticator) {
	s.mu.Lock()
	s.authenticator = authenticator
	s.mu.Unlock()
}

func (s *authServer) Authenticator() directoryAuthenticator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authenticator
}

func (s *authServer) Authenticate(ctx context.Context, req *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	capabilityID, err := capability.ResolveAuthProviderID(s.manifest, req.GetCapabilityId())
	if err != nil || capabilityID != "ldap" {
		return nil, status.Error(codes.InvalidArgument, "unknown authentication capability")
	}
	authenticator := s.Authenticator()
	if authenticator == nil {
		return nil, status.Error(codes.FailedPrecondition, "LDAP authentication is not configured")
	}

	user, err := authenticator.Authenticate(ctx, req.GetUsername(), req.GetPassword())
	if err != nil {
		if errors.Is(err, ldapauth.ErrInvalidCredentials) || errors.Is(err, ldapauth.ErrGroupDenied) {
			return &pluginv1.AuthenticateResponse{}, nil
		}
		stage := ldapauth.FailureStage(err)
		slog.ErrorContext(ctx, "LDAP authentication failed", "stage", stage, "error", err)
		return nil, status.Errorf(codes.Unavailable, "LDAP authentication failed during %s", stage)
	}

	var managedRole *pluginv1.ManagedSiloRoleAssertion
	if user.Role != "" {
		var role pluginv1.ManagedSiloRole
		switch user.Role {
		case "user":
			role = pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_USER
		case "admin":
			role = pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_ADMIN
		default:
			return nil, status.Error(codes.Internal, "LDAP returned an unsupported managed role")
		}
		managedRole = &pluginv1.ManagedSiloRoleAssertion{Role: role}
	}
	return &pluginv1.AuthenticateResponse{
		ExternalSubject: user.Subject,
		DisplayName:     user.DisplayName,
		Email:           user.Email,
		ManagedSiloRole: managedRole,
	}, nil
}

func main() {
	manifest, err := publicmanifest.LoadWithChecksum(manifestJSON, version)
	if err != nil {
		panic(fmt.Errorf("load plugin manifest: %w", err))
	}

	auth := &authServer{manifest: manifest}
	runtime := &runtimeServer{
		manifest: manifest,
		auth:     auth,
	}
	configuration := &configurationServer{}
	servers := sdkruntime.CapabilityServers{
		Runtime:      runtime,
		AuthProvider: auth,
	}

	sdkruntime.Serve(sdkruntime.ServeConfig{
		Servers: servers,
		Plugins: sdkruntime.DefaultPluginSetWithAuthProviderConfiguration(
			servers,
			nil,
			configuration,
		),
	})
}
