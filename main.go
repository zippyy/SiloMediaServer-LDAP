package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimedefault"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/config"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/hostcontract"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/ldapauth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
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

	var claims *structpb.Struct
	if user.Role != "" {
		claims, err = structpb.NewStruct(map[string]any{
			hostcontract.RoleContractClaim: hostcontract.ManagedRoleV1,
			hostcontract.RoleManagedClaim:  true,
			hostcontract.RoleClaim:         user.Role,
		})
		if err != nil {
			return nil, status.Error(codes.Internal, "could not construct managed-role claims")
		}
	}
	return &pluginv1.AuthenticateResponse{
		ExternalSubject: user.Subject,
		DisplayName:     user.DisplayName,
		Email:           user.Email,
		Claims:          claims,
	}, nil
}

func main() {
	manifest, err := publicmanifest.LoadWithChecksum(manifestJSON, version)
	if err != nil {
		panic(fmt.Errorf("load plugin manifest: %w", err))
	}

	auth := &authServer{}
	runtime := &runtimeServer{
		manifest: manifest,
		auth:     auth,
	}

	sdkruntime.Serve(sdkruntime.ServeConfig{
		Servers: sdkruntime.CapabilityServers{
			Runtime:      runtime,
			AuthProvider: auth,
		},
	})
}
