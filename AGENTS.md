# Silo LDAP Authentication Plugin

Go plugin for Silo Media Server that provides LDAP/Active Directory password authentication via
the `auth_provider.v1` capability. `main.go` is the gRPC entrypoint that bridges the plugin SDK to
the `internal/ldapauth` authenticator; `internal/config` decodes and validates the plugin's
configuration block.

## Priorities

Security first. Every code path must produce the same observable result for missing users, wrong
passwords, and denied groups — no timing or error-message distinctions that leak directory
topology. Credentials are never logged. Plaintext LDAP is rejected by default and requires an
explicit dangerous opt-in.

## Building and verifying

```bash
make test        # go test ./...
make vet         # go vet ./...
make build VERSION=0.3.1
```

Go 1.26 or newer is required (the current Silo plugin SDK requires it).

CI runs on every push to `main` and `agent/**` branches, and on pull requests. It verifies
`go mod tidy` is clean, runs tests, vet, and a build check.

## Architecture

```
main.go                  → gRPC server, manifest, Configure/Authenticate handlers
internal/
  config/config.go       → Config struct, Decode from pluginpb.ConfigEntry, Validate
  ldapauth/
    authenticator.go     → Authenticator: dial, bind, search, authenticate, CheckConnection
```

The `authServer` in `main.go` wraps an `ldapauth.Authenticator` behind a `sync.RWMutex` —
`Configure` swaps the authenticator atomically, and `Authenticate` reads it under the read lock so
reconfigures never race with in-flight logins.

## Error classification

The `Authenticate` handler in `main.go` maps `ldapauth` errors to gRPC status codes. Invalid
credentials and group denials return an empty response (no gRPC error) so Silo treats them as
ordinary failed logins. Infrastructure errors (connection refused, search failure, timeout) return
`Unavailable` with a classified failure stage for diagnostics. `ldapAuthenticationFailureStage`
classifies errors by their wrapped message prefix — keep that mapping in sync when adding new
error paths in the authenticator.

## Stable subjects

The `stableSubject` function in `authenticator.go` produces a durable external identity from the
configured attribute. For `objectGUID` and `objectSid` it hex-encodes the raw binary value; for
other attributes it uses the string value if it's valid UTF-8, falling back to hex-encoded raw
bytes. The result is always prefixed `attributename:value` so the attribute name is part of the
identity and a later attribute change is detectable.

## Pull requests

Conventional Commit subjects (`feat(ldap): add group DN validation`). One concern per PR.

AI-use disclosure is required. Follow the same disclosure block used in the
[Silo server](https://github.com/Silo-Server/silo-server) repo — tool, exact model ID, involvement
level, and adversarial review summary. Undisclosed AI use gets the PR closed.
