# Silo Media Server LDAP Authentication

An LDAP authentication provider plugin for [Silo Media Server](https://github.com/Silo-Server/silo-server).

The plugin implements Silo's `auth_provider.v1` password flow and supports:

- Synology LDAP Server and other OpenLDAP-compatible directories
- Synology Directory Server and Microsoft Active Directory
- LDAPS and StartTLS
- Read-only service-account searches or anonymous searches
- Stable Silo identities through `entryUUID`, `objectGUID`, or another configured attribute
- Optional direct LDAP group allowlisting
- Optional LDAP administrator-group to Silo-role synchronization
- Configuration connection testing
- Linux AMD64 and ARM64 builds for common Docker and Synology deployments

## Authentication flow

1. Silo sends the submitted username and password to the plugin.
2. The plugin connects to LDAP and optionally binds with a read-only search account.
3. It searches for exactly one user with the configured filter.
4. It binds as the discovered user DN with the submitted password.
5. Only after a successful password bind does it check optional direct group membership.
6. It returns a stable external subject, display name, email address, and, when enabled, versioned managed-role claims.
7. Silo creates the session, optionally provisions the account, and applies a role only when the host authorized the advertised managed-role contract.

Zero-result, multiple-result, and server size-limit searches perform a bind attempt against a reserved dummy DN before returning the same invalid-login result. This removes the most obvious password-bind operation-count oracle; it is not a claim of cryptographic constant-time behavior or indistinguishable directory response timing.

The plugin never stores user passwords and does not log credentials.

## Recommended directory settings

### Synology LDAP Server / OpenLDAP

| Setting | Example |
| --- | --- |
| LDAP URL | `ldaps://nas.example.com:636` |
| Base DN | `dc=example,dc=com` |
| User filter | `(&(objectClass=person)(uid={username}))` |
| Subject attribute | `entryUUID` |
| Display-name attribute | `displayName` or `cn` |
| Email attribute | `mail` |
| Group attribute | `memberOf` |

### Active Directory / Synology Directory Server

| Setting | Example |
| --- | --- |
| LDAP URL | `ldaps://dc01.example.com:636` |
| Base DN | `dc=example,dc=com` |
| User filter | `(&(objectClass=user)(sAMAccountName={username}))` |
| Subject attribute | `objectGUID` |
| Display-name attribute | `displayName` |
| Email attribute | `mail` |
| Group attribute | `memberOf` |

`{username}` is escaped with LDAP filter escaping before the search is performed.

The external subject includes the lowercased subject-attribute name and one exact, non-empty attribute value. Textual values preserve whitespace and case. Binary `objectGUID` and `objectSid` values use explicit canonical hex encoding; other non-UTF-8 subject attributes are rejected rather than assigned a potentially ambiguous representation. Multivalued subject attributes are rejected because value ordering is not a stable identity. Changing the configured subject attribute changes the Silo identity namespace and can provision a different Silo account, so treat that setting as immutable after users first sign in.

## Active Directory group and role mapping

For the `nbennett.xyz` directory, use:

| Purpose | Group DN |
| --- | --- |
| Allowed normal users | `CN=JellyfinUsers,OU=groups,DC=nbennett,DC=xyz` |
| Silo administrators | `CN=JellyfinAdmins,OU=groups,DC=nbennett,DC=xyz` |

Configure the user group under **Sign-in group DNs**, enable **Synchronize Silo roles from LDAP**, and place the administrator group under **Administrator group DNs**.

When role synchronization is enabled:

- a member of the configured administrator group receives the Silo `admin` role;
- any other LDAP user who passes the sign-in allowlist receives the Silo `user` role;
- promotions and demotions are applied on the next successful LDAP login;
- removing a user from the administrator group demotes that account back to normal user permissions.

Role authority uses the temporary versioned `silo.auth.managed-role.v1` host extension. The plugin emits `silo_role_contract`, `silo_role_managed`, and `silo_role` only when role synchronization is enabled. A compatible Silo host must also authorize that exact contract from the installed capability metadata; a bare role claim is not authoritative.

Administrator accounts must still satisfy the sign-in allowlist. Add administrators to both groups, nest the administrator group inside the user group where your directory exposes the membership as required, or include both group DNs in the sign-in allowlist with **Any configured group** selected.

## Security defaults

- Plain `ldap://` connections are rejected unless StartTLS is enabled.
- Plaintext LDAP can only be enabled through an explicit dangerous setting.
- TLS 1.2 or later is required.
- Certificate verification is enabled by default.
- A private CA certificate can be supplied in PEM format.
- User searches are limited to two results and authentication fails unless exactly one entry matches.
- Missing users, ambiguous users, wrong passwords, and denied groups produce the same caller-visible login result. Found users are password-verified before group authorization.
- One absolute deadline, bounded by the host request context, covers TCP connection setup, LDAPS or StartTLS negotiation, binds, searches, and connection testing. Cancellation closes the socket to wake blocked LDAP I/O.
- Managed-role claims are limited to `user` and `admin`. They are not applied unless both plugin and host opt into the exact v1 contract; malformed authoritative claims fail authentication closed.

Keep a working local Silo administrator account for recovery.

## Build

Go 1.26 or newer is required because the current Silo plugin SDK requires it.

```bash
go test ./...
make build VERSION=0.4.0
```

The resulting binary is written to `dist/silo-plugin-auth-ldap`.

## Release artifacts

Tags matching `v*` trigger Linux AMD64 and ARM64 builds. Each release contains:

- `plugin-linux-amd64`
- `plugin-linux-arm64`
- `checksums.txt`

The workflow also generates platform-specific manifests with the binary checksum during the build.

## Current limitations

- Group checks use direct values on the configured user attribute, normally `memberOf`.
- When both a configured group and a returned value parse as LDAP DNs, comparison is structural and case-insensitive for practical AD, Synology, and OpenLDAP interoperability. RDN order remains significant, while attribute order inside a multi-valued RDN does not. This is not full schema-aware LDAP matching-rule evaluation.
- Values that do not parse as DNs are treated as opaque, trimmed, case-sensitive strings. This supports custom group attributes without pretending they have DN semantics.
- Nested Active Directory group resolution is not yet implemented.
- LDAP groups do not yet map to individual Silo libraries or granular permissions.
- Password changes, account linking, and full LDAP directory synchronization are outside the password-provider contract.

## What Test connection verifies

Silo calls the SDK `request_router.v1` `TestConnection` RPC for the LDAP configuration key and requires an explicit `ok: true` response. The check uses the same absolute timeout, network transport, certificate verification, optional StartTLS, and optional search-account bind as authentication. It then executes the configured user filter under the base DN while requesting no user attributes.

The check does not bind as a real user, verify a user password, require configured group objects to be readable, prove group membership visibility, or prove that the configured subject/display/email attributes are populated on every account. Those checks require a real directory account and remain deployment validation tasks.

## License

MIT
