package ldapauth

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/config"
)

func TestAuthenticateOperationSequences(t *testing.T) {
	allowed := testUserEntry("uid=alice,ou=people,dc=example,dc=com", "cn=users,dc=example,dc=com")
	denied := testUserEntry("uid=alice,ou=people,dc=example,dc=com", "cn=denied,dc=example,dc=com")
	invalidCredentials := ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))

	tests := []struct {
		name       string
		result     *ldap.SearchResult
		searchErr  error
		bindErrors map[string]error
		wantErr    error
		wantOps    []string
	}{
		{
			name:    "nonexistent username",
			result:  &ldap.SearchResult{},
			wantErr: ErrInvalidCredentials,
			wantOps: []string{"connect", "bind:cn=reader,dc=example,dc=com", "search", "bind:cn=__silo_auth_dummy__,dc=example,dc=com", "close"},
		},
		{
			name: "ambiguous username",
			result: &ldap.SearchResult{Entries: []*ldap.Entry{
				allowed,
				testUserEntry("uid=alice2,ou=people,dc=example,dc=com", "cn=users,dc=example,dc=com"),
			}},
			wantErr: ErrInvalidCredentials,
			wantOps: []string{"connect", "bind:cn=reader,dc=example,dc=com", "search", "bind:cn=__silo_auth_dummy__,dc=example,dc=com", "close"},
		},
		{
			name:      "size limit ambiguity",
			searchErr: ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("too many matches")),
			wantErr:   ErrInvalidCredentials,
			wantOps:   []string{"connect", "bind:cn=reader,dc=example,dc=com", "search", "bind:cn=__silo_auth_dummy__,dc=example,dc=com", "close"},
		},
		{
			name:    "existing denied user binds before authorization",
			result:  &ldap.SearchResult{Entries: []*ldap.Entry{denied}},
			wantErr: ErrGroupDenied,
			wantOps: []string{"connect", "bind:cn=reader,dc=example,dc=com", "search", "bind:uid=alice,ou=people,dc=example,dc=com", "close"},
		},
		{
			name:       "existing allowed user wrong password",
			result:     &ldap.SearchResult{Entries: []*ldap.Entry{allowed}},
			bindErrors: map[string]error{allowed.DN: invalidCredentials},
			wantErr:    ErrInvalidCredentials,
			wantOps:    []string{"connect", "bind:cn=reader,dc=example,dc=com", "search", "bind:uid=alice,ou=people,dc=example,dc=com", "close"},
		},
		{
			name:    "existing allowed user correct password",
			result:  &ldap.SearchResult{Entries: []*ldap.Entry{allowed}},
			wantOps: []string{"connect", "bind:cn=reader,dc=example,dc=com", "search", "bind:uid=alice,ou=people,dc=example,dc=com", "close"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := []string{}
			connection := &fakeLDAPConnection{
				operations: &operations,
				result:     test.result,
				searchErr:  test.searchErr,
				bindErrors: test.bindErrors,
			}
			authenticator := testAuthenticator(connection, &operations)

			user, err := authenticator.Authenticate(context.Background(), "alice", "submitted-password")
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("Authenticate() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("Authenticate() error = %v", err)
				}
				if user == nil || user.Subject != "entryuuid:subject-1" {
					t.Fatalf("Authenticate() user = %#v", user)
				}
			}
			if !slices.Equal(operations, test.wantOps) {
				t.Fatalf("operations = %#v, want %#v", operations, test.wantOps)
			}
		})
	}
}

func TestAuthenticateExpiredContextDoesNotConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	connected := false
	authenticator := New(validTestConfig())
	authenticator.connect = func(context.Context, time.Time) (ldapConnection, error) {
		connected = true
		return nil, errors.New("unexpected")
	}

	_, err := authenticator.Authenticate(ctx, "alice", "password")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Authenticate() error = %v, want context cancellation", err)
	}
	if connected {
		t.Fatal("expired request attempted an LDAP connection")
	}
}

func TestConnectionCheckUsesBoundedTransportBindAndBaseSearch(t *testing.T) {
	operations := []string{}
	connection := &fakeLDAPConnection{
		operations: &operations,
		result: &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("dc=example,dc=com", map[string][]string{"objectClass": {"domain"}}),
		}},
		bindErrors: map[string]error{},
	}
	authenticator := testAuthenticator(connection, &operations)

	if err := authenticator.TestConnection(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"connect", "bind:cn=reader,dc=example,dc=com", "search", "close"}
	if !slices.Equal(operations, want) {
		t.Fatalf("operations = %#v, want %#v", operations, want)
	}
}

func TestConnectionCheckFailsClosedWhenBaseIsNotVisible(t *testing.T) {
	operations := []string{}
	authenticator := testAuthenticator(&fakeLDAPConnection{
		operations: &operations,
		result:     &ldap.SearchResult{},
		bindErrors: map[string]error{},
	}, &operations)

	err := authenticator.TestConnection(context.Background())
	if err == nil || FailureStage(err) != StageDirectorySearch {
		t.Fatalf("TestConnection() error = %v, stage = %q", err, FailureStage(err))
	}
}

func TestConnectionCheckFailsClosedOnEmptyDirectoryResponse(t *testing.T) {
	operations := []string{}
	authenticator := testAuthenticator(&fakeLDAPConnection{
		operations: &operations,
		bindErrors: map[string]error{},
	}, &operations)
	// Prevent the fake from synthesizing an empty result so the new path also
	// covers a malformed nil success response from a connector implementation.
	authenticator.connect = func(context.Context, time.Time) (ldapConnection, error) {
		operations = append(operations, "connect")
		return &nilSearchResultConnection{operations: &operations}, nil
	}

	err := authenticator.TestConnection(context.Background())
	if err == nil || FailureStage(err) != StageDirectorySearch {
		t.Fatalf("TestConnection() error = %v, stage = %q", err, FailureStage(err))
	}
}

func TestManagedConnectionCancellationWakesBlockedBind(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	ldapConn := ldap.NewConn(client, false)
	ldapConn.Start()
	ctx, cancel := context.WithCancel(context.Background())
	managed := newManagedLDAPConn(ctx, time.Now().Add(5*time.Second), ldapConn, client)

	requestRead := make(chan struct{})
	go func() {
		buffer := make([]byte, 4096)
		_, _ = server.Read(buffer)
		close(requestRead)
	}()
	done := make(chan error, 1)
	go func() { done <- managed.Bind("uid=alice,dc=example,dc=com", "password") }()

	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("LDAP bind request was not written")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Bind() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked LDAP bind did not wake after cancellation")
	}
	_ = managed.Close()
}

func TestManagedConnectionAppliesAbsoluteSocketDeadline(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	recording := &recordingConn{Conn: client}
	ldapConn := ldap.NewConn(recording, false)
	ldapConn.Start()
	deadline := time.Now().Add(time.Minute).Round(0)
	managed := newManagedLDAPConn(context.Background(), deadline, ldapConn, recording)

	if err := managed.beforeOperation(); err != nil {
		t.Fatalf("beforeOperation() error = %v", err)
	}
	if got := recording.lastDeadline(); !got.Equal(deadline) {
		t.Fatalf("socket deadline = %v, want %v", got, deadline)
	}
	_ = managed.Close()
}

func TestDialTLSPhasesHonorContextDeadline(t *testing.T) {
	for _, test := range []struct {
		name     string
		scheme   string
		startTLS bool
	}{
		{name: "LDAPS handshake", scheme: "ldaps"},
		{name: "StartTLS negotiation", scheme: "ldap", startTLS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			accepted := make(chan struct{})
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer conn.Close()
				close(accepted)
				buffer := make([]byte, 4096)
				_, _ = conn.Read(buffer)
				<-time.After(2 * time.Second)
			}()

			cfg := validTestConfig()
			cfg.URL = test.scheme + "://" + listener.Addr().String()
			cfg.StartTLS = test.startTLS
			cfg.AllowInsecurePlaintext = false
			authenticator := New(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			deadline, _ := ctx.Deadline()
			started := time.Now()
			_, err = authenticator.dial(ctx, deadline)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("dial() error = %v, want deadline exceeded", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("TLS phase exceeded request deadline: %v", elapsed)
			}
			select {
			case <-accepted:
			default:
				t.Fatal("test server did not accept the connection")
			}
		})
	}
}

func TestGroupValuesEqual(t *testing.T) {
	tests := []struct {
		name        string
		left, right string
		want        bool
	}{
		{name: "DN case", left: "CN=Admins,OU=Groups,DC=Example,DC=COM", right: "cn=admins,ou=groups,dc=example,dc=com", want: true},
		{name: "escaped comma", left: `CN=Ops\, Media,OU=Groups,DC=example,DC=com`, right: `cn=ops\2c media,ou=groups,dc=example,dc=com`, want: true},
		{name: "multivalued RDN order", left: "CN=Admins+UID=42,OU=Groups,DC=example,DC=com", right: "uid=42+cn=admins,ou=groups,dc=example,dc=com", want: true},
		{name: "RDN order remains significant", left: "CN=Admins,OU=Groups,DC=example,DC=com", right: "OU=Groups,CN=Admins,DC=example,DC=com", want: false},
		{name: "malformed values exact fallback", left: "not a dn", right: "not a dn", want: true},
		{name: "malformed values do not case fold", left: "not a dn", right: "NOT A DN", want: false},
		{name: "opaque custom values are exact", left: "Admin", right: "admin", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := groupValuesEqual(test.left, test.right); got != test.want {
				t.Fatalf("groupValuesEqual(%q, %q) = %v, want %v", test.left, test.right, got, test.want)
			}
		})
	}
}

func TestGroupsAllowedAnyAllAndDuplicates(t *testing.T) {
	actual := []string{"CN=Users,DC=example,DC=com", "opaque-value"}
	if !groupsAllowed(actual, []string{"cn=users,dc=example,dc=com", "CN=USERS,DC=EXAMPLE,DC=COM"}, "all") {
		t.Fatal("structural duplicate DNs should satisfy all mode")
	}
	if !groupsAllowed(actual, []string{"missing", "opaque-value"}, "any") {
		t.Fatal("any mode did not accept one opaque exact match")
	}
	if groupsAllowed(actual, []string{"Opaque-Value"}, "any") {
		t.Fatal("opaque values must not be case-folded")
	}
}

func TestRoleForGroups(t *testing.T) {
	cfg := config.Default()
	cfg.RoleSyncEnabled = true
	cfg.AdminGroups = []string{"CN=SiloAdmins,OU=Groups,DC=example,DC=com"}

	if role := roleForGroups([]string{"cn=siloadmins,ou=groups,dc=example,dc=com"}, cfg); role != "admin" {
		t.Fatalf("administrator role = %q, want admin", role)
	}
	if role := roleForGroups([]string{"cn=silousers,ou=groups,dc=example,dc=com"}, cfg); role != "user" {
		t.Fatalf("normal role = %q, want user", role)
	}

	cfg.RoleSyncEnabled = false
	if role := roleForGroups([]string{"cn=siloadmins,ou=groups,dc=example,dc=com"}, cfg); role != "" {
		t.Fatalf("disabled role sync returned %q, want empty", role)
	}
}

func TestStableSubjectUsesBinaryObjectGUID(t *testing.T) {
	entry := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{Name: "objectGUID", ByteValues: [][]byte{{0x01, 0x02, 0xab}}}}}
	subject, err := stableSubject(entry, "objectGUID")
	if err != nil {
		t.Fatalf("stableSubject returned an error: %v", err)
	}
	if subject != "objectguid:0102ab" {
		t.Fatalf("subject = %q, want objectguid:0102ab", subject)
	}
}

func TestStableSubjectPreservesExactText(t *testing.T) {
	entry := ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
		"entryUUID": {" subject-1 "},
	})
	subject, err := stableSubject(entry, "entryUUID")
	if err != nil {
		t.Fatalf("stableSubject returned an error: %v", err)
	}
	if subject != "entryuuid: subject-1 " {
		t.Fatalf("subject = %q, want exact attribute whitespace preserved", subject)
	}
}

func TestStableSubjectRejectsMultipleValues(t *testing.T) {
	entry := ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
		"externalID": {"subject-1", "subject-2"},
	})
	if _, err := stableSubject(entry, "externalID"); err == nil {
		t.Fatal("stableSubject accepted a multivalued identity attribute")
	}
}

func TestStableSubjectRejectsUnsupportedBinaryValue(t *testing.T) {
	entry := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{
		Name: "externalID", ByteValues: [][]byte{{0xff, 0x00, 0x7f}},
	}}}
	if _, err := stableSubject(entry, "externalID"); err == nil {
		t.Fatal("stableSubject accepted a binary attribute without a canonical encoding")
	}
}

func TestBuildUserFilterEscapesEveryUsernamePlaceholder(t *testing.T) {
	username := "nick*)(|(objectClass=*))"
	filter, err := buildUserFilter(
		"(&(uid={username})(mail={username}@example.com))",
		username,
	)
	if err != nil {
		t.Fatalf("buildUserFilter returned an error: %v", err)
	}
	if strings.Contains(filter, "nick*)(|") || strings.Contains(filter, "{username}") {
		t.Fatalf("username placeholder was not safely replaced: %q", filter)
	}
	escaped := ldap.EscapeFilter(username)
	if strings.Count(filter, escaped) != 2 {
		t.Fatalf("filter %q does not contain escaped username %q twice", filter, escaped)
	}
}

func TestBuildUserFilterRejectsInvalidTemplate(t *testing.T) {
	if _, err := buildUserFilter("(&(objectClass=user)", "nick"); err == nil {
		t.Fatal("expected malformed LDAP filter to be rejected")
	}
}

type fakeLDAPConnection struct {
	operations *[]string
	result     *ldap.SearchResult
	searchErr  error
	bindErrors map[string]error
}

type nilSearchResultConnection struct{ operations *[]string }

func (c *nilSearchResultConnection) Bind(username, _ string) error {
	*c.operations = append(*c.operations, "bind:"+username)
	return nil
}

func (c *nilSearchResultConnection) Search(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	*c.operations = append(*c.operations, "search")
	return nil, nil
}

func (c *nilSearchResultConnection) Close() error {
	*c.operations = append(*c.operations, "close")
	return nil
}

func (f *fakeLDAPConnection) Bind(username, _ string) error {
	*f.operations = append(*f.operations, "bind:"+username)
	return f.bindErrors[username]
}

func (f *fakeLDAPConnection) Search(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	*f.operations = append(*f.operations, "search")
	if f.result == nil {
		f.result = &ldap.SearchResult{}
	}
	return f.result, f.searchErr
}

func (f *fakeLDAPConnection) Close() error {
	*f.operations = append(*f.operations, "close")
	return nil
}

func testAuthenticator(connection ldapConnection, operations *[]string) *Authenticator {
	authenticator := New(validTestConfig())
	authenticator.connect = func(context.Context, time.Time) (ldapConnection, error) {
		*operations = append(*operations, "connect")
		return connection, nil
	}
	return authenticator
}

func validTestConfig() config.Config {
	cfg := config.Default()
	cfg.URL = "ldaps://ldap.example.com:636"
	cfg.BaseDN = "dc=example,dc=com"
	cfg.BindDN = "cn=reader,dc=example,dc=com"
	cfg.BindPassword = "reader-password"
	cfg.RequiredGroups = []string{"cn=users,dc=example,dc=com"}
	return cfg
}

func testUserEntry(dn, group string) *ldap.Entry {
	return ldap.NewEntry(dn, map[string][]string{
		"entryUUID":   {"subject-1"},
		"displayName": {"Alice"},
		"mail":        {"alice@example.com"},
		"memberOf":    {group},
	})
}

type recordingConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

func (c *recordingConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func (c *recordingConn) lastDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}
