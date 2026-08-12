package ldapauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/zippyy/SiloMediaServer-LDAP/internal/config"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrGroupDenied        = errors.New("user is not a member of an allowed LDAP group")
)

type Stage string

const (
	StageConnection        Stage = "connection"
	StageTLS               Stage = "TLS"
	StageSearchAccountBind Stage = "search-account bind"
	StageFilter            Stage = "filter"
	StageUserSearch        Stage = "user search"
	StageDirectorySearch   Stage = "directory search"
	StageUserBind          Stage = "user bind"
	StageIdentityMapping   Stage = "identity mapping"
	StageTimeout           Stage = "timeout"
	StageRequest           Stage = "request cancellation"
	StageDirectory         Stage = "directory processing"
)

type StageError struct {
	Stage Stage
	Err   error
}

func (e *StageError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %v", e.Stage, e.Err)
}

func (e *StageError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func FailureStage(err error) Stage {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return StageTimeout
	case errors.Is(err, context.Canceled):
		return StageRequest
	}
	var staged *StageError
	if errors.As(err, &staged) && staged.Stage != "" {
		return staged.Stage
	}
	return StageDirectory
}

type User struct {
	Subject     string
	Username    string
	DisplayName string
	Email       string
	DN          string
	Groups      []string
	Role        string
}

type ldapConnection interface {
	Bind(username, password string) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

type connector func(context.Context, time.Time) (ldapConnection, error)

type Authenticator struct {
	config  config.Config
	connect connector
}

func New(cfg config.Config) *Authenticator {
	authenticator := &Authenticator{config: cfg}
	authenticator.connect = authenticator.dial
	return authenticator
}

func (a *Authenticator) Authenticate(parent context.Context, username, password string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	ctx, cancel, deadline, err := a.operationContext(parent)
	if err != nil {
		return nil, err
	}
	defer cancel()

	conn, err := a.connect(ctx, deadline)
	if err != nil {
		return nil, staged(StageConnection, err)
	}
	defer func() { _ = conn.Close() }()

	if a.config.BindDN != "" {
		if err := conn.Bind(a.config.BindDN, a.config.BindPassword); err != nil {
			return nil, staged(StageSearchAccountBind, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	entry, ambiguous, err := a.findUser(conn, username)
	if err != nil {
		return nil, err
	}
	if ambiguous {
		a.dummyBind(ctx, conn, password)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}

	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, staged(StageUserBind, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	groups := entry.GetEqualFoldAttributeValues(a.config.GroupAttribute)
	if !groupsAllowed(groups, a.config.RequiredGroups, a.config.GroupMatchMode) {
		return nil, ErrGroupDenied
	}

	subject, err := stableSubject(entry, a.config.SubjectAttribute)
	if err != nil {
		return nil, staged(StageIdentityMapping, err)
	}
	displayName := strings.TrimSpace(entry.GetEqualFoldAttributeValue(a.config.DisplayNameAttribute))
	if displayName == "" {
		displayName = username
	}

	return &User{
		Subject:     subject,
		Username:    username,
		DisplayName: displayName,
		Email:       strings.TrimSpace(entry.GetEqualFoldAttributeValue(a.config.EmailAttribute)),
		DN:          entry.DN,
		Groups:      append([]string(nil), groups...),
		Role:        roleForGroups(groups, a.config),
	}, nil
}

// TestConnection verifies transport security, the configured search-account
// bind, and visibility of the configured base DN. It deliberately does not
// authenticate an end user or evaluate group membership.
func (a *Authenticator) TestConnection(parent context.Context) error {
	ctx, cancel, deadline, err := a.operationContext(parent)
	if err != nil {
		return err
	}
	defer cancel()

	conn, err := a.connect(ctx, deadline)
	if err != nil {
		return staged(StageConnection, err)
	}
	defer func() { _ = conn.Close() }()

	if a.config.BindDN != "" {
		if err := conn.Bind(a.config.BindDN, a.config.BindPassword); err != nil {
			return staged(StageSearchAccountBind, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	result, err := conn.Search(ldap.NewSearchRequest(
		a.config.BaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		return staged(StageDirectorySearch, err)
	}
	if result == nil || len(result.Entries) != 1 {
		return staged(StageDirectorySearch, fmt.Errorf("configured base DN did not resolve to exactly one entry"))
	}
	return ctx.Err()
}

func (a *Authenticator) operationContext(parent context.Context) (context.Context, context.CancelFunc, time.Time, error) {
	if err := parent.Err(); err != nil {
		return nil, nil, time.Time{}, err
	}
	deadline := time.Now().Add(a.config.Timeout())
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, nil, time.Time{}, err
	}
	return ctx, cancel, deadline, nil
}

func (a *Authenticator) dummyBind(ctx context.Context, conn ldapConnection, password string) {
	if ctx.Err() != nil {
		return
	}
	dummyDN := "cn=__silo_auth_dummy__," + a.config.BaseDN
	_ = conn.Bind(dummyDN, password)
}

func roleForGroups(groups []string, cfg config.Config) string {
	if !cfg.RoleSyncEnabled {
		return ""
	}
	if groupsAllowed(groups, cfg.AdminGroups, cfg.AdminGroupMatchMode) {
		return "admin"
	}
	return "user"
}

func (a *Authenticator) dial(ctx context.Context, deadline time.Time) (ldapConnection, error) {
	tlsConfig, err := a.tlsConfig()
	if err != nil {
		return nil, staged(StageTLS, err)
	}
	parsed, err := url.Parse(a.config.URL)
	if err != nil {
		return nil, err
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "ldaps" {
			port = ldap.DefaultLdapsPort
		} else {
			port = ldap.DefaultLdapPort
		}
	}

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(parsed.Hostname(), port))
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return nil, err
	}

	var socket net.Conn = raw
	isTLS := parsed.Scheme == "ldaps"
	if isTLS {
		tlsConn := tls.Client(raw, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, staged(StageTLS, operationError(ctx, deadline, err))
		}
		socket = tlsConn
	}

	conn := ldap.NewConn(socket, isTLS)
	conn.Start()
	managed := newManagedLDAPConn(ctx, deadline, conn, socket)
	if parsed.Scheme == "ldap" && a.config.StartTLS {
		if err := managed.beforeOperation(); err != nil {
			_ = managed.Close()
			return nil, err
		}
		if err := conn.StartTLS(tlsConfig); err != nil {
			_ = managed.Close()
			return nil, staged(StageTLS, operationError(ctx, deadline, err))
		}
	}
	return managed, nil
}

func (a *Authenticator) tlsConfig() (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if strings.TrimSpace(a.config.CAPEM) != "" {
		if ok := roots.AppendCertsFromPEM([]byte(a.config.CAPEM)); !ok {
			return nil, fmt.Errorf("custom CA PEM did not contain a valid certificate")
		}
	}

	serverName := a.config.ServerName
	if serverName == "" {
		parsed, err := url.Parse(a.config.URL)
		if err == nil {
			serverName = parsed.Hostname()
		}
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            roots,
		ServerName:         serverName,
		InsecureSkipVerify: a.config.InsecureSkipVerify, //nolint:gosec // explicit operator setting
	}, nil
}

func (a *Authenticator) findUser(conn ldapConnection, username string) (*ldap.Entry, bool, error) {
	filter, err := buildUserFilter(a.config.UserFilter, username)
	if err != nil {
		return nil, false, staged(StageFilter, err)
	}
	attributes := uniqueNonEmpty(
		a.config.SubjectAttribute,
		a.config.DisplayNameAttribute,
		a.config.EmailAttribute,
		a.config.GroupAttribute,
	)
	request := ldap.NewSearchRequest(
		a.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		0,
		false,
		filter,
		attributes,
		nil,
	)
	result, err := conn.Search(request)
	if err != nil {
		if errors.Is(err, ldap.ErrSizeLimitExceeded) || ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, true, nil
		}
		return nil, false, staged(StageUserSearch, err)
	}
	if len(result.Entries) != 1 {
		return nil, true, nil
	}
	return result.Entries[0], false, nil
}

func buildUserFilter(template, username string) (string, error) {
	filter := strings.ReplaceAll(template, "{username}", ldap.EscapeFilter(username))
	if _, err := ldap.CompileFilter(filter); err != nil {
		return "", err
	}
	return filter, nil
}

func stableSubject(entry *ldap.Entry, attribute string) (string, error) {
	attribute = strings.TrimSpace(attribute)
	values := entry.GetEqualFoldRawAttributeValues(attribute)
	if len(values) != 1 || len(values[0]) == 0 {
		return "", fmt.Errorf("LDAP subject attribute %q must contain exactly one non-empty value", attribute)
	}
	raw := values[0]

	if strings.EqualFold(attribute, "objectGUID") || strings.EqualFold(attribute, "objectSid") {
		return strings.ToLower(attribute) + ":" + hex.EncodeToString(raw), nil
	}
	if utf8.Valid(raw) {
		return strings.ToLower(attribute) + ":" + string(raw), nil
	}
	return "", fmt.Errorf("LDAP subject attribute %q is binary but has no supported canonical encoding", attribute)
}

func groupsAllowed(actual, required []string, mode string) bool {
	if len(required) == 0 {
		return true
	}
	matched := 0
	for _, expected := range required {
		found := false
		for _, candidate := range actual {
			if groupValuesEqual(candidate, expected) {
				found = true
				break
			}
		}
		if found {
			matched++
			if mode == "any" {
				return true
			}
		} else if mode == "all" {
			return false
		}
	}
	return mode == "all" && matched == len(required)
}

func groupValuesEqual(left, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	leftDN, leftErr := ldap.ParseDN(left)
	rightDN, rightErr := ldap.ParseDN(right)
	if leftErr == nil && rightErr == nil && len(leftDN.RDNs) > 0 && len(rightDN.RDNs) > 0 {
		return leftDN.EqualFold(rightDN)
	}
	return left == right
}

func uniqueNonEmpty(values ...string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func staged(stage Stage, err error) error {
	if err == nil {
		return nil
	}
	var existing *StageError
	if errors.As(err, &existing) {
		return err
	}
	return &StageError{Stage: stage, Err: err}
}

type managedLDAPConn struct {
	ctx      context.Context
	deadline time.Time
	conn     *ldap.Conn
	socket   net.Conn
	stop     chan struct{}
	close    sync.Once
}

func newManagedLDAPConn(ctx context.Context, deadline time.Time, conn *ldap.Conn, socket net.Conn) *managedLDAPConn {
	managed := &managedLDAPConn{
		ctx: ctx, deadline: deadline, conn: conn, socket: socket, stop: make(chan struct{}),
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = socket.SetDeadline(time.Now())
			_ = socket.Close()
		case <-managed.stop:
		}
	}()
	return managed
}

func (c *managedLDAPConn) beforeOperation() error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	remaining := time.Until(c.deadline)
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	if err := c.socket.SetDeadline(c.deadline); err != nil {
		return err
	}
	c.conn.SetTimeout(remaining)
	return nil
}

func (c *managedLDAPConn) Bind(username, password string) error {
	if err := c.beforeOperation(); err != nil {
		return err
	}
	return operationError(c.ctx, c.deadline, c.conn.Bind(username, password))
}

func (c *managedLDAPConn) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if err := c.beforeOperation(); err != nil {
		return nil, err
	}
	result, err := c.conn.Search(request)
	return result, operationError(c.ctx, c.deadline, err)
}

func (c *managedLDAPConn) Close() error {
	var closeErr error
	c.close.Do(func() {
		close(c.stop)
		remaining := time.Until(c.deadline)
		if remaining <= 0 || remaining > 50*time.Millisecond {
			remaining = 50 * time.Millisecond
		}
		c.conn.SetTimeout(remaining)
		closeErr = c.conn.Close()
	})
	return closeErr
}

func operationError(ctx context.Context, deadline time.Time, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var netErr net.Error
	if err != nil && errors.As(err, &netErr) && netErr.Timeout() && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}
