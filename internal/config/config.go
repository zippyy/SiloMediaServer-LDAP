package config

import (
	"crypto/x509"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/go-ldap/ldap/v3"
)

const EntryKey = "ldap"

var knownFields = map[string]struct{}{
	"url": {}, "start_tls": {}, "allow_insecure_plaintext": {}, "insecure_skip_verify": {},
	"server_name": {}, "ca_pem": {}, "bind_dn": {}, "bind_password": {}, "base_dn": {},
	"user_filter": {}, "subject_attribute": {}, "display_name_attribute": {}, "email_attribute": {},
	"group_attribute": {}, "required_groups": {}, "group_match_mode": {}, "role_sync_enabled": {},
	"admin_groups": {}, "admin_group_match_mode": {}, "timeout_seconds": {},
}

type Config struct {
	URL                    string
	StartTLS               bool
	AllowInsecurePlaintext bool
	InsecureSkipVerify     bool
	ServerName             string
	CAPEM                  string
	BindDN                 string
	BindPassword           string
	BaseDN                 string
	UserFilter             string
	SubjectAttribute       string
	DisplayNameAttribute   string
	EmailAttribute         string
	GroupAttribute         string
	RequiredGroups         []string
	GroupMatchMode         string
	RoleSyncEnabled        bool
	AdminGroups            []string
	AdminGroupMatchMode    string
	TimeoutSeconds         int
}

func Default() Config {
	return Config{
		UserFilter:           "(&(objectClass=person)(|(uid={username})(sAMAccountName={username})))",
		SubjectAttribute:     "entryUUID",
		DisplayNameAttribute: "displayName",
		EmailAttribute:       "mail",
		GroupAttribute:       "memberOf",
		GroupMatchMode:       "any",
		AdminGroupMatchMode:  "any",
		TimeoutSeconds:       10,
	}
}

func Decode(entries []*pluginv1.ConfigEntry) (Config, bool, error) {
	cfg := Default()
	var values map[string]any
	for _, entry := range entries {
		if entry == nil || entry.GetKey() != EntryKey {
			continue
		}
		if values != nil {
			return Config{}, true, fmt.Errorf("duplicate %q configuration entry", EntryKey)
		}
		if entry.GetValue() == nil {
			return Config{}, true, fmt.Errorf("configuration value must be an object")
		}
		values = entry.GetValue().AsMap()
	}
	if values == nil {
		return cfg, false, nil
	}
	if err := rejectUnknownFields(values); err != nil {
		return Config{}, true, err
	}

	var err error
	if cfg.URL, err = stringField(values, "url", cfg.URL, true); err != nil {
		return Config{}, true, err
	}
	if cfg.StartTLS, err = boolField(values, "start_tls", cfg.StartTLS); err != nil {
		return Config{}, true, err
	}
	if cfg.AllowInsecurePlaintext, err = boolField(values, "allow_insecure_plaintext", cfg.AllowInsecurePlaintext); err != nil {
		return Config{}, true, err
	}
	if cfg.InsecureSkipVerify, err = boolField(values, "insecure_skip_verify", cfg.InsecureSkipVerify); err != nil {
		return Config{}, true, err
	}
	if cfg.ServerName, err = stringField(values, "server_name", cfg.ServerName, true); err != nil {
		return Config{}, true, err
	}
	if cfg.CAPEM, err = stringField(values, "ca_pem", cfg.CAPEM, false); err != nil {
		return Config{}, true, err
	}
	if cfg.BindDN, err = stringField(values, "bind_dn", cfg.BindDN, true); err != nil {
		return Config{}, true, err
	}
	if cfg.BindPassword, err = stringField(values, "bind_password", cfg.BindPassword, false); err != nil {
		return Config{}, true, err
	}
	if cfg.BaseDN, err = stringField(values, "base_dn", cfg.BaseDN, true); err != nil {
		return Config{}, true, err
	}
	if cfg.UserFilter, err = stringField(values, "user_filter", cfg.UserFilter, true); err != nil {
		return Config{}, true, err
	}
	if cfg.SubjectAttribute, err = stringField(values, "subject_attribute", cfg.SubjectAttribute, true); err != nil {
		return Config{}, true, err
	}
	if cfg.DisplayNameAttribute, err = stringField(values, "display_name_attribute", cfg.DisplayNameAttribute, true); err != nil {
		return Config{}, true, err
	}
	if cfg.EmailAttribute, err = stringField(values, "email_attribute", cfg.EmailAttribute, true); err != nil {
		return Config{}, true, err
	}
	if cfg.GroupAttribute, err = stringField(values, "group_attribute", cfg.GroupAttribute, true); err != nil {
		return Config{}, true, err
	}
	requiredGroups, err := stringField(values, "required_groups", "", true)
	if err != nil {
		return Config{}, true, err
	}
	cfg.RequiredGroups = splitList(requiredGroups)
	if cfg.GroupMatchMode, err = stringField(values, "group_match_mode", cfg.GroupMatchMode, true); err != nil {
		return Config{}, true, err
	}
	cfg.GroupMatchMode = strings.ToLower(cfg.GroupMatchMode)
	if cfg.RoleSyncEnabled, err = boolField(values, "role_sync_enabled", cfg.RoleSyncEnabled); err != nil {
		return Config{}, true, err
	}
	adminGroups, err := stringField(values, "admin_groups", "", true)
	if err != nil {
		return Config{}, true, err
	}
	cfg.AdminGroups = splitList(adminGroups)
	if cfg.AdminGroupMatchMode, err = stringField(values, "admin_group_match_mode", cfg.AdminGroupMatchMode, true); err != nil {
		return Config{}, true, err
	}
	cfg.AdminGroupMatchMode = strings.ToLower(cfg.AdminGroupMatchMode)
	if cfg.TimeoutSeconds, err = intField(values, "timeout_seconds", cfg.TimeoutSeconds); err != nil {
		return Config{}, true, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, true, err
	}
	return cfg, true, nil
}

func (c Config) Validate() error {
	parsed, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("invalid LDAP URL: %w", err)
	}
	if parsed.Scheme != "ldap" && parsed.Scheme != "ldaps" {
		return fmt.Errorf("LDAP URL must use ldap:// or ldaps://")
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("LDAP URL must include a hostname")
	}
	if parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("LDAP URL must contain only a scheme, hostname, and optional port")
	}
	if parsed.Scheme == "ldaps" && c.StartTLS {
		return fmt.Errorf("StartTLS cannot be enabled with an ldaps:// URL")
	}
	if c.AllowInsecurePlaintext && (parsed.Scheme != "ldap" || c.StartTLS) {
		return fmt.Errorf("allow insecure plaintext is only valid for ldap:// without StartTLS")
	}
	if parsed.Scheme == "ldap" && !c.StartTLS && !c.AllowInsecurePlaintext {
		return fmt.Errorf("plaintext LDAP is disabled; enable StartTLS or explicitly allow insecure plaintext LDAP")
	}
	usesTLS := parsed.Scheme == "ldaps" || c.StartTLS
	if !usesTLS && (c.InsecureSkipVerify || c.ServerName != "" || strings.TrimSpace(c.CAPEM) != "") {
		return fmt.Errorf("TLS settings require LDAPS or StartTLS")
	}
	if (c.BindDN == "") != (c.BindPassword == "") {
		return fmt.Errorf("bind DN and bind password must either both be set or both be empty")
	}
	if c.BaseDN == "" {
		return fmt.Errorf("base DN is required")
	}
	if _, err := ldap.ParseDN(c.BaseDN); err != nil {
		return fmt.Errorf("base DN is invalid: %w", err)
	}
	if c.UserFilter == "" || !strings.Contains(c.UserFilter, "{username}") {
		return fmt.Errorf("user filter must contain {username}")
	}
	compiledFilter := strings.ReplaceAll(c.UserFilter, "{username}", ldap.EscapeFilter("silo-config-validation"))
	if _, err := ldap.CompileFilter(compiledFilter); err != nil {
		return fmt.Errorf("user filter is invalid: %w", err)
	}
	if c.SubjectAttribute == "" {
		return fmt.Errorf("subject attribute is required")
	}
	if (len(c.RequiredGroups) > 0 || len(c.AdminGroups) > 0) && c.GroupAttribute == "" {
		return fmt.Errorf("group attribute is required when group access or role mapping is configured")
	}
	if c.GroupMatchMode != "any" && c.GroupMatchMode != "all" {
		return fmt.Errorf("group match mode must be any or all")
	}
	if c.AdminGroupMatchMode != "any" && c.AdminGroupMatchMode != "all" {
		return fmt.Errorf("administrator group match mode must be any or all")
	}
	if c.RoleSyncEnabled && len(c.AdminGroups) == 0 {
		return fmt.Errorf("at least one administrator group is required when role synchronization is enabled")
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 60 {
		return fmt.Errorf("timeout must be between 1 and 60 seconds")
	}
	if strings.TrimSpace(c.CAPEM) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return fmt.Errorf("custom CA PEM did not contain a valid certificate")
		}
	}
	return nil
}

func (c Config) Timeout() time.Duration {
	return time.Duration(c.TimeoutSeconds) * time.Second
}

func rejectUnknownFields(values map[string]any) error {
	unknown := make([]string, 0)
	for key := range values {
		if _, ok := knownFields[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("unknown configuration field %q", unknown[0])
}

func stringField(values map[string]any, key, fallback string, trim bool) (string, error) {
	value, ok := values[key]
	if !ok {
		return fallback, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("configuration field %q must be a string", key)
	}
	if trim {
		text = strings.TrimSpace(text)
	}
	return text, nil
}

func boolField(values map[string]any, key string, fallback bool) (bool, error) {
	value, ok := values[key]
	if !ok {
		return fallback, nil
	}
	result, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("configuration field %q must be a boolean", key)
	}
	return result, nil
}

func intField(values map[string]any, key string, fallback int) (int, error) {
	value, ok := values[key]
	if !ok {
		return fallback, nil
	}
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number {
		return 0, fmt.Errorf("configuration field %q must be an integer number", key)
	}
	return int(number), nil
}

func splitList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';'
	})
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, exists := seen[part]; exists {
			continue
		}
		seen[part] = struct{}{}
		result = append(result, part)
	}
	return result
}
