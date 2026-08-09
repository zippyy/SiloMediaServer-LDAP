package config

import (
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestDecodeAllowsMissingConfig(t *testing.T) {
	cfg, configured, err := Decode(nil)
	if err != nil {
		t.Fatalf("Decode returned an error: %v", err)
	}
	if configured {
		t.Fatal("expected missing configuration to remain unconfigured")
	}
	if cfg.TimeoutSeconds != 10 {
		t.Fatalf("default timeout = %d, want 10", cfg.TimeoutSeconds)
	}
}

func TestDecodeValidLDAPSConfig(t *testing.T) {
	value, err := structpb.NewStruct(map[string]any{
		"url":                    "ldaps://ldap.example.com:636",
		"base_dn":                "dc=example,dc=com",
		"bind_dn":                "cn=silo,dc=example,dc=com",
		"bind_password":          "secret",
		"required_groups":        "cn=silo-users,ou=groups,dc=example,dc=com\ncn=media,ou=groups,dc=example,dc=com",
		"group_match_mode":       "all",
		"role_sync_enabled":      true,
		"admin_groups":           "cn=silo-admins,ou=groups,dc=example,dc=com",
		"admin_group_match_mode": "any",
		"timeout_seconds":        15,
		"subject_attribute":      "entryUUID",
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg, configured, err := Decode([]*pluginv1.ConfigEntry{{Key: EntryKey, Value: value}})
	if err != nil {
		t.Fatalf("Decode returned an error: %v", err)
	}
	if !configured {
		t.Fatal("expected configuration to be detected")
	}
	if len(cfg.RequiredGroups) != 2 {
		t.Fatalf("required groups = %d, want 2", len(cfg.RequiredGroups))
	}
	if cfg.GroupMatchMode != "all" {
		t.Fatalf("group match mode = %q, want all", cfg.GroupMatchMode)
	}
	if !cfg.RoleSyncEnabled {
		t.Fatal("expected role synchronization to be enabled")
	}
	if len(cfg.AdminGroups) != 1 {
		t.Fatalf("administrator groups = %d, want 1", len(cfg.AdminGroups))
	}
}

func TestValidateRejectsPlaintextByDefault(t *testing.T) {
	cfg := Default()
	cfg.URL = "ldap://ldap.example.com:389"
	cfg.BaseDN = "dc=example,dc=com"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected plaintext LDAP configuration to be rejected")
	}
}

func TestValidateRequiresAdminGroupForRoleSync(t *testing.T) {
	cfg := Default()
	cfg.URL = "ldaps://ldap.example.com:636"
	cfg.BaseDN = "dc=example,dc=com"
	cfg.RoleSyncEnabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected role synchronization without an administrator group to be rejected")
	}
}

func TestDecodeRejectsUnknownAndWrongTypedFields(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		value  any
		marker string
	}{
		{name: "unknown", field: "future_option", value: true, marker: "unknown configuration field"},
		{name: "bool string", field: "role_sync_enabled", value: "true", marker: "must be a boolean"},
		{name: "string bool", field: "subject_attribute", value: true, marker: "must be a string"},
		{name: "numeric string", field: "timeout_seconds", value: "15", marker: "must be an integer number"},
		{name: "fractional number", field: "timeout_seconds", value: 1.9, marker: "must be an integer number"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := validConfigValues()
			values[test.field] = test.value
			_, _, err := Decode([]*pluginv1.ConfigEntry{{Key: EntryKey, Value: mustStruct(t, values)}})
			if err == nil || !strings.Contains(err.Error(), test.marker) {
				t.Fatalf("Decode() error = %v, want marker %q", err, test.marker)
			}
		})
	}
}

func TestDecodePreservesBindPasswordWhitespace(t *testing.T) {
	values := validConfigValues()
	values["bind_dn"] = "cn=reader,dc=example,dc=com"
	values["bind_password"] = "  secret with spaces  "
	cfg, configured, err := Decode([]*pluginv1.ConfigEntry{{Key: EntryKey, Value: mustStruct(t, values)}})
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !configured || cfg.BindPassword != "  secret with spaces  " {
		t.Fatalf("bind password = %q; whitespace was not preserved", cfg.BindPassword)
	}
}

func TestDecodeRejectsDuplicateLDAPEntries(t *testing.T) {
	entry := &pluginv1.ConfigEntry{Key: EntryKey, Value: mustStruct(t, validConfigValues())}
	if _, _, err := Decode([]*pluginv1.ConfigEntry{entry, entry}); err == nil {
		t.Fatal("Decode() accepted duplicate LDAP configuration entries")
	}
}

func TestValidateCompilesFilterAndRequiresPlaceholder(t *testing.T) {
	tests := []string{
		"(&(objectClass=person)",
		"(&(objectClass=person)(uid=literal))",
	}
	for _, filter := range tests {
		cfg := Default()
		cfg.URL = "ldaps://ldap.example.com:636"
		cfg.BaseDN = "dc=example,dc=com"
		cfg.UserFilter = filter
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate() accepted filter %q", filter)
		}
	}
}

func TestValidateRejectsUnsupportedURLComponents(t *testing.T) {
	for _, rawURL := range []string{
		"ldaps://user:pass@ldap.example.com:636",
		"ldaps://ldap.example.com:636/dc=example,dc=com",
		"ldaps://ldap.example.com:636?scope=sub",
		"ldaps://ldap.example.com:636#fragment",
	} {
		cfg := Default()
		cfg.URL = rawURL
		cfg.BaseDN = "dc=example,dc=com"
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate() accepted unsupported URL %q", rawURL)
		}
	}
}

func TestValidateRejectsContradictoryTransportSettings(t *testing.T) {
	tests := []Config{
		func() Config {
			cfg := Default()
			cfg.URL = "ldaps://ldap.example.com:636"
			cfg.BaseDN = "dc=example,dc=com"
			cfg.AllowInsecurePlaintext = true
			return cfg
		}(),
		func() Config {
			cfg := Default()
			cfg.URL = "ldap://ldap.example.com:389"
			cfg.BaseDN = "dc=example,dc=com"
			cfg.AllowInsecurePlaintext = true
			cfg.InsecureSkipVerify = true
			return cfg
		}(),
	}
	for _, cfg := range tests {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate() accepted contradictory config %#v", cfg)
		}
	}
}

func validConfigValues() map[string]any {
	return map[string]any{
		"url":               "ldaps://ldap.example.com:636",
		"base_dn":           "dc=example,dc=com",
		"user_filter":       "(&(objectClass=person)(uid={username}))",
		"subject_attribute": "entryUUID",
	}
}

func mustStruct(t *testing.T, values map[string]any) *structpb.Struct {
	t.Helper()
	value, err := structpb.NewStruct(values)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
