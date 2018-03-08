package config

import (
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

func TestLoadConfig(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}

	err := sc.ReloadConfig("testdata/blackbox-good.yml")
	if err != nil {
		t.Errorf("Error loading config %v: %v", "blackbox.yml", err)
	}
}

func TestLoadBadConfigs(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}
	baseErrorMsg := "Error parsing config file: "
	tests := []struct {
		ConfigFile    string
		ExpectedError string
	}{
		{
			ConfigFile:    "testdata/blackbox-bad.yml",
			ExpectedError: "unknown fields in dns probe: invalid_extra_field",
		},
		{
			ConfigFile:    "testdata/invalid-dns-module.yml",
			ExpectedError: "Query name must be set for DNS module",
		},
		{
			ConfigFile:    "testdata/ldap/no_dn.yml",
			ExpectedError: "DN is required to query LDAP",
		},
		{
			ConfigFile:    "testdata/ldap/bad_dn.yml",
			ExpectedError: "Invalid DN detected uid,dc=bar",
		},
		{
			ConfigFile:    "testdata/ldap/bad_scope.yml",
			ExpectedError: "Unknown scope type: foo",
		},
		{
			ConfigFile:    "testdata/ldap/bad_filter.yml",
			ExpectedError: "Invalid filter detected: not=working)",
		},
	}
	for i, test := range tests {
		err := sc.ReloadConfig(test.ConfigFile)
		if err.Error() != baseErrorMsg+test.ExpectedError {
			t.Errorf("In case %v:\nExpected:\n%v\nGot:\n%v", i, test.ExpectedError, err.Error())
		}
	}
}

func TestHideConfigSecrets(t *testing.T) {
	sc := &SafeConfig{
		C: &Config{},
	}

	err := sc.ReloadConfig("testdata/blackbox-good.yml")
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/blackbox-good.yml", err)
	}

	// String method must not reveal authentication credentials.
	sc.RLock()
	c, err := yaml.Marshal(sc.C)
	sc.RUnlock()
	if err != nil {
		t.Errorf("Error marshalling config: %v", err)
	}
	if strings.Contains(string(c), "mysecret") {
		t.Fatal("config's String method reveals authentication credentials.")
	}
}
