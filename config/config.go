package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"runtime"
	"strings"
	"sync"
	"time"

	ldap "gopkg.in/ldap.v2"
	yaml "gopkg.in/yaml.v2"

	"github.com/prometheus/common/config"
)

type Config struct {
	Modules map[string]Module `yaml:"modules"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type SafeConfig struct {
	sync.RWMutex
	C *Config
}

func (sc *SafeConfig) ReloadConfig(confFile string) (err error) {
	var c = &Config{}

	yamlFile, err := ioutil.ReadFile(confFile)
	if err != nil {
		return fmt.Errorf("Error reading config file: %s", err)
	}

	if err := yaml.Unmarshal(yamlFile, c); err != nil {
		return fmt.Errorf("Error parsing config file: %s", err)
	}

	sc.Lock()
	sc.C = c
	sc.Unlock()

	return nil
}

type Module struct {
	Prober  string        `yaml:"prober,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	HTTP    HTTPProbe     `yaml:"http,omitempty"`
	TCP     TCPProbe      `yaml:"tcp,omitempty"`
	ICMP    ICMPProbe     `yaml:"icmp,omitempty"`
	DNS     DNSProbe      `yaml:"dns,omitempty"`
	LDAP    LDAPProbe     `yaml:"ldap,omitempty"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type HTTPProbe struct {
	// Defaults to 2xx.
	ValidStatusCodes       []int                   `yaml:"valid_status_codes,omitempty"`
	ValidHTTPVersions      []string                `yaml:"valid_http_versions,omitempty"`
	PreferredIPProtocol    string                  `yaml:"preferred_ip_protocol,omitempty"`
	NoFollowRedirects      bool                    `yaml:"no_follow_redirects,omitempty"`
	FailIfSSL              bool                    `yaml:"fail_if_ssl,omitempty"`
	FailIfNotSSL           bool                    `yaml:"fail_if_not_ssl,omitempty"`
	Method                 string                  `yaml:"method,omitempty"`
	Headers                map[string]string       `yaml:"headers,omitempty"`
	FailIfMatchesRegexp    []string                `yaml:"fail_if_matches_regexp,omitempty"`
	FailIfNotMatchesRegexp []string                `yaml:"fail_if_not_matches_regexp,omitempty"`
	Body                   string                  `yaml:"body,omitempty"`
	HTTPClientConfig       config.HTTPClientConfig `yaml:"http_client_config,inline"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type QueryResponse struct {
	Expect   string `yaml:"expect,omitempty"`
	Send     string `yaml:"send,omitempty"`
	StartTLS bool   `yaml:"starttls,omitempty"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type TCPProbe struct {
	PreferredIPProtocol string           `yaml:"preferred_ip_protocol,omitempty"`
	QueryResponse       []QueryResponse  `yaml:"query_response,omitempty"`
	TLS                 bool             `yaml:"tls,omitempty"`
	TLSConfig           config.TLSConfig `yaml:"tls_config,omitempty"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type ICMPProbe struct {
	PreferredIPProtocol string `yaml:"preferred_ip_protocol,omitempty"` // Defaults to "ip6".
	PayloadSize         int    `yaml:"payload_size,omitempty"`
	DontFragment        bool   `yaml:"dont_fragment,omitempty"`
	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type DNSProbe struct {
	PreferredIPProtocol string         `yaml:"preferred_ip_protocol,omitempty"`
	TransportProtocol   string         `yaml:"transport_protocol,omitempty"`
	QueryName           string         `yaml:"query_name,omitempty"`
	QueryType           string         `yaml:"query_type,omitempty"`   // Defaults to ANY.
	ValidRcodes         []string       `yaml:"valid_rcodes,omitempty"` // Defaults to NOERROR.
	ValidateAnswer      DNSRRValidator `yaml:"validate_answer_rrs,omitempty"`
	ValidateAuthority   DNSRRValidator `yaml:"validate_authority_rrs,omitempty"`
	ValidateAdditional  DNSRRValidator `yaml:"validate_additional_rrs,omitempty"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type DNSRRValidator struct {
	FailIfMatchesRegexp    []string `yaml:"fail_if_matches_regexp,omitempty"`
	FailIfNotMatchesRegexp []string `yaml:"fail_if_not_matches_regexp,omitempty"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type LDAPBind struct {
	Username string
	Password string

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type LDAPQuery struct {
	DN         string
	Filter     string // Defaults is "(objectClass=*)".
	Scope      string
	Attributes []string

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

type LDAPProbe struct {
	Bind  LDAPBind  `yaml:"bind_simple,omitempty"`
	Query LDAPQuery `yaml:"query,omitempty"`
	// Requests []LDAPRequest `yaml:",omitempty`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline"`
}

func checkOverflow(m map[string]interface{}, ctx string) error {
	if len(m) > 0 {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		return fmt.Errorf("unknown fields in %s: %s", ctx, strings.Join(keys, ", "))
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "config"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Module) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Module
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "module"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *HTTPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain HTTPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "http probe"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *DNSProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain DNSProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "dns probe"); err != nil {
		return err
	}
	if s.QueryName == "" {
		return errors.New("Query name must be set for DNS module")
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *TCPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain TCPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "tcp probe"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *DNSRRValidator) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain DNSRRValidator
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "dns rr validator"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *ICMPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain ICMPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if runtime.GOOS == "windows" && s.DontFragment {
		return errors.New("\"dont_fragment\" is not supported on windows platforms")
	}

	if err := checkOverflow(s.XXX, "icmp probe"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *QueryResponse) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain QueryResponse
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "query response"); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *LDAPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain LDAPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "ldap probe"); err != nil {
		return err
	}

	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *LDAPBind) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain LDAPBind
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	if err := checkOverflow(s.XXX, "ldap bind"); err != nil {
		return err
	}
	if _, err := ldap.ParseDN(s.Username); err != nil {
		return fmt.Errorf("Invalid DN detected: %s", s.Username)
	}
	return nil
}

// LDAPScopes  defines mapping between  strings and ldap scopes
var LDAPScopes = map[string]int{"base": ldap.ScopeBaseObject, "one": ldap.ScopeSingleLevel, "sub": ldap.ScopeWholeSubtree}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *LDAPQuery) UnmarshalYAML(unmarshal func(interface{}) error) error {

	type plain LDAPQuery
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if err := checkOverflow(s.XXX, "ldap query"); err != nil {
		return err
	}

	if _, err := ldap.CompileFilter(s.Filter); err != nil && s.Filter != "" {
		return fmt.Errorf("Invalid filter detected: %s", s.Filter)
	}

	if s.DN == "" {
		return fmt.Errorf("DN is required to query LDAP")
	}

	if _, err := ldap.ParseDN(s.DN); err != nil {
		return fmt.Errorf("Invalid DN detected: %s", s.DN)
	}

	if _, ok := LDAPScopes[s.Scope]; !ok {
		if s.Scope == "" {
			s.Scope = "one"
		} else {
			return fmt.Errorf("Unknown scope type: %s", s.Scope)
		}
	}
	return nil
}
