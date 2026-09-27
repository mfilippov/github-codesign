package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type Config struct {
	Spool        string `json:"spool"`
	TokenFile    string `json:"token_file"`
	Certs        string `json:"certs"`
	PKCS11Module string `json:"pkcs11_module"`
	// Slot is the PIV slot of the signing key (9a, 9c, 9d, 9e, 82–95). KeyURI, if set,
	// overrides it, e.g. to select one of several tokens.
	Slot             string     `json:"slot"`
	KeyURI           string     `json:"key_uri"`
	TSAURL           string     `json:"tsa_url"`
	CABundle         string     `json:"ca_bundle"`
	MaxArtifactBytes int64      `json:"max_artifact_bytes"`
	Repos            []RepoRule `json:"repos"`

	token string
}

// RepoRule allows signing artifacts from the listed workflows of one repository.
type RepoRule struct {
	Repo      string   `json:"repo"`
	Workflows []string `json:"workflows"`
	// Branches are path.Match patterns for head_branch (branch or tag name). Empty = any.
	Branches []string `json:"branches"`
	// RequireAttestation: every file must have GitHub build provenance from the allowed
	// workflow, at the run's commit, built on a GitHub-hosted runner (checked with gh).
	RequireAttestation bool `json:"require_attestation"`
}

func defaultConfigDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "github-codesign")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "github-codesign")
}

func loadConfig(file string) (*Config, error) {
	dir := filepath.Dir(file)
	cfg := &Config{
		Spool:            "/var/spool/codesign",
		TokenFile:        filepath.Join(dir, "token"),
		Certs:            filepath.Join(dir, "chain.pem"),
		PKCS11Module:     "/usr/lib/aarch64-linux-gnu/libykcs11.so",
		Slot:             "9a",
		TSAURL:           "http://ts.ssl.com",
		CABundle:         "/etc/ssl/certs/ca-certificates.crt",
		MaxArtifactBytes: 512 << 20,
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if cfg.KeyURI == "" {
		id, err := slotObjectID(cfg.Slot)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		cfg.KeyURI = fmt.Sprintf("pkcs11:id=%%%02x;type=private", id)
	}
	for _, r := range cfg.Repos {
		if !repoRe.MatchString(r.Repo) || len(r.Workflows) == 0 {
			return nil, fmt.Errorf("%s: bad repos entry %q (need repo and workflows)", file, r.Repo)
		}
		for _, b := range r.Branches {
			if _, err := path.Match(b, ""); err != nil {
				return nil, fmt.Errorf("%s: bad branch pattern %q", file, b)
			}
		}
	}

	st, err := os.Stat(cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must not be accessible by group/others (chmod 600)", cfg.TokenFile)
	}
	tok, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	cfg.token = strings.TrimSpace(string(tok))
	if cfg.token == "" {
		return nil, fmt.Errorf("%s is empty", cfg.TokenFile)
	}
	return cfg, nil
}

// slotObjectID maps a PIV slot to the PKCS#11 object id used by ykcs11:
// 9a→1, 9c→2, 9d→3, 9e→4, retired 82–95→5–24.
func slotObjectID(slot string) (int, error) {
	switch s := strings.ToLower(slot); s {
	case "9a":
		return 1, nil
	case "9c":
		return 2, nil
	case "9d":
		return 3, nil
	case "9e":
		return 4, nil
	default:
		var n int
		if _, err := fmt.Sscanf(s, "%x", &n); err == nil && len(s) == 2 && n >= 0x82 && n <= 0x95 {
			return n - 0x82 + 5, nil
		}
	}
	return 0, fmt.Errorf("unknown PIV slot %q (9a, 9c, 9d, 9e, 82–95)", slot)
}

func (c *Config) rule(repo string) *RepoRule {
	for i := range c.Repos {
		if strings.EqualFold(c.Repos[i].Repo, repo) {
			return &c.Repos[i]
		}
	}
	return nil
}

func (r *RepoRule) allowsWorkflow(p string) bool {
	for _, w := range r.Workflows {
		if w == p {
			return true
		}
	}
	return false
}

func (r *RepoRule) allowsBranch(b string) bool {
	if len(r.Branches) == 0 {
		return true
	}
	for _, pat := range r.Branches {
		if ok, _ := path.Match(pat, b); ok {
			return true
		}
	}
	return false
}
