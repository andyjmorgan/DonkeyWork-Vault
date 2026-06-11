// Package manifests owns the OAuth provider catalog: the embedded YAML library of templates and the
// per-user DB-backed resolver. The embedded YAML is a library only — it is never seeded and never
// resolved against directly; adding a provider copies the whole manifest into a self-contained
// per-user row with its own stable provider id.
package manifests

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

//go:embed embedded/oauth/*.yaml
var embeddedFS embed.FS

// ScopeDef is a curated, described OAuth scope for a "pick your access" UI.
//
// The yaml tags match the embedded templates (underscored naming); the json tags are camelCase to
// match the document_json wire form, so existing rows round-trip unchanged.
type ScopeDef struct {
	Value       string `json:"value" yaml:"value"`
	Description string `json:"description" yaml:"description"`
	Category    string `json:"category" yaml:"category"`
	Sensitive   bool   `json:"sensitive" yaml:"sensitive"`
}

// Manifest is a single OAuth provider definition.
type Manifest struct {
	ID                    uuid.UUID         `json:"id" yaml:"id"`
	ParentID              uuid.UUID         `json:"parentId" yaml:"parent_id"`
	Key                   string            `json:"key" yaml:"key"`
	Name                  string            `json:"name" yaml:"name"`
	IconURL               string            `json:"iconUrl" yaml:"icon_url"`
	DocsURL               string            `json:"docsUrl" yaml:"docs_url"`
	AuthorizationEndpoint string            `json:"authorizationEndpoint" yaml:"authorization_endpoint"`
	TokenEndpoint         string            `json:"tokenEndpoint" yaml:"token_endpoint"`
	UserinfoEndpoint      string            `json:"userinfoEndpoint" yaml:"userinfo_endpoint"`
	ScopeDelimiter        string            `json:"scopeDelimiter" yaml:"scope_delimiter"`
	DefaultScopes         []string          `json:"defaultScopes" yaml:"default_scopes"`
	Scopes                []ScopeDef        `json:"scopes" yaml:"scopes"`
	AuthorizeParams       map[string]string `json:"authorizeParams" yaml:"authorize_params"`
}

// Loader holds the validated embedded catalog, indexed by key and by stable id.
type Loader struct {
	byKey map[string]Manifest
	byID  map[uuid.UUID]Manifest
}

// NewLoader reads and validates the embedded OAuth templates, failing fast on a missing/duplicate id
// or a missing key/token endpoint.
func NewLoader() (*Loader, error) {
	return loadFromFS(embeddedFS, "embedded/oauth")
}

// loadFromFS walks root in fsys, validating each *.yaml manifest. Split out from NewLoader so the
// validation/error paths can be exercised against a synthetic filesystem in tests; production always
// passes the embedded FS.
func loadFromFS(fsys fs.FS, root string) (*Loader, error) {
	byKey := make(map[string]Manifest)
	byID := make(map[uuid.UUID]Manifest)

	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err //coverage:ignore path came from WalkDir over a compiled-in embed.FS; read cannot fail
		}
		var m Manifest
		if err := yaml.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("manifest %s: %w", path, err)
		}
		if m.Key == "" || m.TokenEndpoint == "" {
			return fmt.Errorf("manifest %s missing key/token_endpoint", path)
		}
		if m.ID == uuid.Nil {
			return fmt.Errorf("manifest %s missing a stable 'id' GUID", path)
		}
		if existing, dup := byID[m.ID]; dup {
			return fmt.Errorf("manifest %s reuses id %s, already used by %q", path, m.ID, existing.Key)
		}
		if m.ScopeDelimiter == "" {
			m.ScopeDelimiter = " "
		}
		byKey[m.Key] = m
		byID[m.ID] = m
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Loader{byKey: byKey, byID: byID}, nil
}

// All returns the templates ordered by key.
func (l *Loader) All() []Manifest {
	out := make([]Manifest, 0, len(l.byKey))
	for _, m := range l.byKey {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
