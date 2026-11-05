// Package clicontext persists cmd/cli's own login state — which
// Kayra server a token was fetched for, and the token itself — to
// ~/.config/kayra/config, in the same current-context/contexts
// shape kubeconfig uses. `kayra-cli login` always upserts the
// context it just produced and switches to it; `kayra-cli context
// use <name>` switches back to an earlier one without logging in
// again.
package clicontext

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// Context is one saved login: enough to know which server and
// provider a token belongs to, plus the credential itself. ApiDomain
// is that server's own app.api_domain, relayed by `login` (see
// oauth2login.Result.ApiDomain) so later commands (`auth can-i`, the
// generic verbs) never have to guess it as "example.com" — a context
// saved before this field existed, or via `context use`/a hand-edited
// config, simply carries it empty, same fallback as if the server
// itself never set one.
type Context struct {
	Server    string    `yaml:"server"`
	Provider  string    `yaml:"provider,omitempty"`
	Username  string    `yaml:"username,omitempty"`
	Token     string    `yaml:"token"`
	TokenType string    `yaml:"token_type,omitempty"`
	Expiry    time.Time `yaml:"expiry,omitempty"`
	ApiDomain string    `yaml:"api_domain,omitempty"`
}

// File is the on-disk ~/.config/kayra/config.
type File struct {
	CurrentContext string             `yaml:"current_context,omitempty"`
	Contexts       map[string]Context `yaml:"contexts"`
}

// contextFileEnvVar overrides the context file path — distinct from
// configEnvVar (KAYRA_CONFIG_FILE) in cmd/kayra, which names the
// server's own kayra.yaml and has nothing to do with this file.
const contextFileEnvVar = "KAYRA_CONTEXT_FILE"

// Path resolves the context file location: $KAYRA_CONTEXT_FILE if
// set, else $XDG_CONFIG_HOME/kayra/config, else
// ~/.config/kayra/config.
func Path() (string, error) {
	if p := os.Getenv(contextFileEnvVar); p != "" {
		return p, nil
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("clicontext: resolve home directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "kayra", "config"), nil
}

// Load reads the context file at its default Path, returning an
// empty File (never nil) if it doesn't exist yet — the first
// `kayra-cli login` on a fresh machine is what creates it.
func Load() (*File, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	return LoadFrom(path)
}

// LoadFrom reads the context file at an explicit path, for callers
// (tests, KAYRA_CONTEXT_FILE overrides) that already resolved it.
func LoadFrom(path string) (*File, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- path is this user's own $KAYRA_CONTEXT_FILE/default path, never attacker input
	if errors.Is(err, os.ErrNotExist) {
		return &File{Contexts: map[string]Context{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("clicontext: read %s: %w", path, err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("clicontext: parse %s: %w", path, err)
	}
	if f.Contexts == nil {
		f.Contexts = map[string]Context{}
	}
	return &f, nil
}

// Save writes f back to its default Path, creating the parent
// directory if needed. The file carries bearer tokens, so both the
// directory and file are narrowed to 0700/0600.
func (f *File) Save() error {
	path, err := Path()
	if err != nil {
		return err
	}
	return f.SaveTo(path)
}

// SaveTo writes f to an explicit path (mirrors LoadFrom).
func (f *File) SaveTo(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("clicontext: create %s: %w", filepath.Dir(path), err)
	}
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("clicontext: encode: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("clicontext: write %s: %w", path, err)
	}
	return nil
}

// SetContext upserts name and switches CurrentContext to it — a
// login always activates the context it just produced, the same way
// `oc login`/`kubectl config set-context --current` behaves.
func (f *File) SetContext(name string, ctx Context) {
	if f.Contexts == nil {
		f.Contexts = map[string]Context{}
	}
	f.Contexts[name] = ctx
	f.CurrentContext = name
}

// Use switches the current context without touching any credentials.
func (f *File) Use(name string) error {
	if _, ok := f.Contexts[name]; !ok {
		return fmt.Errorf("clicontext: no such context %q", name)
	}
	f.CurrentContext = name
	return nil
}

// Delete removes a context, clearing CurrentContext if it was the
// one deleted.
func (f *File) Delete(name string) error {
	if _, ok := f.Contexts[name]; !ok {
		return fmt.Errorf("clicontext: no such context %q", name)
	}
	delete(f.Contexts, name)
	if f.CurrentContext == name {
		f.CurrentContext = ""
	}
	return nil
}

// Current returns the current context and its name. An unset
// CurrentContext (nothing has ever logged in, or it named a context
// that was since deleted) is reported as an error rather than
// silently returning the zero value.
func (f *File) Current() (string, Context, error) {
	if f.CurrentContext == "" {
		return "", Context{}, errors.New("clicontext: no current context — run `kayra-cli login` or `kayra-cli context use <name>`")
	}
	ctx, ok := f.Contexts[f.CurrentContext]
	if !ok {
		return "", Context{}, fmt.Errorf("clicontext: current context %q no longer exists", f.CurrentContext)
	}
	return f.CurrentContext, ctx, nil
}

// Names returns context names sorted for stable listing output.
func (f *File) Names() []string {
	names := make([]string, 0, len(f.Contexts))
	for name := range f.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
