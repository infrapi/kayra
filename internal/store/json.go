package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ConfigSuffix is the leaf key name every resource's own record ends in
// ("/config"), as opposed to a sibling key under the same resource (a
// group's "/members", say). ListConfigValues filters on it so a listing
// of one resource type never picks up another's sibling data.
const ConfigSuffix = "/config"

// PutJSON marshals v and writes it at key.
func PutJSON(s Store, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("store: marshal %s: %w", key, err)
	}
	if err := s.Put(key, data); err != nil {
		return fmt.Errorf("store: put %s: %w", key, err)
	}
	return nil
}

// GetJSON reads key and unmarshals it into v.
func GetJSON(s Store, key string, v any) error {
	data, err := s.Get(key)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("store: unmarshal %s: %w", key, err)
	}
	return nil
}

// ListConfigValues returns the raw bytes of every ConfigSuffix entry under
// prefix, in key order — a resource's other sibling keys (a group's
// "/members", say) are deliberately excluded.
func ListConfigValues(s Store, prefix string) ([][]byte, error) {
	entries, err := s.List(prefix)
	if err != nil {
		return nil, fmt.Errorf("store: list %s: %w", prefix, err)
	}

	keys := make([]string, 0, len(entries))
	for key := range entries {
		if strings.HasSuffix(key, ConfigSuffix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	values := make([][]byte, len(keys))
	for i, key := range keys {
		values[i] = entries[key]
	}
	return values, nil
}
