package vaultarchive

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// variants are manifests that Go reads as the real one and another JSON reader reads differently,
// or that carry more than the format allows, each made from the real manifest's text.
func variants(t *testing.T, canonical string) map[string][2]string {
	t.Helper()
	if !strings.Contains(canonical, `"coveredTo": `) || !strings.Contains(canonical, `"windows": [`) {
		t.Fatalf("the manifest is not laid out as expected:\n%s", canonical)
	}
	shadowed := strings.Replace(canonical, `"coveredTo": `, `"coveredTo": 0, "windows": [], "CoveredTo": `, 1)
	shadowed = strings.Replace(shadowed, `"windows": [`+"\n", `"Windows": [`+"\n", 1)
	return map[string][2]string{
		"keys in another case that shadow the real ones": {shadowed, "is not a field"},
		"the same key twice":                             {strings.Replace(canonical, `"producer": `, `"producer": "x", "producer": `, 1), "twice"},
		"a field of its own":                             {strings.Replace(canonical, `"producer": `, `"mirrors": ["https://evil.example/archive"], "producer": `, 1), "is not a field"},
		"compact text":                                   {strings.Join(strings.Fields(canonical), ""), "canonical"},
		"extra spaces":                                   {strings.Replace(canonical, `"format": `, `"format":   `, 1), "canonical"},
		"no newline at the end":                          {strings.TrimSuffix(canonical, "\n"), "canonical"},
		"a second value":                                 {canonical + "{}\n", "canonical"},
		"a long producer":                                {strings.Replace(canonical, `"producer": "`, `"producer": "`+strings.Repeat("x", 200), 1), "producer"},
		"a producer with a control character":            {strings.Replace(canonical, `"producer": "`, `"producer": "\u0007`, 1), "producer"},
	}
}

func TestAManifestThatIsNotInCanonicalFormIsRefusedWhoeverReadsIt(t *testing.T) {
	remote := published(t, 3)
	raw, err := os.ReadFile(filepath.Join(remote, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(raw, pin()); err != nil {
		t.Fatalf("the manifest Build wrote: %v", err)
	}
	copyOf := t.TempDir()
	if _, err := Mirror(context.Background(), DirFetcher(remote), copyOf, pin()); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, copyOf)
	for name, v := range variants(t, string(raw)) {
		bad, reason := v[0], v[1]
		_, err := ParseManifest([]byte(bad), pin())
		mustInvalid(t, name, err, reason)

		if err := os.WriteFile(filepath.Join(remote, ManifestName), []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		fresh := filepath.Join(t.TempDir(), "copy")
		_, err = Mirror(context.Background(), DirFetcher(remote), fresh, pin())
		mustInvalid(t, name+" (mirror)", err, reason)
		if _, err := os.Stat(fresh); !os.IsNotExist(err) {
			t.Fatalf("%s: a refused mirror left %s: %v", name, fresh, err)
		}
		_, err = Mirror(context.Background(), DirFetcher(remote), copyOf, pin())
		mustInvalid(t, name+" (mirror into a copy)", err, reason)
		if after := snapshot(t, copyOf); !maps.Equal(before, after) {
			t.Fatalf("%s: a refused mirror changed the copy", name)
		}
		_, err = Load(context.Background(), DirFetcher(remote), pin())
		mustInvalid(t, name+" (load)", err, reason)
	}
}

func TestAMirrorWritesTheManifestInCanonicalForm(t *testing.T) {
	remote := published(t, 2)
	dir := t.TempDir()
	if _, err := Mirror(context.Background(), DirFetcher(remote), dir, pin()); err != nil {
		t.Fatal(err)
	}
	m := readManifestFile(t, dir)
	canonical, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil || string(got) != string(canonical) {
		t.Fatalf("the copy's manifest is not canonical: %v\n%s", err, got)
	}
}
