package deploy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func archiveLocations(t *testing.T) (vhost string, served []location) {
	t.Helper()
	raw, err := os.ReadFile("nginx/sites-available/private.cyphras.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range locations(t, string(raw)) {
		if strings.Contains(l.spec, "/archive/") && strings.Contains(l.body, "alias") {
			served = append(served, l)
		}
	}
	if len(served) != 4 {
		t.Fatalf("%d archive locations serve files, want the manifest and the windows of two networks", len(served))
	}
	return string(raw), served
}

// A header added with always also rides on an error, so a year-long immutable answer would be
// kept for a window that is asked for before it exists.
func TestOnlyASuccessfulAnswerIsGivenACacheLifetime(t *testing.T) {
	_, served := archiveLocations(t)
	for _, l := range served {
		for _, line := range strings.Split(l.body, "\n") {
			if strings.HasPrefix(line, "add_header Cache-Control") && strings.HasSuffix(line, "always;") {
				t.Errorf("%s: %q is sent with errors too", l.spec, line)
			}
			if strings.HasPrefix(line, "expires") {
				t.Errorf("%s: %q", l.spec, line)
			}
		}
		if !strings.Contains(l.body, "add_header Cache-Control") {
			t.Errorf("%s has no Cache-Control", l.spec)
		}
	}
}

func TestTheArchiveRoutesKeepTheServersSecurityHeadersAndNothingThatRewritesAPath(t *testing.T) {
	vhost, served := archiveLocations(t)
	hsts := regexp.MustCompile(`(?m)^  add_header (Strict-Transport-Security "[^"]+" always;)$`).FindStringSubmatch(vhost)
	if hsts == nil {
		t.Fatal("the server block has no HSTS header")
	}
	for _, l := range served {
		if !strings.Contains(l.body, "add_header "+hsts[1]+"\n") {
			t.Errorf("%s does not repeat the server's %s", l.spec, hsts[1])
		}
		for _, line := range strings.Split(l.body, "\n") {
			directive, _, _ := strings.Cut(line, " ")
			switch directive {
			case "rewrite", "if", "set", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "root", "error_page", "return", "autoindex_exact_size":
				t.Errorf("%s uses %q", l.spec, line)
			}
		}
		for _, line := range []string{"gzip off;", "autoindex off;"} {
			if !strings.Contains(l.body, line+"\n") {
				t.Errorf("%s lacks %q", l.spec, line)
			}
		}
		if strings.Contains(l.body, "..") {
			t.Errorf("%s has a parent directory in it", l.spec)
		}
		if l.modifier == "~" {
			if !strings.HasPrefix(l.pattern, "^/") || !strings.HasSuffix(l.pattern, "$") {
				t.Errorf("%s is not anchored at both ends", l.spec)
			}
			if !strings.Contains(l.pattern, `(?<window>[0-9]{10})\.jsonl\.gz$`) {
				t.Errorf("%s captures more than ten digits", l.spec)
			}
		}
	}
}

func TestTheArchiveRoutesNeverFollowALink(t *testing.T) {
	_, served := archiveLocations(t)
	for _, l := range served {
		if !strings.Contains(l.body, "disable_symlinks on;\n") {
			t.Errorf("%s follows symbolic links", l.spec)
		}
	}
}
