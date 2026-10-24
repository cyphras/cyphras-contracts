package deploy

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

// nginxText writes an IPv6 address as nginx's ngx_inet6_ntop does: lowercase groups without
// leading zeros, the first longest run of two or more zero groups as "::", and the last 32 bits
// in dotted form for the addresses it treats as carrying an IPv4 address.
func nginxText(p [16]byte) string {
	zero, last, longest, n := -1, -1, 1, 0
	for i := 0; i < 16; i += 2 {
		if p[i] != 0 || p[i+1] != 0 {
			if longest < n {
				zero, longest = last, n
			}
			n = 0
			continue
		}
		if n == 0 {
			last = i
		}
		n++
	}
	if longest < n {
		zero, longest = last, n
	}
	var b strings.Builder
	end := 16
	if zero == 0 {
		if (longest == 5 && p[10] == 0xff && p[11] == 0xff) || longest == 6 || (longest == 7 && p[14] != 0 && p[15] != 1) {
			end = 12
		}
		b.WriteByte(':')
	}
	for i := 0; i < end; i += 2 {
		if i == zero {
			b.WriteByte(':')
			i += (longest - 1) * 2
			continue
		}
		fmt.Fprintf(&b, "%x", int(p[i])<<8|int(p[i+1]))
		if i < 14 {
			b.WriteByte(':')
		}
	}
	if end == 12 {
		fmt.Fprintf(&b, "%d.%d.%d.%d", p[12], p[13], p[14], p[15])
	}
	return b.String()
}

type rule struct {
	re    *regexp.Regexp
	value string
}

// tokens splits one map line into its quoted or bare words.
func tokens(line string) []string {
	var out []string
	for line = strings.TrimSpace(line); line != ""; line = strings.TrimSpace(line) {
		if line[0] == '"' {
			end := strings.IndexByte(line[1:], '"') + 1
			out = append(out, line[1:end])
			line = line[end+1:]
			continue
		}
		end := strings.IndexAny(line, " \t")
		if end < 0 {
			end = len(line)
		}
		out = append(out, line[:end])
		line = line[end:]
	}
	return out
}

// mapKey reads a map the rate limits key clients by and returns it as a function.
func mapKey(t *testing.T, name string) func(string) string {
	t.Helper()
	conf, err := os.ReadFile("nginx/conf.d/cyphras-v2-zones.conf")
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(conf), "map $remote_addr $"+name+" {\n")
	block, _, ok2 := strings.Cut(block, "\n}")
	if !ok || !ok2 {
		t.Fatalf("the map of $%s is missing", name)
	}
	var rules []rule
	def := ""
	for _, line := range strings.Split(block, "\n") {
		words := tokens(strings.TrimSuffix(strings.TrimSpace(line), ";"))
		switch {
		case len(words) == 2 && words[0] == "default":
			def = words[1]
		case len(words) == 2 && strings.HasPrefix(words[0], "~"):
			rules = append(rules, rule{re: regexp.MustCompile(words[0][1:]), value: words[1]})
		default:
			t.Fatalf("map line %q", line)
		}
	}
	return func(addr string) string {
		for _, r := range rules {
			if m := r.re.FindStringSubmatchIndex(addr); m != nil {
				if strings.HasPrefix(r.value, "$binary") {
					return r.value
				}
				return string(r.re.ExpandString(nil, r.value, addr, m))
			}
		}
		return def
	}
}

func TestEveryAddressOfASlash64AndASlash48GetsOneRateLimitKey(t *testing.T) {
	client, site := mapKey(t, "cy_client"), mapKey(t, "cy_site")
	rng := rand.New(rand.NewPCG(1, 2))
	check := func(groups [8]uint16) {
		t.Helper()
		var p [16]byte
		for i, g := range groups {
			p[2*i], p[2*i+1] = byte(g>>8), byte(g)
		}
		text := nginxText(p)
		want64 := fmt.Sprintf("6:%x:%x:%x:%x", groups[0], groups[1], groups[2], groups[3])
		want48 := fmt.Sprintf("6:%x:%x:%x", groups[0], groups[1], groups[2])
		if strings.Contains(text, ".") {
			want64, want48 = "$binary_remote_addr", "$binary_remote_addr"
		}
		if got := client(text); got != want64 {
			t.Fatalf("%s keys its /64 as %q, want %q", text, got, want64)
		}
		if got := site(text); got != want48 {
			t.Fatalf("%s keys its /48 as %q, want %q", text, got, want48)
		}
	}
	// Every placement of zero groups, so every place nginx can put the "::".
	for mask := range 256 {
		for range 20 {
			var groups [8]uint16
			for i := range groups {
				if mask&(1<<i) == 0 {
					groups[i] = uint16(rng.IntN(0xffff) + 1)
				}
			}
			check(groups)
		}
	}
	if client("203.0.113.7") != "$binary_remote_addr" || site("203.0.113.7") != "$binary_remote_addr" {
		t.Fatal("an IPv4 address is not keyed on itself")
	}
}

// location is one location block of the vhost: its modifier and pattern as written, and its body.
type location struct {
	spec, modifier, pattern, body string
	re                            *regexp.Regexp
}

var locationLine = regexp.MustCompile(`^  location (.+) \{$`)

// locations reads the location blocks of a vhost laid out as the file is: one directive a line,
// a block opened on its own line, and a block that fits a line (limit_except) written on one.
func locations(t *testing.T, vhost string) []location {
	t.Helper()
	var out []location
	var open *location
	for _, line := range strings.Split(vhost, "\n") {
		if open != nil {
			if line == "  }" {
				out = append(out, *open)
				open = nil
				continue
			}
			open.body += strings.TrimSpace(line) + "\n"
			continue
		}
		m := locationLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		l := location{spec: m[1]}
		words := strings.SplitN(m[1], " ", 2)
		l.modifier, l.pattern = "", m[1]
		if len(words) == 2 && (words[0] == "=" || words[0] == "~" || words[0] == "~*" || words[0] == "^~") {
			l.modifier, l.pattern = words[0], words[1]
		}
		l.pattern = strings.Trim(l.pattern, `"`)
		if l.modifier == "~" {
			// nginx names a capture (?<name>...), Go (?P<name>...).
			l.re = regexp.MustCompile(strings.ReplaceAll(l.pattern, "(?<", "(?P<"))
		}
		open = &l
	}
	if open != nil {
		t.Fatalf("location %s is not closed", open.spec)
	}
	return out
}

// normalise reads a URI as nginx does before it picks a location: percent-escapes decoded, runs of
// slashes merged, and . and .. segments resolved.
func normalise(uri string) string {
	p, err := url.PathUnescape(uri)
	if err != nil {
		return uri
	}
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		clean += "/"
	}
	return clean
}

// route picks the location nginx would serve a URI from: an exact match, else the longest prefix
// if it is marked ^~, else the first matching regex in file order, else the longest prefix.
func route(locs []location, uri string) (*location, map[string]string) {
	var prefix *location
	for i, l := range locs {
		switch {
		case l.modifier == "=" && l.pattern == uri:
			return &locs[i], nil
		case (l.modifier == "" || l.modifier == "^~") && strings.HasPrefix(uri, l.pattern):
			if prefix == nil || len(l.pattern) > len(prefix.pattern) {
				prefix = &locs[i]
			}
		}
	}
	if prefix != nil && prefix.modifier == "^~" {
		return prefix, nil
	}
	for i, l := range locs {
		if l.re == nil {
			continue
		}
		if m := l.re.FindStringSubmatch(uri); m != nil {
			names := map[string]string{}
			for j, name := range l.re.SubexpNames() {
				if name != "" {
					names[name] = m[j]
				}
			}
			return &locs[i], names
		}
	}
	return prefix, nil
}

// The published archive is read from disk by anyone, so it may only ever give out its own two
// kinds of file, to GET and HEAD, with the headers a page needs to read it and a cache needs to
// keep it, and none of what identifies the reader.
func TestPrivateVhostServesThePublishedArchiveReadOnly(t *testing.T) {
	vhost, err := os.ReadFile("nginx/sites-available/private.cyphras.com")
	if err != nil {
		t.Fatal(err)
	}
	locs := locations(t, string(vhost))
	for _, network := range []string{"testnet", "mainnet"} {
		base := "/" + network + "/xlm/archive"
		dir := "/var/www/cyphras-vault-archive/" + network + "/xlm"
		served := map[string]string{
			base + "/manifest.json":               dir + "/manifest.json",
			base + "/windows/0000017280.jsonl.gz": dir + "/windows/0000017280.jsonl.gz",
		}
		// The same files by other spellings of the URI, which nginx normalises before it routes.
		served[base+"/windows/../manifest.json"] = dir + "/manifest.json"
		served[base+"//./manifest.json"] = dir + "/manifest.json"
		served[base+"/%6danifest.json"] = dir + "/manifest.json"
		served[base+"/windows%2f0000017280.jsonl.gz"] = dir + "/windows/0000017280.jsonl.gz"
		for uri, file := range served {
			l, names := route(locs, normalise(uri))
			if l == nil {
				t.Fatalf("%s is not routed", uri)
			}
			var alias string
			for _, line := range strings.Split(l.body, "\n") {
				if rest, ok := strings.CutPrefix(line, "alias "); ok {
					alias = strings.TrimSuffix(rest, ";")
				}
			}
			for name, value := range names {
				alias = strings.ReplaceAll(alias, "$"+name, value)
			}
			if alias != file {
				t.Errorf("%s is served from %q, want %q", uri, alias, file)
			}
			for _, line := range []string{
				"limit_except GET { deny all; }", "autoindex off;",
				`add_header Strict-Transport-Security "max-age=63072000" always;`,
				`add_header Access-Control-Allow-Origin "*" always;`,
				`add_header X-Content-Type-Options "nosniff" always;`,
			} {
				if !strings.Contains(l.body, line+"\n") {
					t.Errorf("%s lacks %q", uri, line)
				}
			}
			for _, line := range strings.Split(l.body, "\n") {
				directive, _, _ := strings.Cut(line, " ")
				switch directive {
				case "proxy_pass", "proxy_set_header", "include", "root", "try_files", "index":
					t.Errorf("%s uses %q", uri, line)
				}
			}
			cache := `add_header Cache-Control "public, max-age=60";`
			if strings.HasSuffix(file, ".gz") {
				cache = `add_header Cache-Control "public, max-age=31536000, immutable";`
			}
			if !strings.Contains(l.body, cache+"\n") {
				t.Errorf("%s lacks %q", uri, cache)
			}
		}
		for _, uri := range []string{
			base, base + "/", base + "/windows/", base + "/windows", base + "/manifest.json/", base + "/manifest.json/x",
			base + "/manifest.json.bak", base + "/Manifest.json", base + "/index.html", base + "/windows/0000017280.jsonl",
			base + "/windows/17280.jsonl.gz", base + "/windows/00000172800.jsonl.gz", base + "/windows/0000017280.jsonl.gz/",
			base + "/windows/0000017280.jsonl.gz.sig", base + "/windows/000001728a.jsonl.gz", base + "/windows/x/0000017280.jsonl.gz",
			base + "/.git/config", base + "/windows/.0000017280.jsonl.gz", base + "/windows/../../../etc/passwd",
			base + "/%2e%2e/manifest.json",
		} {
			l, _ := route(locs, normalise(uri))
			if l == nil || strings.TrimSpace(l.body) != "return 404;" {
				t.Errorf("%s is not answered with 404: %+v", uri, l)
			}
		}
	}
	for _, l := range locs {
		if strings.Contains(l.body, "alias") && !strings.Contains(l.spec, "/archive/") {
			t.Errorf("location %s serves files", l.spec)
		}
	}
}

// The vhost is the privacy boundary of the services: every route that reaches one strips what
// identifies the client, keeps no access log, and nothing else is served.
func TestPrivateVhostStripsClientIdentityOnEveryRoute(t *testing.T) {
	vhost, err := os.ReadFile("nginx/sites-available/private.cyphras.com")
	if err != nil {
		t.Fatal(err)
	}
	snippet, err := os.ReadFile("nginx/snippets/cyphras-v2-proxy.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"access_log off;",
		`proxy_set_header X-Forwarded-For "";`, `proxy_set_header X-Real-IP "";`, `proxy_set_header Forwarded "";`,
		`proxy_set_header User-Agent "";`, `proxy_set_header Referer "";`, `proxy_set_header Cookie "";`,
		`proxy_set_header Authorization "";`,
	} {
		if !strings.Contains(string(snippet), "\n"+line+"\n") {
			t.Errorf("the proxy snippet lacks %q", line)
		}
	}

	seen := map[string]string{}
	for _, l := range locations(t, string(vhost)) {
		seen[l.spec] = l.body
		if strings.Contains(l.body, "proxy_pass") && !strings.Contains(l.body, "include snippets/cyphras-v2-proxy.conf;") {
			t.Errorf("location %s proxies without the identity-stripping snippet", l.spec)
		}
	}
	for _, path := range []string{
		"/", "/mainnet/screening/internal/", "/testnet/screening/internal/",
		"/mainnet/xlm/indexer/internal/", "/testnet/xlm/indexer/internal/",
		"/mainnet/xlm/relayer/internal/", "/testnet/xlm/relayer/internal/",
	} {
		if strings.TrimSpace(seen[path]) != "return 404;" {
			t.Errorf("location %s = %q, want only return 404", path, seen[path])
		}
	}
	for _, line := range []string{"server_tokens off;", `add_header Strict-Transport-Security "max-age=63072000" always;`} {
		if !strings.Contains(string(vhost), line) {
			t.Errorf("the vhost lacks %q", line)
		}
	}
}
