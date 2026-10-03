package deploy

import (
	"fmt"
	"math/rand/v2"
	"os"
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
	conf, err := os.ReadFile("nginx/cyphras-services.conf")
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
