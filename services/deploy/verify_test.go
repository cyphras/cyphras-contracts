package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// release is a clone of a repository, with its origin, in which verify-images.sh runs as on a
// host, and the keys that sign tags.
type release struct {
	t          *testing.T
	dir, clone string
}

func (r *release) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.clone
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *release) key(name string) string {
	r.t.Helper()
	path := filepath.Join(r.dir, name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", path).CombinedOutput(); err != nil {
		r.t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		r.t.Fatal(err)
	}
	return name + "@example.org " + strings.TrimSpace(string(pub))
}

// sign makes a tag signed with the named key, whose message is its name and the notes given.
func (r *release) sign(key, tag, commit string, notes ...string) {
	args := []string{"-c", "gpg.format=ssh", "-c", "user.signingkey=" + filepath.Join(r.dir, key), "tag", "-s", "-m", tag}
	for _, n := range notes {
		args = append(args, "-m", n)
	}
	r.git(append(args, tag, commit)...)
}

// verify runs the script for a tag and commit, with the given signers in the repository variable.
func (r *release) verify(tag, commit, variable string) (string, bool) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, "variable"), []byte(variable), 0o600); err != nil {
		r.t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(r.clone, "services", "deploy", "verify-images.sh"))
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"PATH="+filepath.Join(r.dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_VARIABLE="+filepath.Join(r.dir, "variable"), "RELEASE_TAG="+tag, "RELEASE_COMMIT="+commit,
		"INDEXER_IMAGE=ghcr.io/cyphras/cyphras-contracts/indexer@sha256:"+strings.Repeat("ab", 32))
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

func TestAReleaseTagIsCheckedOnTheHost(t *testing.T) {
	for _, tool := range []string{"git", "ssh-keygen", "bash"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	r := &release{t: t, dir: dir, clone: filepath.Join(dir, "clone")}
	maintainer, stranger := r.key("maintainer"), r.key("stranger")
	// The GitHub CLI answers with the repository variable and passes every attestation.
	gh := "#!/bin/sh\ncase \"$1 $2\" in\n\"variable get\") cat \"$FAKE_VARIABLE\" ;;\n\"attestation verify\") exit 0 ;;\n*) exit 1 ;;\nesac\n"
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "gh"), []byte(gh), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "-q", "--bare", filepath.Join(dir, "origin.git")).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := exec.Command("git", "init", "-q", "-b", "dev", r.clone).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	script, err := os.ReadFile("verify-images.sh")
	if err != nil {
		t.Fatal(err)
	}
	deploy := filepath.Join(r.clone, "services", "deploy")
	if err := os.MkdirAll(deploy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deploy, "verify-images.sh"), script, 0o700); err != nil {
		t.Fatal(err)
	}
	signers := "# maintainers\n" + maintainer + "\n"
	if err := os.WriteFile(filepath.Join(deploy, "allowed_signers"), []byte(signers), 0o600); err != nil {
		t.Fatal(err)
	}
	r.git("config", "user.name", "release")
	r.git("config", "user.email", "release@example.org")
	r.git("remote", "add", "origin", filepath.Join(dir, "origin.git"))
	r.git("add", ".")
	r.git("commit", "-q", "-m", "release")
	reviewed := r.git("rev-parse", "HEAD")
	r.git("branch", "main")
	r.git("commit", "-q", "--allow-empty", "-m", "later")
	later := r.git("rev-parse", "HEAD")
	r.git("checkout", "-q", "-b", "feature")
	r.git("commit", "-q", "--allow-empty", "-m", "unreviewed")
	unreviewed := r.git("rev-parse", "HEAD")
	r.sign("maintainer", "services-v1.0.0", reviewed)
	r.sign("stranger", "services-v1.0.1", reviewed)
	r.git("tag", "-a", "-m", "services-v1.0.2", "services-v1.0.2", reviewed)
	r.git("tag", "services-v1.0.3", reviewed)
	r.sign("maintainer", "services-v1.0.4", unreviewed)
	r.git("update-ref", "refs/tags/services-v1.0.5", r.git("rev-parse", "refs/tags/services-v1.0.0"))
	r.sign("maintainer", "services-v1.0.6", reviewed, "tag services-v1.0.7")
	r.git("update-ref", "refs/tags/services-v1.0.7", r.git("rev-parse", "refs/tags/services-v1.0.6"))
	r.git("push", "-q", "origin", "dev", "main", "--tags")

	if out, ok := r.verify("services-v1.0.0", reviewed, maintainer); !ok {
		t.Fatalf("a good release was refused:\n%s", out)
	}
	// In a fixed order, so the case that catches a broken check is always the same.
	for _, c := range []struct {
		name, tag, commit, variable, says string
	}{
		{"a signer not allowed", "services-v1.0.1", reviewed, maintainer, "No principal matched"},
		{"an unsigned tag", "services-v1.0.2", reviewed, maintainer, "no signature found"},
		{"a lightweight tag", "services-v1.0.3", reviewed, maintainer, "not a signed tag"},
		{"a commit on neither branch", "services-v1.0.4", unreviewed, maintainer, "neither dev nor main"},
		{"another release's signed tag", "services-v1.0.5", reviewed, maintainer, "signed tag of another release"},
		{"a tag whose message names it", "services-v1.0.7", reviewed, maintainer, "signed tag of another release"},
		{"a tag of another dev commit", "services-v1.0.0", later, maintainer, "does not point at RELEASE_COMMIT"},
		{"a tag of another commit", "services-v1.0.0", unreviewed, maintainer, "does not point at RELEASE_COMMIT"},
		{"a variable that disagrees", "services-v1.0.0", reviewed, stranger, "disagree"},
		{"an empty variable", "services-v1.0.0", reviewed, "", "disagree"},
	} {
		if out, ok := r.verify(c.tag, c.commit, c.variable); ok || !strings.Contains(out, c.says) {
			t.Fatalf("%s: passed %v\n%s", c.name, ok, out)
		}
	}
}
