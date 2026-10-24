package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// exportHost is the layout archive-export.sh runs in, with a docker that only writes down what it
// was asked to run.
type exportHost struct {
	t                  *testing.T
	root, log, publish string
	// cwd is where the script is started from; the root of the host when empty.
	cwd string
}

func newExportHost(t *testing.T) *exportHost {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	root := t.TempDir()
	h := &exportHost{t: t, root: root, log: filepath.Join(root, "docker.log"), publish: filepath.Join(root, "publish")}
	for _, dir := range []string{
		filepath.Join(root, "bin"), filepath.Join(root, "services", "deploy", "data", "testnet", "xlm", "archive"),
		filepath.Join(root, "deployments"), h.publish,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile("archive-export.sh")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		filepath.Join(root, "services", "deploy", "archive-export.sh"): script,
		filepath.Join(root, "deployments", "testnet.json"):             []byte("{}"),
		filepath.Join(root, "bin", "docker"):                           []byte("#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done > \"$FAKE_LOG\"\nexit \"${FAKE_STATUS:-0}\"\n"),
		// flock -n FD, for a host that has no flock(1): perl takes the lock on the descriptor the
		// script opened, which stays locked for as long as the script holds it.
		filepath.Join(root, "bin", "flock"): []byte("#!/bin/sh\nexec perl -e 'open(my $f, \">&=\", $ARGV[1]) or exit 2; flock($f, 6) or exit 1' -- \"$@\"\n"),
	}
	for name, content := range files {
		if err := os.WriteFile(name, content, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

const exportImage = "ghcr.io/cyphras/cyphras-contracts/archive@sha256:abababababababababababababababababababababababababababababababab"

// run runs the script with the settings given after a complete set, and returns what docker was
// asked and whether the script succeeded.
func (h *exportHost) run(env ...string) (args []string, output string, ok bool) {
	h.t.Helper()
	os.Remove(h.log)
	cmd := exec.Command("bash", filepath.Join(h.root, "services", "deploy", "archive-export.sh"))
	cmd.Dir = h.cwd
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(h.root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_LOG="+h.log, "NETWORK=testnet", "ASSET=xlm", "ARCHIVE_IMAGE="+exportImage, "ARCHIVE_PUBLISH_DIR="+h.publish, "ARCHIVE_UID=10100")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	raw, _ := os.ReadFile(h.log)
	if len(raw) > 0 {
		args = strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	return args, string(out), err == nil
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestTheArchiveExportRunsTheImageAsAnUnprivilegedUserOverAReadOnlyEventArchive(t *testing.T) {
	h := newExportHost(t)
	args, out, ok := h.run()
	if !ok {
		t.Fatalf("the export failed:\n%s", out)
	}
	events := filepath.Join(h.root, "services", "deploy", "data", "testnet", "xlm", "archive")
	published := h.publish
	for _, want := range []string{
		"run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "no-new-privileges:true", "10100:10100",
		"type=bind,source=" + events + ",target=/in,readonly",
		"type=bind,source=" + published + ",target=/out",
		exportImage, "export", "--out", "/out", "--dir", "/in", "--network", "testnet",
	} {
		if !contains(args, want) {
			t.Errorf("docker was not asked for %q:\n%s", want, strings.Join(args, "\n"))
		}
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "type=bind") && strings.Contains(arg, "target=/etc/cyphras/deployment.json") && !strings.HasSuffix(arg, ",readonly") {
			t.Errorf("the deployment file is mounted writable: %s", arg)
		}
		if strings.Contains(arg, "source="+events) && !strings.HasSuffix(arg, ",readonly") {
			t.Errorf("the event archive is mounted writable: %s", arg)
		}
	}
	if contains(args, "--vault") {
		t.Error("a vault was named without ARCHIVE_VAULT")
	}
	if args, _, ok := h.run("ARCHIVE_VAULT=CVAULT"); !ok || !contains(args, "--vault") || !contains(args, "CVAULT") {
		t.Errorf("ARCHIVE_VAULT is not passed on: %v", args)
	}
	if args, _, ok := h.run("ARCHIVE_UID=1234"); !ok || !contains(args, "1234:1234") {
		t.Errorf("ARCHIVE_UID is not used: %v", args)
	}
}

func TestTheArchiveExportFailsWhenTheExportFailsOrItsSettingsAreWrong(t *testing.T) {
	h := newExportHost(t)
	if _, _, ok := h.run("FAKE_STATUS=3"); ok {
		t.Fatal("a failing export was reported as a success")
	}
	missing := filepath.Join(h.root, "nothing")
	for name, env := range map[string][]string{
		"no network":                           {"NETWORK="},
		"a network that climbs out":            {"NETWORK=../x"},
		"an asset with a slash":                {"ASSET=x/y"},
		"an image by tag":                      {"ARCHIVE_IMAGE=ghcr.io/cyphras/cyphras-contracts/archive:latest"},
		"no image":                             {"ARCHIVE_IMAGE="},
		"no publish directory":                 {"ARCHIVE_PUBLISH_DIR="},
		"a publish directory that is absent":   {"ARCHIVE_PUBLISH_DIR=" + missing},
		"root":                                 {"ARCHIVE_UID=0"},
		"the user every service image runs as": {"ARCHIVE_UID=65532"},
		"no user":                              {"ARCHIVE_UID="},
		"an image of another repository":       {"ARCHIVE_IMAGE=ghcr.io/someone/else/archive@sha256:" + strings.Repeat("ab", 32)},
		"another image of this repository":     {"ARCHIVE_IMAGE=ghcr.io/cyphras/cyphras-contracts/indexer@sha256:" + strings.Repeat("ab", 32)},
		"a user that is not a number":          {"ARCHIVE_UID=nobody"},
		"a network with no event archive":      {"NETWORK=mainnet"},
	} {
		args, out, ok := h.run(env...)
		if ok || len(args) != 0 {
			t.Errorf("%s: ok %v, docker asked %v\n%s", name, ok, args, out)
		}
	}
}

func TestTheArchiveExportTakesARelativePublishDirectoryFromWhereItWasStarted(t *testing.T) {
	h := newExportHost(t)
	h.cwd = h.root
	args, out, ok := h.run("ARCHIVE_PUBLISH_DIR=publish")
	if !ok {
		t.Fatalf("a publish directory relative to the caller's directory was refused:\n%s", out)
	}
	physical, err := filepath.EvalSymlinks(h.publish)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(args, "type=bind,source="+h.publish+",target=/out") && !contains(args, "type=bind,source="+physical+",target=/out") {
		t.Errorf("the publish directory is mounted from the wrong place:\n%s", strings.Join(args, "\n"))
	}
	if err := os.Mkdir(filepath.Join(h.root, "services", "deploy", "publish"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.cwd = t.TempDir()
	if args, out, ok := h.run("ARCHIVE_PUBLISH_DIR=publish"); ok || len(args) != 0 {
		t.Errorf("a directory of the script's own folder was taken for the caller's:\n%s", out)
	}
}

func TestTheArchiveExportRefusesPathsThatWouldAddMountOptions(t *testing.T) {
	h := newExportHost(t)
	odd := filepath.Join(h.root, "pub,readonly")
	if err := os.Mkdir(odd, 0o755); err != nil {
		t.Fatal(err)
	}
	if args, out, ok := h.run("ARCHIVE_PUBLISH_DIR=" + odd); ok || len(args) != 0 {
		t.Errorf("a publish directory with a comma in its name reached docker:\n%s\n%v", out, args)
	}
}

func TestTheArchiveExportStopsWhenAnotherExportHoldsTheLock(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl is not installed")
	}
	h := newExportHost(t)
	lock := filepath.Join(h.root, "services", "deploy", "data", "testnet", "xlm", ".archive-export.lock")
	// Another process holds the lock until its input closes.
	holder := exec.Command("perl", "-e", `$| = 1; open(my $f, ">", $ARGV[0]) or die; flock($f, 2) or die; print "locked\n"; <STDIN>`, lock)
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			stdin.Close()
			holder.Wait()
		}
	}
	defer release()
	if n, err := stdout.Read(make([]byte, 7)); err != nil || n != 7 {
		t.Fatalf("the lock was not taken: %d, %v", n, err)
	}
	args, out, ok := h.run()
	if ok || len(args) != 0 || !strings.Contains(out, "another export is running") {
		t.Fatalf("an export beside another: ok %v, docker asked %v\n%s", ok, args, out)
	}
	release()
	if args, out, ok := h.run(); !ok || len(args) == 0 {
		t.Fatalf("the export after the lock was let go: %v\n%s", args, out)
	}
}
