// Command archive builds, checks and serves the canonical archive of a vault's events, format
// cyphras-vault-archive/1, so a wallet can sync from it when the indexer and the RPC no longer
// have the history. It needs no Cyphras service: export turns an indexer's raw event archive into
// the format, rebuild makes the same bytes from the public ledger metadata archive, and verify
// checks an archive against the vault on chain.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/config"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/service"
	"github.com/cyphras/cyphras-contracts/services/internal/vaultarchive"
)

const usage = `usage:
  archive export  --dir <indexer archive> --deployment <file> --out <dir> [--vault <id>] [--network <name>]
  archive rebuild --ledger-meta <url> --deployment <file> --out <dir> [--vault <id>] [--network <name>] [--from <ledger>] [--to <ledger> | --rpc <url>] [--workers <n>]
  archive verify  (--dir <dir> | --url <base>) (--rpc <url> | --format-only) [--deployment <file> [--vault <id>]]
  archive serve   --dir <dir> [--addr 127.0.0.1:8737]`

// dialRPC is replaced by tests.
var dialRPC = rpc.Dial

// patientClient retries what an object store answers when it is busy, since one failed request
// would otherwise cost a whole window of ledger files that a rebuild fetches again.
var patientClient = &http.Client{Timeout: 10 * time.Minute, Transport: retrying{next: http.DefaultTransport, delay: 500 * time.Millisecond}}

// attempts is the number of tries a request gets.
const attempts = 5

type retrying struct {
	next  http.RoundTripper
	delay time.Duration
}

func (r retrying) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	for try := range attempts {
		if try > 0 {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(r.delay << (try - 1)):
			}
		}
		resp, err = r.next.RoundTrip(req)
		if err == nil && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			return resp, nil
		}
		if err != nil && req.Context().Err() != nil {
			return nil, err
		}
		if err == nil && try < attempts-1 {
			resp.Body.Close()
		}
	}
	return resp, err
}

// defaultAddr keeps the server on this machine unless --addr says otherwise.
const defaultAddr = "127.0.0.1:8737"

func main() {
	ctx, stop := service.Context()
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "archive:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	commands := map[string]func(context.Context, []string, io.Writer) error{
		"export": export, "rebuild": rebuild, "verify": verify, "serve": serve,
	}
	cmd, ok := commands[args[0]]
	if !ok {
		return fmt.Errorf("unknown command %q\n%s", args[0], usage)
	}
	return cmd(ctx, args[1:], out)
}

func flags(name string, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(out)
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

func require(values map[string]string) error {
	for name, value := range values {
		if value == "" {
			return fmt.Errorf("--%s is required", name)
		}
	}
	return nil
}

// target reads the deployment file and picks the vault: the one named, or the only one.
func target(path, vaultID, network string) (config.Deployment, config.DeployedVault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return config.Deployment{}, config.DeployedVault{}, fmt.Errorf("deployment file: %w", err)
	}
	var listed config.Deployment
	if err := json.Unmarshal(raw, &listed); err != nil {
		return config.Deployment{}, config.DeployedVault{}, fmt.Errorf("deployment file: %w", err)
	}
	if vaultID == "" {
		if len(listed.Vaults) != 1 {
			return config.Deployment{}, config.DeployedVault{}, fmt.Errorf("the deployment file lists %d vaults; name one with --vault", len(listed.Vaults))
		}
		vaultID = listed.Vaults[0].Vault
	}
	d, v, err := config.LoadDeployment(path, vaultID)
	if err != nil {
		return config.Deployment{}, config.DeployedVault{}, err
	}
	if network != "" && network != d.Network {
		return config.Deployment{}, config.DeployedVault{}, fmt.Errorf("--network %s, but the deployment file is for %s", network, d.Network)
	}
	return d, v, nil
}

func header(d config.Deployment, v config.DeployedVault) vaultarchive.Header {
	return vaultarchive.Header{
		Network: d.Network, NetworkPassphrase: d.NetworkPassphrase, Vault: v.Vault, DeployLedger: v.DeployLedger,
		Producer: "cyphras-archive/" + service.Version,
	}
}

func ledger(name string, n uint64) (uint32, error) {
	if n > math.MaxUint32 {
		return 0, fmt.Errorf("--%s %d is not a ledger", name, n)
	}
	return uint32(n), nil
}

func summary(out io.Writer, m vaultarchive.Manifest) {
	if m.Format == "" {
		return
	}
	var events, nullifiers int
	for _, w := range m.Windows {
		events += w.Events
		nullifiers += w.Nullifiers
	}
	var leaves uint64
	if n := len(m.Windows); n > 0 {
		leaves = m.Windows[n-1].Leaves[1]
	}
	fmt.Fprintf(out, "%s: %d windows covering ledgers %d to %d, %d events, %d leaves, %d nullifiers\n",
		m.Vault, len(m.Windows), windowsFrom(m), m.CoveredTo, events, leaves, nullifiers)
}

func windowsFrom(m vaultarchive.Manifest) uint32 {
	if len(m.Windows) == 0 {
		return 0
	}
	return m.Windows[0].Start
}

func export(ctx context.Context, args []string, out io.Writer) error {
	fs := flags("export", out)
	dir := fs.String("dir", "", "the indexer's raw event archive")
	deployment := fs.String("deployment", "", "the deployment file")
	outDir := fs.String("out", "", "where the archive is written")
	vaultID := fs.String("vault", "", "the vault, when the deployment file lists several")
	network := fs.String("network", "", "the network's name, checked against the deployment file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(map[string]string{"dir": *dir, "deployment": *deployment, "out": *outDir}); err != nil {
		return err
	}
	d, v, err := target(*deployment, *vaultID, *network)
	if err != nil {
		return err
	}
	covered, err := archive.LastCovered(*dir)
	if err != nil {
		return err
	}
	if covered == 0 {
		return errors.New("the event archive covers no ledger")
	}
	m, err := vaultarchive.Build(ctx, archive.Reader{Dir: *dir, Vault: v.Vault}, *outDir, header(d, v), 0, covered)
	summary(out, m)
	return err
}

func rebuild(ctx context.Context, args []string, out io.Writer) error {
	fs := flags("rebuild", out)
	meta := fs.String("ledger-meta", os.Getenv("LEDGER_META_ARCHIVE_URL"), "the SEP-54 ledger metadata archive")
	deployment := fs.String("deployment", "", "the deployment file")
	outDir := fs.String("out", "", "where the archive is written")
	vaultID := fs.String("vault", "", "the vault, when the deployment file lists several")
	network := fs.String("network", "", "the network's name, checked against the deployment file")
	from := fs.Uint64("from", 0, "a ledger of the first window to build; by default after the windows already in --out")
	to := fs.Uint64("to", 0, "the last ledger to cover; by default the RPC's latest")
	rpcURL := fs.String("rpc", "", "an RPC that tells the latest ledger when --to is not given")
	workers := fs.Int("workers", 16, "ledger files fetched at once")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(map[string]string{"ledger-meta": *meta, "deployment": *deployment, "out": *outDir}); err != nil {
		return err
	}
	first, err := ledger("from", *from)
	if err != nil {
		return err
	}
	last, err := ledger("to", *to)
	if err != nil {
		return err
	}
	if last == 0 {
		if *rpcURL == "" {
			return errors.New("give --to or --rpc")
		}
		health, err := dialRPC(*rpcURL).GetHealth(ctx)
		if err != nil {
			return fmt.Errorf("rpc health: %w", err)
		}
		last = health.LatestLedger
	}
	if first > last {
		return fmt.Errorf("--from %d is past the last ledger %d", first, last)
	}
	d, v, err := target(*deployment, *vaultID, *network)
	if err != nil {
		return err
	}
	src := &follow.LedgerArchive{BaseURL: *meta, Passphrase: d.NetworkPassphrase, Vault: v.Vault, Workers: *workers, HTTP: patientClient}
	m, err := vaultarchive.Build(ctx, src, *outDir, header(d, v), first, last)
	summary(out, m)
	return err
}

func verify(ctx context.Context, args []string, out io.Writer) error {
	fs := flags("verify", out)
	dir := fs.String("dir", "", "an archive in a directory")
	url := fs.String("url", "", "an archive at a base URL")
	rpcURL := fs.String("rpc", "", "the RPC the chain checks read")
	formatOnly := fs.Bool("format-only", false, "check the format only, without asking the chain")
	deployment := fs.String("deployment", "", "a deployment file that pins the vault, network and deploy ledger")
	vaultID := fs.String("vault", "", "the vault, when the deployment file lists several")
	if err := parse(fs, args); err != nil {
		return err
	}
	if (*dir == "") == (*url == "") {
		return errors.New("give --dir or --url")
	}
	if (*rpcURL == "") == !*formatOnly {
		return errors.New("give --rpc, or --format-only to skip the chain checks")
	}
	if *vaultID != "" && *deployment == "" {
		return errors.New("--vault needs --deployment, which is what pins it")
	}
	var want vaultarchive.Expect
	if *deployment != "" {
		d, v, err := target(*deployment, *vaultID, "")
		if err != nil {
			return err
		}
		want = vaultarchive.Expect{Vault: v.Vault, NetworkPassphrase: d.NetworkPassphrase, DeployLedger: v.DeployLedger}
	}
	var fetch vaultarchive.Fetcher = vaultarchive.DirFetcher(*dir)
	if *url != "" {
		fetch = vaultarchive.HTTPFetcher{Base: *url}
	}
	if *formatOnly {
		contents, err := vaultarchive.Load(ctx, fetch, want)
		if err != nil {
			return err
		}
		summary(out, contents.Manifest)
		fmt.Fprintln(out, "format checks passed")
		return nil
	}
	contents, report, err := vaultarchive.VerifyArchive(ctx, fetch, want, dialRPC(*rpcURL))
	if err != nil {
		return err
	}
	summary(out, contents.Manifest)
	fmt.Fprintln(out, "format checks passed")
	fmt.Fprintf(out, "chain checks passed at ledger %d: %d of the vault's %d leaves, %d nullifiers present\n",
		report.Ledger, report.Leaves, report.ChainLeaves, report.Nullifiers)
	return nil
}

func serve(ctx context.Context, args []string, out io.Writer) error {
	fs := flags("serve", out)
	dir := fs.String("dir", "", "the archive to serve")
	addr := fs.String("addr", defaultAddr, "where to listen")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := require(map[string]string{"dir": *dir}); err != nil {
		return err
	}
	fmt.Fprintf(out, "serving %s on http://%s\n", *dir, *addr)
	return httpapi.Serve(ctx, *addr, handler(*dir))
}

var served = regexp.MustCompile(`^/(manifest\.json|windows/[0-9]{10}\.jsonl\.gz)$`)

// handler serves the archive's own files and nothing else in dir, to any page that asks. A
// symbolic link is never followed, so a directory someone else made cannot leak a file.
func handler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		switch {
		case r.Method == http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD")
			w.WriteHeader(http.StatusNoContent)
		case r.Method != http.MethodGet && r.Method != http.MethodHead:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		case !served.MatchString(r.URL.Path):
			http.NotFound(w, r)
		default:
			sendFile(w, r, dir)
		}
	})
}

func sendFile(w http.ResponseWriter, r *http.Request, dir string) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer root.Close()
	name := strings.TrimPrefix(r.URL.Path, "/")
	f, err := vaultarchive.OpenRegular(root, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if name == vaultarchive.ManifestName {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, name, info.ModTime(), f)
}
