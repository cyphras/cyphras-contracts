package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/tree"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
	"github.com/cyphras/cyphras-contracts/services/internal/vaultarchive"
)

const (
	window     = vaultarchive.WindowLedgers
	deployAt   = 10
	passphrase = "Test SDF Network ; September 2015"
)

// sample is a vault's history over four windows: deposits and admissions in the first two, none in
// the third, and a deposit in the fourth, which is still open.
func sample() []vault.RawEvent {
	c := vaulttest.New(deployAt, 1_728_000_000)
	c.Shield(vaulttest.Depositor, 10_000_000)
	c.NextLedger(5)
	c.Shield(vaulttest.Depositor, 20_000_000)
	c.NextLedger(5)
	c.Attest(2)
	c.NextLedger(5)
	c.Admit(1, 2)
	c.Ledger = window + 39
	c.NextLedger(86_400)
	id := c.Shield(vaulttest.Depositor, 30_000_000)
	c.NextLedger(5)
	c.Attest(id)
	c.NextLedger(5)
	c.Admit(id)
	c.NextLedger(5)
	c.Transact(-1_000_000, 100_000, vaulttest.Relayer)
	c.Ledger = 3*window + 6
	c.NextLedger(2 * 86_400)
	c.Shield(vaulttest.Depositor, 40_000_000)
	return c.Events
}

func writeDeployment(t *testing.T, vaults ...string) string {
	t.Helper()
	type entry struct {
		Asset        string `json:"asset"`
		Vault        string `json:"vault"`
		Token        string `json:"token"`
		DeployLedger uint32 `json:"deploy_ledger"`
		FeeTier      string `json:"fee_tier"`
	}
	var d struct {
		Network           string  `json:"network"`
		NetworkPassphrase string  `json:"network_passphrase"`
		Vaults            []entry `json:"vaults"`
	}
	d.Network, d.NetworkPassphrase = "testnet", passphrase
	for _, v := range vaults {
		d.Vaults = append(d.Vaults, entry{Asset: "native", Vault: v, Token: vaulttest.Token, DeployLedger: deployAt, FeeTier: "100000"})
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "testnet.json")
	if err := os.WriteFile(name, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

// indexerArchive is what the indexer keeps: the raw events, covered to a ledger of the fourth window.
func indexerArchive(t *testing.T, events []vault.RawEvent) string {
	t.Helper()
	dir := t.TempDir()
	if err := (archive.Writer{Dir: dir}).Append(events, deployAt, 3*window+100); err != nil {
		t.Fatal(err)
	}
	return dir
}

func contractEvent(t *testing.T, e vault.RawEvent) xdr.ContractEvent {
	t.Helper()
	id, err := strkey.Decode(strkey.VersionByteContract, e.Contract)
	if err != nil {
		t.Fatal(err)
	}
	var contract xdr.ContractId
	copy(contract[:], id)
	topics := make([]xdr.ScVal, len(e.Topics))
	for i, s := range e.Topics {
		if err := xdr.SafeUnmarshalBase64(s, &topics[i]); err != nil {
			t.Fatal(err)
		}
	}
	var data xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(e.Value, &data); err != nil {
		t.Fatal(err)
	}
	return xdr.ContractEvent{ContractId: &contract, Type: xdr.ContractEventTypeContract, Body: xdr.ContractEventBody{
		V: 0, V0: &xdr.ContractEventV0{Topics: topics, Data: data},
	}}
}

// ledgerMeta is a ledger that holds the events as RPC positions them: transaction number Tx in
// application order, all in the first operation.
func ledgerMeta(t *testing.T, seq uint32, events []vault.RawEvent) xdr.LedgerCloseMeta {
	t.Helper()
	closeTime := uint64(1)
	var txs []xdr.TransactionResultMetaV1
	for _, e := range events {
		closeTime = uint64(e.ClosedAt)
		for uint32(len(txs)) < e.Tx {
			txs = append(txs, xdr.TransactionResultMetaV1{
				Result:            xdr.TransactionResultPair{Result: xdr.TransactionResult{Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxSuccess, Results: &[]xdr.OperationResult{}}}},
				TxApplyProcessing: xdr.TransactionMeta{V: 4, V4: &xdr.TransactionMetaV4{Operations: []xdr.OperationMetaV2{{}}}},
			})
		}
		tx := &txs[e.Tx-1]
		hash, err := hex.DecodeString(e.TxHash)
		if err != nil {
			t.Fatal(err)
		}
		copy(tx.Result.TransactionHash[:], hash)
		op := &tx.TxApplyProcessing.V4.Operations[0]
		op.Events = append(op.Events, contractEvent(t, e))
	}
	return xdr.LedgerCloseMeta{V: 2, V2: &xdr.LedgerCloseMetaV2{
		LedgerHeader: xdr.LedgerHeaderHistoryEntry{Header: xdr.LedgerHeader{
			LedgerSeq: xdr.Uint32(seq),
			ScpValue:  xdr.StellarValue{CloseTime: xdr.TimePoint(closeTime), Ext: xdr.StellarValueExt{V: xdr.StellarValueTypeStellarValueBasic}},
		}},
		TxSet:        xdr.GeneralizedTransactionSet{V: 1, V1TxSet: &xdr.TransactionSetV1{}},
		TxProcessing: txs,
	}}
}

// perFile is the number of ledgers in each file of the SEP-54 archive the tests serve.
const perFile = 64

// ledgerArchive serves the ledgers of the first windows as a SEP-54 archive with files of perFile
// ledgers, and returns its base URL.
func ledgerArchive(t *testing.T, events []vault.RawEvent, windows int) string {
	t.Helper()
	files := map[string][]byte{}
	for start := uint32(0); start < uint32(windows)*window; start += perFile {
		batch := xdr.LedgerCloseMetaBatch{StartSequence: xdr.Uint32(max(start, 1)), EndSequence: xdr.Uint32(start + perFile - 1)}
		for seq := max(start, 1); seq < start+perFile; seq++ {
			var in []vault.RawEvent
			for _, e := range events {
				if e.Ledger == seq {
					in = append(in, e)
				}
			}
			batch.LedgerCloseMetas = append(batch.LedgerCloseMetas, ledgerMeta(t, seq, in))
		}
		raw, err := batch.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var compressed bytes.Buffer
		enc, err := zstd.NewWriter(&compressed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enc.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err := enc.Close(); err != nil {
			t.Fatal(err)
		}
		files[fmt.Sprintf("/pubnet/%08X--%d-%d.xdr.zst", math.MaxUint32-start, start, start+perFile-1)] = compressed.Bytes()
	}
	files["/pubnet/.config.json"] = []byte(fmt.Sprintf(`{"networkPassphrase":%q,"compression":"zstd","ledgersPerBatch":%d,"batchesPerPartition":1}`, passphrase, perFile))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := files[r.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/pubnet"
}

func do(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(context.Background(), args, &out)
	return out.String(), err
}

func decompressed(t *testing.T, dir, name string) []byte {
	t.Helper()
	compressed, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestExportAndRebuildOfTheSameLedgersGiveTheSameWindows(t *testing.T) {
	events := sample()
	deployment := writeDeployment(t, vaulttest.Vault)
	exported := filepath.Join(t.TempDir(), "exported")
	if _, err := do(t, "export", "--dir", indexerArchive(t, events), "--deployment", deployment, "--network", "testnet", "--vault", vaulttest.Vault, "--out", exported); err != nil {
		t.Fatal(err)
	}
	base := ledgerArchive(t, events, 3)
	rebuilt := filepath.Join(t.TempDir(), "rebuilt")
	if _, err := do(t, "rebuild", "--ledger-meta", base, "--deployment", deployment, "--out", rebuilt, "--to", fmt.Sprint(3*window-1), "--workers", "4"); err != nil {
		t.Fatal(err)
	}
	// Without --to the latest ledger of the RPC decides which windows have closed.
	rpcFake := rpctest.New(passphrase, 3*window+100)
	t.Cleanup(func(old func(string) rpc.Client) func() { return func() { dialRPC = old } }(dialRPC))
	dialRPC = func(string) rpc.Client { return rpcFake }
	byRPC := filepath.Join(t.TempDir(), "by-rpc")
	if _, err := do(t, "rebuild", "--ledger-meta", base, "--deployment", deployment, "--out", byRPC, "--rpc", "http://rpc.invalid"); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(exported, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m vaultarchive.Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Windows) != 3 || m.CoveredTo != 3*window-1 || m.Windows[0].Events != 13 || m.Windows[2].Events != 0 {
		t.Fatalf("manifest %+v", m)
	}
	for _, other := range []string{rebuilt, byRPC} {
		got, err := os.ReadFile(filepath.Join(other, "manifest.json"))
		if err != nil || !bytes.Equal(got, manifest) {
			t.Fatalf("manifest of %s differs: %v", filepath.Base(other), err)
		}
		for _, w := range m.Windows[:2] {
			a, b := decompressed(t, exported, w.File()), decompressed(t, other, w.File())
			sum := sha256.Sum256(b)
			if !bytes.Equal(a, b) || hex.EncodeToString(sum[:]) != w.SHA256 {
				t.Fatalf("window %d of %s differs", w.Start, filepath.Base(other))
			}
		}
	}
}

// chainFake is a vault holding the archive's leaves and nullifiers, as the entries the checks read.
func chainFake(t *testing.T, dir string) *rpctest.Fake {
	t.Helper()
	c, err := vaultarchive.Load(context.Background(), vaultarchive.DirFetcher(dir), vaultarchive.Expect{})
	if err != nil {
		t.Fatal(err)
	}
	var tr tree.Tree
	ring := make([]xdr.ScVal, vault.RootHistory)
	for i := range ring {
		ring[i] = vaulttest.Field(fr.Element{})
	}
	ring[0] = vaulttest.Field(tree.Zero(tree.Depth))
	for i := 0; i < len(c.Commitments); i += 2 {
		if _, err := tr.AppendPair(c.Commitments[i], c.Commitments[i+1]); err != nil {
			t.Fatal(err)
		}
		ring[(i/2+1)%vault.RootHistory] = vaulttest.Field(tr.Root())
	}
	newest := uint32((len(c.Commitments) / 2) % vault.RootHistory)
	f := rpctest.New(passphrase, 5*window)
	set := func(k xdr.LedgerKey, err error, v xdr.ScVal) {
		if err != nil {
			t.Fatal(err)
		}
		f.SetContractData(k, v, 100, nil)
	}
	k, err := vault.RootsKey(vaulttest.Vault)
	set(k, err, vault.Struct(vault.Field{Name: "roots", Value: vault.Vec(ring...)}, vault.Field{Name: "newest", Value: vault.U32(newest)}))
	k, err = vault.NextLeafKey(vaulttest.Vault)
	set(k, err, vault.U64(uint64(len(c.Commitments))))
	for _, n := range c.Nullifiers {
		k, err = vault.NullifierKey(vaulttest.Vault, n.Bytes())
		set(k, err, vault.Bool(true))
	}
	return f
}

// tamperLeaf gives the first commitment of the first window another value, keeping the window and
// the manifest consistent, so that only the chain can tell.
func tamperLeaf(t *testing.T, dir string) {
	t.Helper()
	name := "windows/0000000000.jsonl.gz"
	lines := strings.Split(strings.TrimSuffix(string(decompressed(t, dir, name)), "\n"), "\n")
	for i, line := range lines[:len(lines)-1] {
		var e vault.RawEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		decoded, err := vault.Decode(e)
		if err != nil {
			t.Fatal(err)
		}
		c, ok := decoded.Body.(vault.NewCommitment)
		if !ok {
			continue
		}
		e.Value, err = xdr.MarshalBase64(vault.Struct(
			vault.Field{Name: "index", Value: vault.U64(c.Index)},
			vault.Field{Name: "commitment", Value: vaulttest.Field(fr.SetUint64(424242))},
			vault.Field{Name: "encrypted_output", Value: vault.Bytes(c.Ciphertext)},
		))
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
		lines[i] = strings.TrimSuffix(buf.String(), "\n")
		break
	}
	data := []byte(strings.Join(lines, "\n") + "\n")
	var packed bytes.Buffer
	zw := gzip.NewWriter(&packed)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), packed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	var m vaultarchive.Manifest
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	m.Windows[0].Bytes, m.Windows[0].SHA256 = int64(len(data)), hex.EncodeToString(sum[:])
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func exportSample(t *testing.T) (dir, deployment string) {
	t.Helper()
	deployment = writeDeployment(t, vaulttest.Vault)
	dir = filepath.Join(t.TempDir(), "archive")
	if _, err := do(t, "export", "--dir", indexerArchive(t, sample()), "--deployment", deployment, "--out", dir); err != nil {
		t.Fatal(err)
	}
	return dir, deployment
}

func TestVerifyAcceptsAGoodArchiveAndRefusesATamperedLeafAndAMissingNullifier(t *testing.T) {
	dir, deployment := exportSample(t)
	fake := chainFake(t, dir)
	t.Cleanup(func(old func(string) rpc.Client) func() { return func() { dialRPC = old } }(dialRPC))
	dialRPC = func(string) rpc.Client { return fake }
	out, err := do(t, "verify", "--dir", dir, "--rpc", "http://rpc.invalid", "--deployment", deployment)
	if err != nil || !strings.Contains(out, "chain checks passed") || !strings.Contains(out, "8 of its 8 leaves, 8 nullifiers present") {
		t.Fatalf("a good archive: %q, %v", out, err)
	}
	if _, err := do(t, "verify", "--dir", dir, "--format-only", "--deployment", writeDeployment(t, vaulttest.Token)); err == nil || !strings.Contains(err.Error(), "archive of vault") {
		t.Fatalf("an archive of another vault than the pinned one: %v", err)
	}
	if out, err := do(t, "verify", "--dir", dir, "--format-only"); err != nil || strings.Contains(out, "chain checks") {
		t.Fatalf("format only: %q, %v", out, err)
	}

	missing := chainFake(t, dir)
	c, err := vaultarchive.Load(context.Background(), vaultarchive.DirFetcher(dir), vaultarchive.Expect{})
	if err != nil {
		t.Fatal(err)
	}
	k, err := vault.NullifierKey(vaulttest.Vault, c.Nullifiers[3].Bytes())
	if err != nil {
		t.Fatal(err)
	}
	missing.DeleteEntry(k)
	dialRPC = func(string) rpc.Client { return missing }
	if _, err := do(t, "verify", "--dir", dir, "--rpc", "http://rpc.invalid", "--deployment", deployment); err == nil || !strings.Contains(err.Error(), "has no entry in the vault") {
		t.Fatalf("a nullifier the vault never spent: %v", err)
	}

	tampered := filepath.Join(t.TempDir(), "tampered")
	if err := os.CopyFS(tampered, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	tamperLeaf(t, tampered)
	dialRPC = func(string) rpc.Client { return fake }
	if out, err := do(t, "verify", "--dir", tampered, "--format-only"); err != nil {
		t.Fatalf("the tampered archive is well formed: %q, %v", out, err)
	}
	if _, err := do(t, "verify", "--dir", tampered, "--rpc", "http://rpc.invalid", "--deployment", deployment); err == nil || !strings.Contains(err.Error(), "never held") {
		t.Fatalf("a tampered leaf: %v", err)
	}
}

func TestTheServerGivesTheArchiveToAnyPageAndNothingElse(t *testing.T) {
	dir, _ := exportSample(t)
	if err := os.WriteFile(filepath.Join(dir, "private.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler(dir))
	defer srv.Close()
	get := func(method, path string) *http.Response {
		req, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	for _, path := range []string{"/manifest.json", "/windows/0000000000.jsonl.gz"} {
		resp := get(http.MethodGet, path)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s: %d, %v", path, resp.StatusCode, resp.Header)
		}
	}
	for _, path := range []string{"/", "/windows/", "/private.txt", "/windows/0000000002.jsonl.gz", "/windows/../private.txt", "/%2e%2e/private.txt"} {
		if resp := get(http.MethodGet, path); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
	}
	if resp := get(http.MethodPost, "/manifest.json"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("post: %d", resp.StatusCode)
	}
	if resp := get(http.MethodOptions, "/manifest.json"); resp.StatusCode != http.StatusNoContent || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("preflight: %d", resp.StatusCode)
	}
	out, err := do(t, "verify", "--url", srv.URL, "--format-only")
	if err != nil || !strings.Contains(out, "format checks passed") {
		t.Fatalf("verify over the server: %q, %v", out, err)
	}
	host, _, err := net.SplitHostPort(defaultAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatalf("the server listens on %s by default", defaultAddr)
	}
}

func TestTheCommandsRefuseWhatTheyCannotDo(t *testing.T) {
	deployment := writeDeployment(t, vaulttest.Vault)
	two := writeDeployment(t, vaulttest.Vault, vaulttest.Token)
	raw := indexerArchive(t, sample())
	out := filepath.Join(t.TempDir(), "out")
	for name, args := range map[string][]string{
		"no command":                   nil,
		"an unknown command":           {"fetch"},
		"a missing flag":               {"export", "--dir", raw, "--out", out},
		"an extra argument":            {"export", "--dir", raw, "--deployment", deployment, "--out", out, "more"},
		"another network":              {"export", "--dir", raw, "--deployment", deployment, "--out", out, "--network", "mainnet"},
		"several vaults, none named":   {"export", "--dir", raw, "--deployment", two, "--out", out},
		"a vault the file lacks":       {"export", "--dir", raw, "--deployment", deployment, "--out", out, "--vault", vaulttest.Depositor},
		"an empty event archive":       {"export", "--dir", t.TempDir(), "--deployment", deployment, "--out", out},
		"a rebuild with no end":        {"rebuild", "--ledger-meta", "http://127.0.0.1:1", "--deployment", deployment, "--out", out},
		"a verify with neither source": {"verify", "--format-only"},
		"a verify with both":           {"verify", "--dir", raw, "--url", "http://127.0.0.1:1", "--format-only"},
		"a verify with no chain":       {"verify", "--dir", raw},
		"a ledger past the last":       {"rebuild", "--ledger-meta", "http://127.0.0.1:1", "--deployment", deployment, "--out", out, "--to", "99999999999"},
	} {
		if _, err := do(t, args...); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
