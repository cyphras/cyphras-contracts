package follow

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// LedgerArchive reads ledger metadata in the SEP-54 layout over HTTP, such as the public pubnet
// archive at https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/pubnet.
// It holds every ledger, so a rebuild scans all of them since the deploy ledger.
type LedgerArchive struct {
	BaseURL    string
	Passphrase string
	Vault      string
	HTTP       *http.Client
	// Workers is the number of files fetched at once.
	Workers int

	mu     sync.Mutex
	loaded bool
	schema archiveSchema
}

// archiveClient bounds every archive request, so a stalled transfer cannot hold a rebuild forever.
var archiveClient = &http.Client{Timeout: 2 * time.Minute}

const (
	maxCompressed = 256 << 20
	// maxLedgerMeta bounds the decompressed metadata of one ledger, far above what a ledger holds.
	maxLedgerMeta = 64 << 20
)

type archiveSchema struct {
	NetworkPassphrase   string `json:"networkPassphrase"`
	Compression         string `json:"compression"`
	LedgersPerBatch     uint32 `json:"ledgersPerBatch"`
	BatchesPerPartition uint32 `json:"batchesPerPartition"`
}

// objectKey follows the SEP-54 naming, in which a partition and a file are named by the
// complement of their first ledger so that listings sort newest first.
func (s archiveSchema) objectKey(ledger uint32) string {
	var key string
	if s.BatchesPerPartition > 1 {
		size := s.LedgersPerBatch * s.BatchesPerPartition
		start := ledger / size * size
		end := uint32(min(uint64(start)+uint64(size)-1, math.MaxUint32))
		key = fmt.Sprintf("%08X--%d-%d/", math.MaxUint32-start, start, end)
	}
	start := ledger / s.LedgersPerBatch * s.LedgersPerBatch
	end := start + s.LedgersPerBatch - 1
	key += fmt.Sprintf("%08X--%d", math.MaxUint32-start, start)
	if end != start {
		key += fmt.Sprintf("-%d", end)
	}
	return key + ".xdr.zst"
}

func (a *LedgerArchive) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return archiveClient
}

// readAll refuses input longer than limit instead of cutting it short.
func readAll(r io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("more than %d bytes", limit)
	}
	return raw, nil
}

func (a *LedgerArchive) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(a.BaseURL, "/")+"/"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", ErrRetention, path)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("archive answered %d for %s", resp.StatusCode, path)
	}
	raw, err := readAll(resp.Body, maxCompressed)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return raw, nil
}

// load reads the archive's layout once it can; a failed read is retried on the next call.
func (a *LedgerArchive) load(ctx context.Context) (archiveSchema, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loaded {
		return a.schema, nil
	}
	raw, err := a.get(ctx, ".config.json")
	if err != nil {
		return archiveSchema{}, err
	}
	var schema archiveSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return archiveSchema{}, err
	}
	switch {
	case schema.NetworkPassphrase != a.Passphrase:
		return archiveSchema{}, fmt.Errorf("archive holds %q", schema.NetworkPassphrase)
	case schema.Compression != "zstd":
		return archiveSchema{}, fmt.Errorf("archive compression %q", schema.Compression)
	case schema.LedgersPerBatch == 0:
		return archiveSchema{}, errors.New("archive has no batch size")
	}
	a.schema, a.loaded = schema, true
	return schema, nil
}

// Events implements Source.
func (a *LedgerArchive) Events(ctx context.Context, from, to uint32) ([]vault.RawEvent, error) {
	if from > to {
		return nil, fmt.Errorf("%w: ledgers %d to %d", ErrRange, from, to)
	}
	schema, err := a.load(ctx)
	if err != nil {
		return nil, err
	}
	contract, err := strkey.Decode(strkey.VersionByteContract, a.Vault)
	if err != nil {
		return nil, err
	}
	var files []uint32
	for l := uint64(from / schema.LedgersPerBatch * schema.LedgersPerBatch); l <= uint64(to); l += uint64(schema.LedgersPerBatch) {
		files = append(files, uint32(l))
	}
	results := make([][]vault.RawEvent, len(files))
	errs := make([]error, len(files))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range max(a.Workers, 1) {
		wg.Go(func() {
			for i := range jobs {
				results[i], errs[i] = a.file(ctx, schema, files[i], from, to, xdr.ContractId(contract))
			}
		})
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	var out []vault.RawEvent
	for i := range files {
		if errs[i] != nil {
			return nil, errs[i]
		}
		out = append(out, results[i]...)
	}
	return out, nil
}

func (a *LedgerArchive) file(ctx context.Context, schema archiveSchema, first, from, to uint32, contract xdr.ContractId) ([]vault.RawEvent, error) {
	compressed, err := a.get(ctx, schema.objectKey(first))
	if err != nil {
		return nil, err
	}
	dec, err := zstd.NewReader(bytes.NewReader(compressed), zstd.WithDecoderMaxMemory(1<<30))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	raw, err := readAll(dec, int64(schema.LedgersPerBatch)*maxLedgerMeta)
	if err != nil {
		return nil, fmt.Errorf("ledger batch %d: %w", first, err)
	}
	var batch xdr.LedgerCloseMetaBatch
	if err := batch.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("ledger batch %d: %w", first, err)
	}
	// Every ledger of the batch that the range needs must be there, in order, or events would be
	// lost without a trace.
	want, last := max(from, first), min(to, uint32(min(uint64(first)+uint64(schema.LedgersPerBatch)-1, math.MaxUint32)))
	var out []vault.RawEvent
	for _, lcm := range batch.LedgerCloseMetas {
		seq := lcm.LedgerSequence()
		if seq < want || seq > last {
			continue
		}
		if seq != want {
			return nil, fmt.Errorf("ledger batch %d: ledger %d where %d belongs", first, seq, want)
		}
		events, err := ledgerEvents(lcm, contract)
		if err != nil {
			return nil, fmt.Errorf("ledger %d: %w", seq, err)
		}
		out = append(out, events...)
		want++
	}
	if want <= last {
		return nil, fmt.Errorf("ledger batch %d: ledger %d is missing", first, want)
	}
	return out, nil
}

// ledgerEvents extracts the contract's events from one ledger with the positions RPC gives them:
// a 1-based transaction index in application order, and each event's index among all events of
// its operation.
func ledgerEvents(lcm xdr.LedgerCloseMeta, contract xdr.ContractId) ([]vault.RawEvent, error) {
	var out []vault.RawEvent
	for i := range lcm.CountTransactions() {
		if !lcm.TransactionResultPair(i).Successful() {
			continue
		}
		meta := lcm.TxApplyProcessing(i)
		var perOp [][]xdr.ContractEvent
		switch meta.V {
		case 0, 1, 2:
			// Metadata older than Soroban carries no contract events.
		case 3:
			if sm := meta.MustV3().SorobanMeta; sm != nil {
				perOp = [][]xdr.ContractEvent{sm.Events}
			}
		case 4:
			for _, op := range meta.MustV4().Operations {
				perOp = append(perOp, op.Events)
			}
		default:
			return nil, fmt.Errorf("%w: transaction meta version %d", vault.ErrMalformed, meta.V)
		}
		hash := lcm.TransactionHash(i)
		for op, events := range perOp {
			for index, e := range events {
				if e.Type != xdr.ContractEventTypeContract || e.ContractId == nil || *e.ContractId != contract {
					continue
				}
				raw, err := rawFromXDR(e, lcm, hex.EncodeToString(hash[:]), uint32(i+1), uint32(op), uint32(index))
				if err != nil {
					return nil, err
				}
				out = append(out, raw)
			}
		}
	}
	return out, nil
}

func rawFromXDR(e xdr.ContractEvent, lcm xdr.LedgerCloseMeta, hash string, tx, op, index uint32) (vault.RawEvent, error) {
	raw, err := vault.RawFromXDR(e)
	if err != nil {
		return vault.RawEvent{}, err
	}
	raw.Ledger, raw.ClosedAt, raw.TxHash = lcm.LedgerSequence(), lcm.LedgerCloseTime(), hash
	raw.Tx, raw.Op, raw.Index = tx, op, index
	return raw, nil
}
