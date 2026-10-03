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

	once   sync.Once
	schema archiveSchema
	err    error
}

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
	return http.DefaultClient
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
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

func (a *LedgerArchive) load(ctx context.Context) error {
	a.once.Do(func() {
		raw, err := a.get(ctx, ".config.json")
		if err != nil {
			a.err = err
			return
		}
		if err := json.Unmarshal(raw, &a.schema); err != nil {
			a.err = err
			return
		}
		switch {
		case a.schema.NetworkPassphrase != a.Passphrase:
			a.err = fmt.Errorf("archive holds %q", a.schema.NetworkPassphrase)
		case a.schema.Compression != "zstd":
			a.err = fmt.Errorf("archive compression %q", a.schema.Compression)
		case a.schema.LedgersPerBatch == 0:
			a.err = errors.New("archive has no batch size")
		}
	})
	return a.err
}

// Events implements Source.
func (a *LedgerArchive) Events(ctx context.Context, from, to uint32) ([]vault.RawEvent, error) {
	if err := a.load(ctx); err != nil {
		return nil, err
	}
	contract, err := strkey.Decode(strkey.VersionByteContract, a.Vault)
	if err != nil {
		return nil, err
	}
	var files []uint32
	for l := from / a.schema.LedgersPerBatch * a.schema.LedgersPerBatch; l <= to; l += a.schema.LedgersPerBatch {
		files = append(files, l)
	}
	results := make([][]vault.RawEvent, len(files))
	errs := make([]error, len(files))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range max(a.Workers, 1) {
		wg.Go(func() {
			for i := range jobs {
				results[i], errs[i] = a.file(ctx, files[i], from, to, xdr.ContractId(contract))
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

func (a *LedgerArchive) file(ctx context.Context, first, from, to uint32, contract xdr.ContractId) ([]vault.RawEvent, error) {
	compressed, err := a.get(ctx, a.schema.objectKey(first))
	if err != nil {
		return nil, err
	}
	dec, err := zstd.NewReader(bytes.NewReader(compressed), zstd.WithDecoderMaxMemory(1<<30))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	raw, err := io.ReadAll(dec)
	if err != nil {
		return nil, err
	}
	var batch xdr.LedgerCloseMetaBatch
	if err := batch.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("ledger batch %d: %w", first, err)
	}
	var out []vault.RawEvent
	for _, lcm := range batch.LedgerCloseMetas {
		seq := lcm.LedgerSequence()
		if seq < from || seq > to {
			continue
		}
		events, err := ledgerEvents(lcm, contract)
		if err != nil {
			return nil, fmt.Errorf("ledger %d: %w", seq, err)
		}
		out = append(out, events...)
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
		case 3:
			if sm := meta.MustV3().SorobanMeta; sm != nil {
				perOp = [][]xdr.ContractEvent{sm.Events}
			}
		case 4:
			for _, op := range meta.MustV4().Operations {
				perOp = append(perOp, op.Events)
			}
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
	body, ok := e.Body.GetV0()
	if !ok {
		return vault.RawEvent{}, fmt.Errorf("%w: event body version %d", vault.ErrMalformed, e.Body.V)
	}
	topics := make([]string, len(body.Topics))
	for i, t := range body.Topics {
		s, err := xdr.MarshalBase64(t)
		if err != nil {
			return vault.RawEvent{}, err
		}
		topics[i] = s
	}
	value, err := xdr.MarshalBase64(body.Data)
	if err != nil {
		return vault.RawEvent{}, err
	}
	contract, err := strkey.Encode(strkey.VersionByteContract, e.ContractId[:])
	if err != nil {
		return vault.RawEvent{}, err
	}
	return vault.RawEvent{
		Ledger: lcm.LedgerSequence(), ClosedAt: lcm.LedgerCloseTime(), TxHash: hash,
		Tx: tx, Op: op, Index: index, Contract: contract, Topics: topics, Value: value,
	}, nil
}
