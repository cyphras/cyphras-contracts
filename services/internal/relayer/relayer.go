package relayer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Error codes of the API.
const (
	CodeBadRequest  = "bad_request"
	CodeWrongVault  = "wrong_vault"
	CodeFeeTooLow   = "fee_too_low"
	CodeFeeAboveCap = "fee_above_cap"
	CodeDuplicate   = "duplicate"
	CodePaused      = "paused"
	CodeRefused     = "refused"
	CodeRejected    = "rejected"
	CodeRateLimited = "rate_limited"
	CodeUnavailable = "unavailable"
)

// Config fixes what the relayer serves.
type Config struct {
	Vault      string
	NetworkID  [32]byte
	Asset      string
	FeeAddress string
	Pricing    Pricing
	// LedgerSeconds is the close time used to turn a time into a ledger.
	LedgerSeconds int64
	// MaxHeld bounds the delayed requests kept in memory.
	MaxHeld int
	// Jitter is the window after not_before in which a delayed request is sent.
	Jitter time.Duration
}

// Screener answers whether an unshield destination may be paid.
type Screener interface {
	Screen(ctx context.Context, address string) (allow bool, reason uint32, err error)
}

// Relayer validates, screens, submits and tracks relayed transactions.
type Relayer struct {
	cfg      Config
	rpc      rpc.Client
	engine   *submit.Engine
	channels *channelPool
	costs    *Costs
	quotes   quotes
	screen   Screener
	db       store
	alerts   *alert.Alerter
	log      *slog.Logger
	now      func() time.Time
	ctx      context.Context

	submitLimit   *httpapi.Limiter
	simulateLimit *httpapi.Limiter

	mu       sync.Mutex
	inflight map[fr.Element]bool
	statuses map[string]txStatus
	order    []string
	held     int
	// heldBy follows each held request by its first input nullifier, which the client knows, since
	// a held request has no transaction hash until it is sent.
	heldBy    map[fr.Element]heldRequest
	heldOrder []fr.Element

	chainMu     sync.RWMutex
	inst        *vault.Instance
	latest      uint32
	latestClose int64
}

// txStatus is a submitted transaction's state. ExitID is set when the transaction succeeded but
// its payment waits in the vault's exit queue, which pays it later in turn.
type txStatus struct {
	Status string  `json:"status"`
	Code   string  `json:"code,omitempty"`
	ExitID *uint64 `json:"exit_id,omitempty"`
}

// maxStatuses bounds the transaction statuses kept in memory.
const maxStatuses = 10_000

// New builds a relayer; ctx bounds the background work of every submission.
func New(ctx context.Context, cfg Config, client rpc.Client, engine *submit.Engine, channels []*submit.Account,
	screen Screener, db store, bootstrapCost int64, alerts *alert.Alerter, log *slog.Logger) (*Relayer, error) {
	if err := cfg.Pricing.Validate(); err != nil {
		return nil, err
	}
	samples, err := db.recentResourceFees(ctx, Samples)
	if err != nil {
		return nil, err
	}
	return &Relayer{
		cfg: cfg, rpc: client, engine: engine, channels: newChannelPool(channels), costs: NewCosts(bootstrapCost, samples),
		screen: screen, db: db, alerts: alerts, log: log, now: time.Now, ctx: ctx,
		submitLimit: httpapi.NewLimiter(120, 20), simulateLimit: httpapi.NewLimiter(60, 10),
		inflight: map[fr.Element]bool{}, statuses: map[string]txStatus{}, heldBy: map[fr.Element]heldRequest{},
	}, nil
}

// Refresh reads the vault's state and the chain tip, and publishes a quote.
func (r *Relayer) Refresh(ctx context.Context) error {
	inst, _, _, err := rpc.VaultInstance(ctx, r.rpc, r.cfg.Vault)
	if err != nil {
		return err
	}
	h, err := r.rpc.GetHealth(ctx)
	if err != nil {
		return err
	}
	r.chainMu.Lock()
	r.inst, r.latest, r.latestClose = &inst, h.LatestLedger, h.LatestLedgerCloseTime
	r.chainMu.Unlock()
	_, err = r.Quote(ctx)
	return err
}

// ErrNoQuote reports that the quote would exceed the vault's fee cap, or that the relayer cannot
// price right now.
var ErrNoQuote = errors.New("relayer: no quote")

// CurrentQuote serves the quote Refresh published in the last 15 seconds, so a client's request
// for a quote costs no RPC call, and prices anew only when there is none.
func (r *Relayer) CurrentQuote(ctx context.Context) (*big.Int, error) {
	if fee := r.quotes.newest(r.now().Add(-15 * time.Second)); fee != nil {
		return fee, nil
	}
	return r.Quote(ctx)
}

// Quote prices one relayed transaction now and remembers the price for QuoteLifetime.
func (r *Relayer) Quote(ctx context.Context) (*big.Int, error) {
	inclusion, err := r.engine.InclusionFee(ctx)
	if err != nil {
		return nil, ErrNoQuote
	}
	fee := r.cfg.Pricing.Quote(r.costs.ResourceFee() + inclusion)
	r.chainMu.RLock()
	inst := r.inst
	r.chainMu.RUnlock()
	if inst == nil || fee.Cmp(inst.Limits.MaxFee) > 0 {
		return nil, ErrNoQuote
	}
	r.quotes.publish(r.now(), fee)
	return fee, nil
}

func (r *Relayer) view() (*vault.Instance, uint32, int64) {
	r.chainMu.RLock()
	defer r.chainMu.RUnlock()
	return r.inst, r.latest, r.latestClose
}

// ledgerAt estimates the ledger that closes at time t.
func (r *Relayer) ledgerAt(t int64) uint32 {
	_, latest, closeTime := r.view()
	if t <= closeTime {
		return latest
	}
	return latest + uint32((t-closeTime+r.cfg.LedgerSeconds-1)/r.cfg.LedgerSeconds)
}

// failure is an API error.
type failure struct {
	status int
	code   string
	reason *uint32
}

func (f *failure) Error() string { return f.code }

func fail(status int, code string) *failure { return &failure{status: status, code: code} }

// check compares a parsed request with the relayer and the vault.
func (r *Relayer) check(req Request) *failure {
	e := req.Ext
	if e.Vault != r.cfg.Vault || e.NetworkID != r.cfg.NetworkID {
		return fail(http.StatusBadRequest, CodeWrongVault)
	}
	if e.ExtAmount.Sign() > 0 || e.Relayer != r.cfg.FeeAddress || e.Recipient == r.cfg.Vault {
		return fail(http.StatusBadRequest, CodeBadRequest)
	}
	if e.ExtAmount.Sign() == 0 && e.Recipient != e.Relayer {
		return fail(http.StatusBadRequest, CodeBadRequest)
	}
	inst, latest, _ := r.view()
	if inst == nil {
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	if e.Fee.Cmp(inst.Limits.MaxFee) > 0 {
		return fail(http.StatusBadRequest, CodeFeeAboveCap)
	}
	low := r.quotes.lowest(r.now())
	if low == nil {
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	if e.Fee.Cmp(low) < 0 {
		return fail(http.StatusBadRequest, CodeFeeTooLow)
	}
	outflow := new(big.Int).Sub(e.Fee, e.ExtAmount)
	if outflow.Cmp(inst.Limits.MaxDailyOutflow) > 0 {
		// No window can ever pay it; the client must split the exit.
		return fail(http.StatusUnprocessableEntity, CodeRejected)
	}
	now := r.now().Unix()
	minDeadline := latest + 3
	if req.NotBefore != nil {
		if *req.NotBefore > now+24*3600 {
			return fail(http.StatusBadRequest, CodeBadRequest)
		}
		if *req.NotBefore > now {
			minDeadline = r.ledgerAt(*req.NotBefore+int64(r.cfg.Jitter.Seconds())) + 12
		}
	}
	if e.Deadline < minDeadline {
		return fail(http.StatusUnprocessableEntity, CodeRejected)
	}
	hash, err := e.Hash()
	if err != nil || hash != req.Proof.ExtDataHash || vault.PublicAmount(e.ExtAmount, e.Fee) != req.Proof.PublicAmount {
		return fail(http.StatusUnprocessableEntity, CodeRejected)
	}
	if inst.Status.Halted(uint64(now)) {
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	if e.ExtAmount.Sign() == 0 && inst.Status.TransfersPaused {
		return fail(http.StatusServiceUnavailable, CodePaused)
	}
	return nil
}

func (r *Relayer) claim(nfs [2]fr.Element) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inflight[nfs[0]] || r.inflight[nfs[1]] {
		return false
	}
	r.inflight[nfs[0]], r.inflight[nfs[1]] = true, true
	return true
}

func (r *Relayer) unclaim(nfs [2]fr.Element) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.inflight, nfs[0])
	delete(r.inflight, nfs[1])
}

func (r *Relayer) setStatus(hash string, s txStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.statuses[hash]; !ok {
		r.order = append(r.order, hash)
		if len(r.order) > maxStatuses {
			delete(r.statuses, r.order[0])
			r.order = r.order[1:]
		}
	}
	r.statuses[hash] = s
}

func (r *Relayer) screenDestination(ctx context.Context, e vault.ExtData) *failure {
	if e.ExtAmount.Sign() == 0 {
		return nil
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	allow, reason, err := r.screen.Screen(sctx, e.Recipient)
	if err != nil {
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	if !allow {
		f := fail(http.StatusForbidden, CodeRefused)
		f.reason = &reason
		return f
	}
	return nil
}

// Accepted is the answer to an accepted submission: the hash, or for a delayed request nothing,
// because the transaction is built only when it is sent; GET /v1/held/{nullifier} follows it by
// its first input nullifier.
type Accepted struct {
	Hash string `json:"hash,omitempty"`
	Held bool   `json:"held,omitempty"`
}

// Submit runs the submission steps in order and stops at the first failure.
func (r *Relayer) Submit(ctx context.Context, req Request) (Accepted, *failure) {
	if f := r.check(req); f != nil {
		return Accepted{}, f
	}
	if !r.claim(req.Proof.Nullifiers) {
		return Accepted{}, fail(http.StatusConflict, CodeDuplicate)
	}
	if f := r.screenDestination(ctx, req.Ext); f != nil {
		r.unclaim(req.Proof.Nullifiers)
		return Accepted{}, f
	}
	if req.NotBefore != nil && *req.NotBefore > r.now().Unix() {
		return r.hold(req)
	}
	hash, f := r.send(ctx, req)
	if f != nil {
		r.unclaim(req.Proof.Nullifiers)
		return Accepted{}, f
	}
	return Accepted{Hash: hash}, nil
}

// heldRequest is a held request's progress: held until sent, then the hash of its transaction,
// or the code it failed with before it was sent.
type heldRequest struct {
	hash string
	code string
}

func (r *Relayer) setHeld(nf fr.Element, h heldRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.heldBy[nf]; !ok {
		r.heldOrder = append(r.heldOrder, nf)
		if len(r.heldOrder) > maxStatuses {
			delete(r.heldBy, r.heldOrder[0])
			r.heldOrder = r.heldOrder[1:]
		}
	}
	r.heldBy[nf] = h
}

// HeldStatus reports a held request by its first input nullifier: held, or once sent, the status
// of its transaction with the hash.
func (r *Relayer) HeldStatus(ctx context.Context, nf fr.Element) (txStatus, string, bool) {
	r.mu.Lock()
	h, ok := r.heldBy[nf]
	r.mu.Unlock()
	switch {
	case !ok:
		return txStatus{}, "", false
	case h.code != "":
		return txStatus{Status: "failed", Code: h.code}, "", true
	case h.hash == "":
		return txStatus{Status: "held"}, "", true
	}
	s, found := r.Status(ctx, h.hash)
	if !found {
		s = txStatus{Status: "pending"}
	}
	return s, h.hash, true
}

func (r *Relayer) hold(req Request) (Accepted, *failure) {
	r.mu.Lock()
	if r.held >= r.cfg.MaxHeld {
		r.mu.Unlock()
		r.unclaim(req.Proof.Nullifiers)
		return Accepted{}, fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	r.held++
	r.mu.Unlock()
	nf := req.Proof.Nullifiers[0]
	r.setHeld(nf, heldRequest{})
	// A random moment in the window keeps the inclusion time from following the request time.
	at := time.Unix(*req.NotBefore, 0)
	if r.cfg.Jitter > 0 {
		at = at.Add(rand.N(r.cfg.Jitter))
	}
	time.AfterFunc(at.Sub(r.now()), func() {
		defer func() {
			r.mu.Lock()
			r.held--
			r.mu.Unlock()
		}()
		if r.ctx.Err() != nil {
			r.unclaim(req.Proof.Nullifiers)
			return
		}
		if f := r.screenDestination(r.ctx, req.Ext); f != nil {
			r.unclaim(req.Proof.Nullifiers)
			r.setHeld(nf, heldRequest{code: f.code})
			r.log.Info("held request dropped at screening", "code", f.code)
			return
		}
		hash, f := r.send(r.ctx, req)
		if f != nil {
			r.unclaim(req.Proof.Nullifiers)
			r.setHeld(nf, heldRequest{code: f.code})
			r.log.Info("held request not sent", "code", f.code)
			return
		}
		r.setHeld(nf, heldRequest{hash: hash})
	})
	return Accepted{Held: true}, nil
}

func (r *Relayer) transact(req Request, channel string) (txnbuild.Operation, error) {
	addr, err := vault.ScAddress(r.cfg.Vault)
	if err != nil {
		return nil, err
	}
	ext, err := req.Ext.ScVal()
	if err != nil {
		return nil, err
	}
	submitter, err := vault.Address(channel)
	if err != nil {
		return nil, err
	}
	return &txnbuild.InvokeHostFunction{HostFunction: xdr.HostFunction{
		Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
		InvokeContract: &xdr.InvokeContractArgs{
			ContractAddress: addr, FunctionName: "transact",
			Args: []xdr.ScVal{req.Proof.ScVal(), ext, submitter},
		},
	}}, nil
}

// send simulates on a free channel, signs and submits, and tracks the transaction in the
// background. It returns once the network holds the transaction. It runs on the relayer's own
// context, so a client that disconnects cannot leave a sent transaction untracked.
func (r *Relayer) send(_ context.Context, req Request) (string, *failure) {
	ctx, cancel := context.WithTimeout(r.ctx, 2*time.Minute)
	defer cancel()
	ch, ok := r.channels.acquire(ctx, 10*time.Second)
	if !ok {
		return "", fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	release := true
	defer func() {
		if release {
			r.channels.release(ch)
		}
	}()
	if !r.simulateLimit.Allow() {
		return "", fail(http.StatusTooManyRequests, CodeRateLimited)
	}
	op, err := r.transact(req, ch.ID)
	if err != nil {
		return "", fail(http.StatusBadRequest, CodeBadRequest)
	}
	prepared, err := r.engine.Prepare(ctx, ch, op)
	if err != nil {
		if errors.Is(err, submit.ErrSimulation) {
			return "", fail(http.StatusUnprocessableEntity, CodeRejected)
		}
		return "", fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	signed, err := r.engine.Send(ctx, prepared)
	if err != nil {
		if errors.Is(err, submit.ErrRejected) {
			return "", fail(http.StatusUnprocessableEntity, CodeRejected)
		}
		return "", fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	release = false
	r.setStatus(signed.Hash, txStatus{Status: "pending"})
	r.log.Info("submitted", "tx", signed.Hash, "fee", req.Ext.Fee.String())
	go r.track(signed, ch, req)
	return signed.Hash, nil
}

func (r *Relayer) track(s *submit.Signed, ch *submit.Account, req Request) {
	res, err := r.engine.Track(r.ctx, s)
	r.channels.release(ch)
	r.unclaim(req.Proof.Nullifiers)
	if err != nil {
		r.log.Warn("tracking stopped", "tx", s.Hash, "error", err.Error())
		return
	}
	switch res.Outcome {
	case submit.Success:
		exitID := r.queuedExit(res.Events)
		r.setStatus(s.Hash, txStatus{Status: "success", ExitID: exitID})
		r.costs.Add(res.ResourceFeeCharged)
		rec := Record{Hash: s.Hash, Ledger: res.Ledger, Fee: req.Ext.Fee.String(), NetworkFee: res.FeeCharged, ResourceFee: res.ResourceFeeCharged, Kind: "transfer", ExitID: exitID}
		if req.Ext.ExtAmount.Sign() < 0 {
			rec.Kind, rec.Destination, rec.Screening = "unshield", req.Ext.Recipient, "allow"
		}
		if err := r.db.record(r.ctx, rec); err != nil {
			r.alerts.Raise(r.ctx, alert.Critical, "relay_record_failed", "relay record of %s not stored: %v", s.Hash, err)
		}
		r.log.Info("confirmed", "tx", s.Hash, "ledger", res.Ledger, "fee", rec.Fee, "network_fee", res.FeeCharged)
	case submit.Failed:
		r.setStatus(s.Hash, txStatus{Status: "failed", Code: CodeRejected})
		r.log.Warn("failed on chain", "tx", s.Hash, "result", res.Code, "network_fee", res.FeeCharged)
		r.alerts.Raise(r.ctx, alert.Warning, "relay_failed", "relayed transaction %s failed on chain: %s", s.Hash, res.Code)
	case submit.Expired:
		r.setStatus(s.Hash, txStatus{Status: "failed", Code: CodeUnavailable})
		r.log.Warn("expired unconfirmed", "tx", s.Hash)
	}
}

// queuedExit returns the exit ID of a transact whose payment joined the exit queue: its fee, like
// its payout, reaches the fee address only when release pays the exit.
func (r *Relayer) queuedExit(events []xdr.ContractEvent) *uint64 {
	for _, e := range events {
		raw, err := vault.RawFromXDR(e)
		if err != nil || raw.Contract != r.cfg.Vault {
			continue
		}
		if ev, err := vault.Decode(raw); err == nil {
			if q, ok := ev.Body.(vault.ExitQueued); ok {
				id := q.ID
				return &id
			}
		}
	}
	return nil
}

// Status reports a transaction this relayer submitted.
func (r *Relayer) Status(ctx context.Context, hash string) (txStatus, bool) {
	r.mu.Lock()
	s, ok := r.statuses[hash]
	r.mu.Unlock()
	if ok {
		return s, true
	}
	if found, exitID, err := r.db.has(ctx, hash); err == nil && found {
		return txStatus{Status: "success", ExitID: exitID}, true
	}
	return txStatus{}, false
}

// channelPool hands each channel account to one transaction at a time.
type channelPool struct {
	free  chan *submit.Account
	total int
}

func newChannelPool(accounts []*submit.Account) *channelPool {
	p := &channelPool{free: make(chan *submit.Account, len(accounts)), total: len(accounts)}
	for _, a := range accounts {
		p.free <- a
	}
	return p
}

func (p *channelPool) acquire(ctx context.Context, wait time.Duration) (*submit.Account, bool) {
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case a := <-p.free:
		a.Lock()
		return a, true
	case <-t.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

func (p *channelPool) release(a *submit.Account) {
	a.Unlock()
	p.free <- a
}

func (p *channelPool) ready() int {
	return len(p.free)
}

// ScreeningClient asks the screening service's internal endpoint.
type ScreeningClient struct {
	URL   string
	Token string
	HTTP  *http.Client
}

// Screen implements Screener.
func (c ScreeningClient) Screen(ctx context.Context, address string) (bool, uint32, error) {
	body, _ := json.Marshal(map[string]string{"address": address})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("screening answered %d", resp.StatusCode)
	}
	var out struct {
		Result string `json:"result"`
		Reason uint32 `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, 0, err
	}
	switch out.Result {
	case "allow":
		return true, 0, nil
	case "refuse":
		return false, out.Reason, nil
	}
	return false, 0, fmt.Errorf("screening answered %q", out.Result)
}
