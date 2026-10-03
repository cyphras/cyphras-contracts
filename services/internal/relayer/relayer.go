package relayer

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"math/rand/v2"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/groth16"
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
	// LedgerSeconds is the ledger close time assumed until the ledgers seen give one.
	LedgerSeconds int64
	// MaxHeld bounds the delayed requests kept in memory.
	MaxHeld int
	// Jitter is the window after not_before in which a delayed request is sent.
	Jitter time.Duration
	// Key is the verifying key of the vault's verifier, so a forged or garbled proof is refused
	// before it costs anything.
	Key *groth16.Key
	// DeadlineMargin is how many ledgers past the latest one a proof's deadline must be when the
	// request is accepted, and again when a held one is sent; 20 when unset.
	DeadlineMargin uint32
	// Cooldown is how long the nullifiers and destination of a relay that failed on chain are
	// refused; 24 hours when unset.
	Cooldown time.Duration
	// BreakerFailures failures on chain within BreakerWindow pause relaying for BreakerPause;
	// 3, an hour and 30 minutes when unset.
	BreakerFailures int
	BreakerWindow   time.Duration
	BreakerPause    time.Duration
}

func (c *Config) defaults() {
	if c.DeadlineMargin == 0 {
		c.DeadlineMargin = 20
	}
	if c.Cooldown == 0 {
		c.Cooldown = 24 * time.Hour
	}
	if c.BreakerFailures == 0 {
		c.BreakerFailures = 3
	}
	if c.BreakerWindow == 0 {
		c.BreakerWindow = time.Hour
	}
	if c.BreakerPause == 0 {
		c.BreakerPause = 30 * time.Minute
	}
	if c.LedgerSeconds == 0 {
		c.LedgerSeconds = 5
	}
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

	// costly is the budget of the steps that cost the network: fresh reads, screening and
	// simulation. It is spent only by requests that passed every local check, so a client sending
	// garbage cannot use it up, and it is well above what nginx lets one client send.
	costly        *httpapi.Limiter
	simulateLimit *httpapi.Limiter
	// lookups is the budget of status lookups that reach the database.
	lookups *httpapi.Limiter

	cool    cooldowns
	brk     *breaker
	results outcomes
	clock   *ledgerClock
	// following counts the transactions being followed to their outcome.
	following sync.WaitGroup

	mu       sync.Mutex
	inflight map[fr.Element]bool
	statuses map[string]txStatus
	order    []string
	held     int
	// heldBy follows each held request by the random ID its reply carried, since a held request
	// has no transaction hash until it is sent.
	heldBy    map[string]*heldRequest
	heldOrder []string

	chainMu     sync.RWMutex
	inst        *vault.Instance
	roots       map[fr.Element]bool
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
	cfg.defaults()
	samples, err := db.recentResourceFees(ctx, Samples)
	if err != nil {
		return nil, err
	}
	past, err := db.recentOutcomes(ctx, outcomeSamples)
	if err != nil {
		return nil, err
	}
	cooling, err := db.cooldowns(ctx)
	if err != nil {
		return nil, err
	}
	r := &Relayer{
		cfg: cfg, rpc: client, engine: engine, channels: newChannelPool(channels), costs: NewCosts(bootstrapCost, samples),
		screen: screen, db: db, alerts: alerts, log: log, now: time.Now, ctx: ctx,
		costly: httpapi.NewLimiter(600, 100), simulateLimit: httpapi.NewLimiter(300, 50), lookups: httpapi.NewLimiter(3000, 300),
		brk:      &breaker{failures: cfg.BreakerFailures, window: cfg.BreakerWindow, pause: cfg.BreakerPause},
		clock:    &ledgerClock{fallback: float64(cfg.LedgerSeconds)},
		inflight: map[fr.Element]bool{}, statuses: map[string]txStatus{}, heldBy: map[string]*heldRequest{},
	}
	for _, ok := range past {
		r.results.add(ok)
	}
	for k, until := range cooling {
		r.cool.add([]string{k}, until)
	}
	return r, nil
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
	r.clock.observe(h.LatestLedger, h.LatestLedgerCloseTime)
	if err := r.db.forgetCooldowns(ctx, r.now().Unix()); err != nil {
		return err
	}
	if err := r.readRoots(ctx); err != nil {
		return err
	}
	_, err = r.Quote(ctx)
	return err
}

// readRoots reads the vault's root history.
func (r *Relayer) readRoots(ctx context.Context) error {
	key, err := vault.RootsKey(r.cfg.Vault)
	if err != nil {
		return err
	}
	e, _, err := rpc.One(ctx, r.rpc, key)
	if err != nil {
		return err
	}
	v, err := rpc.ContractValue(e)
	if err != nil {
		return err
	}
	ring, err := vault.DecodeRootRing(v)
	if err != nil {
		return err
	}
	roots := make(map[fr.Element]bool, len(ring.Roots))
	for _, root := range ring.Roots {
		if !root.IsZero() {
			roots[root] = true
		}
	}
	r.chainMu.Lock()
	r.roots = roots
	r.chainMu.Unlock()
	return nil
}

// knownRoot reports whether the vault still accepts a root, reading the root history again when
// the root is newer than the last refresh.
func (r *Relayer) knownRoot(ctx context.Context, root fr.Element) bool {
	r.chainMu.RLock()
	known := r.roots[root]
	r.chainMu.RUnlock()
	if known || r.readRoots(ctx) != nil {
		return known
	}
	r.chainMu.RLock()
	defer r.chainMu.RUnlock()
	return r.roots[root]
}

// spent reports whether either nullifier is already spent.
func (r *Relayer) spent(ctx context.Context, nfs [2]fr.Element) (bool, error) {
	keys := make([]xdr.LedgerKey, 2)
	for i, nf := range nfs {
		k, err := vault.NullifierKey(r.cfg.Vault, nf.Bytes())
		if err != nil {
			return false, err
		}
		keys[i] = k
	}
	entries, _, err := rpc.Entries(ctx, r.rpc, keys)
	if err != nil {
		return false, err
	}
	return len(entries) > 0, nil
}

// local checks the proof off chain against the vault's key and domain, and that its root is one
// the vault knows. It reads nothing about the request's notes or destination, so a held request
// passes it without the network learning of them.
func (r *Relayer) local(ctx context.Context, req Request) *failure {
	inst, _, _ := r.view()
	if inst == nil {
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	p := req.Proof
	inputs := [groth16.PublicInputs]fr.Element{
		p.Root, p.PublicAmount, p.ExtDataHash, inst.Config.Domain, p.Nullifiers[0], p.Nullifiers[1], p.Commitments[0], p.Commitments[1],
	}
	if !r.cfg.Key.Verify(p.A, p.B, p.C, inputs) || !r.knownRoot(ctx, p.Root) {
		return fail(http.StatusUnprocessableEntity, CodeRejected)
	}
	return nil
}

// fresh checks the request against the chain as it is now: the deadline against a fresh latest
// ledger, so the transaction cannot be included after it, its notes unspent, and its destination
// able to receive, which the vault would otherwise refuse after simulation.
func (r *Relayer) fresh(ctx context.Context, req Request) *failure {
	h, err := r.rpc.GetHealth(ctx)
	if err != nil {
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	r.clock.observe(h.LatestLedger, h.LatestLedgerCloseTime)
	if uint64(req.Ext.Deadline) < uint64(h.LatestLedger)+uint64(r.cfg.DeadlineMargin) {
		return fail(http.StatusUnprocessableEntity, CodeRejected)
	}
	spent, err := r.spent(ctx, req.Proof.Nullifiers)
	if err != nil {
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	if spent {
		return fail(http.StatusUnprocessableEntity, CodeRejected)
	}
	if req.Ext.ExtAmount.Sign() < 0 {
		ok, err := r.CanReceive(ctx, req.Ext.Recipient, new(big.Int).Neg(req.Ext.ExtAmount))
		if err != nil {
			return fail(http.StatusServiceUnavailable, CodeUnavailable)
		}
		if !ok {
			return fail(http.StatusUnprocessableEntity, CodeRejected)
		}
	}
	return nil
}

// guard refuses while relaying is paused, and refuses the notes and destination of a relay that
// failed on chain lately.
func (r *Relayer) guard(req Request) *failure {
	now := r.now()
	if r.brk.open(now) {
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	keys := []string{nullifierKey(req.Proof.Nullifiers[0].Hex()), nullifierKey(req.Proof.Nullifiers[1].Hex())}
	if req.Ext.ExtAmount.Sign() < 0 {
		if account, err := vault.AccountOf(req.Ext.Recipient); err == nil {
			keys = append(keys, destinationKey(account))
		}
	}
	if r.cool.cooling(now.Unix(), keys...) {
		return fail(http.StatusUnprocessableEntity, CodeRejected)
	}
	return nil
}

// CanReceive mirrors the vault's check of an account that is to be paid: it must exist and, for an
// issued asset it does not issue, hold a trustline the issuer has authorized. An account that does
// not exist yet can still be paid the native asset when the payout is enough to create it. A
// contract address is left to the simulation, which runs the vault's own check.
func (r *Relayer) CanReceive(ctx context.Context, address string, payout *big.Int) (bool, error) {
	account, err := vault.AccountOf(address)
	if err != nil || account[0] != 'G' {
		return err == nil, err
	}
	keys, err := vault.ReceiveKeys(r.cfg.Asset, account)
	if err != nil {
		return false, err
	}
	entries, _, err := rpc.Entries(ctx, r.rpc, keys)
	if err != nil {
		return false, err
	}
	if _, ok := entries[mustKeyString(keys[0])]; !ok {
		return r.cfg.Asset == "native" && payout.Cmp(big.NewInt(vault.MinNewAccountPayout)) >= 0, nil
	}
	if len(keys) == 1 {
		return true, nil
	}
	tl, ok := entries[mustKeyString(keys[1])]
	if !ok || tl.Data.TrustLine == nil {
		return false, nil
	}
	return xdr.TrustLineFlags(tl.Data.TrustLine.Flags)&xdr.TrustLineFlagsAuthorizedFlag != 0, nil
}

// mustKeyString encodes a key the relayer built itself, which always encodes.
func mustKeyString(k xdr.LedgerKey) string {
	s, err := rpc.KeyString(k)
	if err != nil {
		panic(err)
	}
	return s
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

// Margin is the published margin: the configured one plus the share of relays that failed on
// chain lately, whose fees bring nothing in, within MaxMarginBps.
func (r *Relayer) Margin() int64 {
	return min(r.cfg.Pricing.MarginBps+r.results.failureBps(), MaxMarginBps)
}

// Quote prices one relayed transaction now and remembers the price for QuoteLifetime.
func (r *Relayer) Quote(ctx context.Context) (*big.Int, error) {
	inclusion, err := r.engine.InclusionFee(ctx)
	if err != nil {
		return nil, ErrNoQuote
	}
	fee := r.cfg.Pricing.QuoteAt(r.costs.ResourceFee()+inclusion, r.Margin())
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

// failure is an API error.
type failure struct {
	status int
	code   string
	reason *uint32
}

func (f *failure) Error() string { return f.code }

func fail(status int, code string) *failure { return &failure{status: status, code: code} }

// belowNewAccount reports a payout of the native asset to an account below what creates one.
// Such a payout fails on chain when its destination merges away in the same ledger, at the
// relayer's cost; from there up the vault creates the account again instead.
func (r *Relayer) belowNewAccount(e vault.ExtData) bool {
	return r.cfg.Asset == "native" && e.ExtAmount.Sign() < 0 && (e.Recipient[0] == 'G' || e.Recipient[0] == 'M') &&
		new(big.Int).Neg(e.ExtAmount).Cmp(big.NewInt(vault.MinNewAccountPayout)) < 0
}

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
	if r.belowNewAccount(e) {
		return fail(http.StatusUnprocessableEntity, CodeRejected)
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
	// The latest ledger here is up to a refresh old; the deadline is checked again against a fresh
	// one before anything is sent. A held request must still be valid at the end of its window,
	// whose ledger the pace of recent ledgers predicts.
	now := r.now().Unix()
	minDeadline := uint64(latest) + uint64(r.cfg.DeadlineMargin)
	if req.NotBefore != nil {
		if *req.NotBefore > now+24*3600 {
			return fail(http.StatusBadRequest, CodeBadRequest)
		}
		if *req.NotBefore > now {
			minDeadline = uint64(r.clock.ledgerAt(*req.NotBefore+int64(r.cfg.Jitter.Seconds()))) + uint64(r.cfg.DeadlineMargin)
		}
	}
	if uint64(e.Deadline) < minDeadline {
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

// Accepted is the answer to an accepted submission: the hash, or for a delayed request, which has
// none until it is sent, a random ID that GET /v1/held/{id} follows it by.
type Accepted struct {
	Hash string `json:"hash,omitempty"`
	Held bool   `json:"held,omitempty"`
	ID   string `json:"id,omitempty"`
}

// Submit runs the submission steps in order and stops at the first failure: the local checks of
// form, vault, fee and proof, the cooldowns, the in-flight dedupe, and then, for a request that is
// not held, the steps that cost the network.
func (r *Relayer) Submit(ctx context.Context, req Request) (Accepted, *failure) {
	if f := r.check(req); f != nil {
		return Accepted{}, f
	}
	if f := r.local(ctx, req); f != nil {
		return Accepted{}, f
	}
	if f := r.guard(req); f != nil {
		return Accepted{}, f
	}
	if !r.claim(req.Proof.Nullifiers) {
		return Accepted{}, fail(http.StatusConflict, CodeDuplicate)
	}
	// A held request touches nothing on the network until it is due: reading its notes or its
	// destination, or screening it, now would tie them to the moment of the request, which the
	// delay is meant to hide.
	if req.NotBefore != nil && *req.NotBefore > r.now().Unix() {
		return r.hold(req)
	}
	hash, f := r.relay(ctx, req)
	if f != nil {
		r.unclaim(req.Proof.Nullifiers)
		return Accepted{}, f
	}
	return Accepted{Hash: hash}, nil
}

// relay runs the steps that cost the network, on a global budget: the checks against the chain as
// it is now, screening, simulation and submission.
func (r *Relayer) relay(ctx context.Context, req Request) (string, *failure) {
	if !r.costly.Allow() {
		return "", fail(http.StatusTooManyRequests, CodeRateLimited)
	}
	if f := r.fresh(ctx, req); f != nil {
		return "", f
	}
	if f := r.screenDestination(ctx, req.Ext); f != nil {
		return "", f
	}
	return r.send(ctx, req)
}

// heldRequest is a held request's progress: held until sent, then the hash of its transaction,
// or the code it failed with before it was sent, with the reason of a screening refusal.
type heldRequest struct {
	hash      string
	code      string
	reason    *uint32
	cancelled bool
	sending   bool
	timer     *time.Timer
	nfs       [2]fr.Element
}

// track keeps a held request's record, the oldest dropped past maxStatuses. The caller holds
// r.mu.
func (r *Relayer) track(id string, h *heldRequest) {
	if _, ok := r.heldBy[id]; !ok {
		r.heldOrder = append(r.heldOrder, id)
		if len(r.heldOrder) > maxStatuses {
			delete(r.heldBy, r.heldOrder[0])
			r.heldOrder = r.heldOrder[1:]
		}
	}
	r.heldBy[id] = h
}

func (r *Relayer) settleHeld(id, hash, code string, reason *uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h := r.heldBy[id]; h != nil {
		h.hash, h.code, h.reason, h.timer = hash, code, reason, nil
	}
}

// HeldStatus reports a held request by its ID: held, cancelled, or once sent, the status of its
// transaction with the hash.
func (r *Relayer) HeldStatus(ctx context.Context, id string) (txStatus, string, *uint32, bool) {
	r.mu.Lock()
	h, ok := r.heldBy[id]
	var hash, code string
	var reason *uint32
	cancelled := false
	if ok {
		hash, code, reason, cancelled = h.hash, h.code, h.reason, h.cancelled
	}
	r.mu.Unlock()
	switch {
	case !ok:
		return txStatus{}, "", nil, false
	case cancelled:
		return txStatus{Status: "cancelled"}, "", nil, true
	case code != "":
		return txStatus{Status: "failed", Code: code}, "", reason, true
	case hash == "":
		return txStatus{Status: "held"}, "", nil, true
	}
	s, found := r.Status(ctx, hash)
	if !found {
		s = txStatus{Status: "pending"}
	}
	return s, hash, nil, true
}

// CancelHeld drops a held request that is not being sent yet and frees its notes; only the client
// that made it knows its ID.
func (r *Relayer) CancelHeld(id string) bool {
	r.mu.Lock()
	h := r.heldBy[id]
	if h == nil || h.timer == nil || h.sending || h.cancelled || !h.timer.Stop() {
		r.mu.Unlock()
		return false
	}
	h.cancelled, h.timer = true, nil
	r.held--
	nfs := h.nfs
	r.mu.Unlock()
	r.unclaim(nfs)
	return true
}

func (r *Relayer) hold(req Request) (Accepted, *failure) {
	var raw [16]byte
	_, _ = crand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	// A random moment in the window keeps the inclusion time from following the request time.
	at := time.Unix(*req.NotBefore, 0)
	if r.cfg.Jitter > 0 {
		at = at.Add(rand.N(r.cfg.Jitter))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.held >= r.cfg.MaxHeld {
		delete(r.inflight, req.Proof.Nullifiers[0])
		delete(r.inflight, req.Proof.Nullifiers[1])
		return Accepted{}, fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	r.held++
	h := &heldRequest{nfs: req.Proof.Nullifiers}
	r.track(id, h)
	// The timer's function takes r.mu first, so it cannot run before the request is recorded.
	h.timer = time.AfterFunc(at.Sub(r.now()), func() { r.sendHeld(id, req) })
	return Accepted{Held: true, ID: id}, nil
}

// sendHeld sends a held request when it is due. Everything that depends on the moment runs now,
// not when it was accepted: the price, the cooldowns, the deadline against a fresh latest ledger,
// the spent and receive checks and the screening.
func (r *Relayer) sendHeld(id string, req Request) {
	r.mu.Lock()
	h := r.heldBy[id]
	switch {
	case h == nil:
		// Its record was dropped for newer ones; the request itself is still owed its release.
		r.held--
		r.mu.Unlock()
		r.unclaim(req.Proof.Nullifiers)
		return
	case h.cancelled:
		r.mu.Unlock()
		return
	}
	h.sending = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.held--
		r.mu.Unlock()
	}()
	fail := func(f *failure) {
		r.unclaim(req.Proof.Nullifiers)
		r.settleHeld(id, "", f.code, f.reason)
		r.log.Info("held request not sent", "code", f.code)
	}
	if r.ctx.Err() != nil {
		fail(&failure{code: CodeUnavailable})
		return
	}
	// The fee was accepted against the quotes of the moment of the request; when it is sent it
	// must still cover what relaying costs then.
	low := r.quotes.lowest(r.now())
	if low == nil {
		fail(&failure{code: CodeUnavailable})
		return
	}
	if req.Ext.Fee.Cmp(low) < 0 {
		fail(&failure{code: CodeFeeTooLow})
		return
	}
	if f := r.guard(req); f != nil {
		fail(f)
		return
	}
	hash, f := r.relay(r.ctx, req)
	if f != nil {
		fail(f)
		return
	}
	r.settleHeld(id, hash, "", nil)
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

// sendWait bounds how long one send may take, from waiting for a channel to the network holding
// the transaction.
const sendWait = 2 * time.Minute

// send simulates on a free channel, signs and submits, and follows the transaction in the
// background. It returns once the network holds the transaction, which may include it only up to
// the proof's deadline. It runs on the relayer's own context, so a client that disconnects cannot
// leave a sent transaction unfollowed.
func (r *Relayer) send(_ context.Context, req Request) (string, *failure) {
	ctx, cancel := context.WithTimeout(r.ctx, sendWait)
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
	// The bound stops at the deadline itself: a ledger bound excludes its own ledger, so the
	// transaction can never land where the vault would answer Expired.
	prepared, err := r.engine.PrepareUntil(ctx, ch, op, req.Ext.Deadline)
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
	rec := Record{Hash: signed.Hash, Kind: "transfer", Fee: req.Ext.Fee.String(), Channel: ch.ID,
		Nullifiers: [2]string{req.Proof.Nullifiers[0].Hex(), req.Proof.Nullifiers[1].Hex()}}
	if req.Ext.ExtAmount.Sign() < 0 {
		rec.Kind, rec.Destination, rec.Screening = "unshield", req.Ext.Recipient, "allow"
	}
	if err := r.db.sent(ctx, rec); err != nil {
		r.alerts.Raise(r.ctx, alert.Critical, "relay_record_failed", "relay record of %s not stored: %v", signed.Hash, err)
	}
	r.following.Add(1)
	go r.follow(signed, ch, req.Proof.Nullifiers, rec)
	return signed.Hash, nil
}

func (r *Relayer) follow(s *submit.Signed, ch *submit.Account, nfs [2]fr.Element, rec Record) {
	defer r.following.Done()
	res, err := r.engine.Track(r.ctx, s)
	r.channels.release(ch)
	r.unclaim(nfs)
	if err != nil {
		r.log.Warn("tracking stopped", "tx", s.Hash, "error", err.Error())
		return
	}
	r.finish(res, rec)
}

// finish records a relayed transaction's outcome. Only here is a relay logged, so no log line
// carries the time of the request that caused it. A failure on chain cools down the notes and the
// destination it was sent with, and counts towards pausing relaying altogether.
func (r *Relayer) finish(res submit.Result, sent Record) {
	rec := Record{Hash: res.Hash, Ledger: res.Ledger, NetworkFee: res.FeeCharged, ResourceFee: res.ResourceFeeCharged}
	switch res.Outcome {
	case submit.Success:
		rec.Outcome, rec.ExitID = outcomeSuccess, r.queuedExit(res.Events)
		r.setStatus(res.Hash, txStatus{Status: "success", ExitID: rec.ExitID})
		r.costs.Add(res.ResourceFeeCharged)
		r.results.add(true)
		r.log.Info("confirmed", "tx", res.Hash, "ledger", res.Ledger, "network_fee", res.FeeCharged)
	case submit.Failed:
		rec.Outcome = outcomeFailed
		r.setStatus(res.Hash, txStatus{Status: "failed", Code: CodeRejected})
		r.results.add(false)
		r.log.Warn("failed on chain", "tx", res.Hash, "result", res.Code, "network_fee", res.FeeCharged)
		r.alerts.Raise(r.ctx, alert.Warning, "relay_failed", "relayed transaction %s failed on chain: %s", res.Hash, res.Code)
		r.coolDown(sent)
		if r.brk.failed(r.now()) {
			r.alerts.Raise(r.ctx, alert.Critical, "relaying_paused", "%d relayed transactions failed on chain within %s; relaying pauses for %s",
				r.cfg.BreakerFailures, r.cfg.BreakerWindow, r.cfg.BreakerPause)
		}
	case submit.Expired:
		rec.Outcome = outcomeExpired
		r.setStatus(res.Hash, txStatus{Status: "failed", Code: CodeUnavailable})
		r.log.Warn("expired unconfirmed", "tx", res.Hash)
	}
	if err := r.db.finish(r.ctx, rec); err != nil {
		r.alerts.Raise(r.ctx, alert.Critical, "relay_record_failed", "relay record of %s not completed: %v", res.Hash, err)
	}
}

// coolDown refuses the nullifiers and the destination of a relay that failed on chain, in memory
// and in the database, so a restart does not forget them.
func (r *Relayer) coolDown(rec Record) {
	var keys []string
	for _, nf := range rec.Nullifiers {
		if nf != "" {
			keys = append(keys, nullifierKey(nf))
		}
	}
	if rec.Destination != "" {
		if account, err := vault.AccountOf(rec.Destination); err == nil {
			keys = append(keys, destinationKey(account))
		}
	}
	until := r.now().Add(r.cfg.Cooldown).Unix()
	r.cool.add(keys, until)
	if err := r.db.coolDown(r.ctx, keys, until); err != nil {
		r.alerts.Raise(r.ctx, alert.Warning, "cooldown_not_stored", "a cooldown was kept in memory only: %v", err)
	}
}

// Resume follows the transactions a previous run sent but did not see to an outcome. Until each
// one's outcome is known, its notes count as in flight and its channel stays taken, so neither is
// used twice.
func (r *Relayer) Resume() error {
	recs, err := r.db.pending(r.ctx)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		r.setStatus(rec.Hash, txStatus{Status: "pending"})
		var nfs []fr.Element
		for _, h := range rec.Nullifiers {
			if nf, err := fr.SetHex(h); err == nil && h != "" {
				nfs = append(nfs, nf)
			}
		}
		r.mu.Lock()
		for _, nf := range nfs {
			r.inflight[nf] = true
		}
		r.mu.Unlock()
		ch := r.channels.take(rec.Channel)
		r.following.Add(1)
		go func() {
			defer r.following.Done()
			res, err := r.engine.Lookup(r.ctx, rec.Hash)
			if ch != nil {
				r.channels.release(ch)
			}
			r.mu.Lock()
			for _, nf := range nfs {
				delete(r.inflight, nf)
			}
			r.mu.Unlock()
			if err != nil {
				r.log.Warn("tracking stopped", "tx", rec.Hash, "error", err.Error())
				return
			}
			r.finish(res, rec)
		}()
	}
	return nil
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

// Wait returns once every transaction being followed has its outcome recorded, or its following
// stopped with the relayer's context.
func (r *Relayer) Wait() {
	r.following.Wait()
}

// Status reports a transaction this relayer submitted. A hash not in memory is looked up in the
// records on a budget of its own.
func (r *Relayer) Status(ctx context.Context, hash string) (txStatus, bool) {
	r.mu.Lock()
	s, ok := r.statuses[hash]
	r.mu.Unlock()
	if ok {
		return s, true
	}
	if !r.lookups.Allow() {
		return txStatus{}, false
	}
	outcome, exitID, found, err := r.db.lookup(ctx, hash)
	if err != nil || !found {
		return txStatus{}, false
	}
	switch outcome {
	case outcomeSuccess:
		return txStatus{Status: "success", ExitID: exitID}, true
	case outcomeFailed:
		return txStatus{Status: "failed", Code: CodeRejected}, true
	case outcomeExpired:
		return txStatus{Status: "failed", Code: CodeUnavailable}, true
	}
	return txStatus{Status: "pending"}, true
}

// channelPool hands each channel account to one transaction at a time.
type channelPool struct {
	mu    sync.Mutex
	free  []*submit.Account
	freed chan struct{}
	total int
}

func newChannelPool(accounts []*submit.Account) *channelPool {
	return &channelPool{free: slices.Clone(accounts), freed: make(chan struct{}, len(accounts)), total: len(accounts)}
}

func (p *channelPool) pop(id string) *submit.Account {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, a := range p.free {
		if id == "" || a.ID == id {
			p.free = slices.Delete(p.free, i, i+1)
			return a
		}
	}
	return nil
}

func (p *channelPool) acquire(ctx context.Context, wait time.Duration) (*submit.Account, bool) {
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		if a := p.pop(""); a != nil {
			a.Lock()
			return a, true
		}
		select {
		case <-p.freed:
		case <-t.C:
			return nil, false
		case <-ctx.Done():
			return nil, false
		}
	}
}

// take removes the named channel from the pool, or returns nil when it is not free.
func (p *channelPool) take(id string) *submit.Account {
	if id == "" {
		return nil
	}
	a := p.pop(id)
	if a != nil {
		a.Lock()
	}
	return a
}

func (p *channelPool) release(a *submit.Account) {
	a.Unlock()
	p.mu.Lock()
	p.free = append(p.free, a)
	p.mu.Unlock()
	select {
	case p.freed <- struct{}{}:
	default:
	}
}

func (p *channelPool) ready() int {
	p.mu.Lock()
	defer p.mu.Unlock()
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
