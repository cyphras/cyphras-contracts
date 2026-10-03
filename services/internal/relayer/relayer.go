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

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
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
	// request is accepted, and again when a held one is sent; 20 when unset, and twice that in the
	// guarded mode.
	DeadlineMargin uint32
	// Cooldown is how long a request that failed on chain is refused, and its nullifiers with it
	// when the failure was of the request's making; 24 hours when unset. A destination that stopped
	// receiving, or that a failure without diagnostics named, rests ten minutes after its first
	// failure, doubling with each one in a row up to a day.
	Cooldown time.Duration
	// BreakerFailures failures on chain within BreakerWindow that point at the relayer itself
	// pause relaying for BreakerPause; 3, an hour and 30 minutes when unset.
	BreakerFailures int
	BreakerWindow   time.Duration
	BreakerPause    time.Duration
	// RaceFailures relays lost within RaceWindow to a race a client can start, notes spent first or
	// a destination that stopped receiving, put relaying in its guarded mode for GuardedFor; 5, an
	// hour and an hour when unset. Relaying never stops for them.
	RaceFailures int
	RaceWindow   time.Duration
	GuardedFor   time.Duration
	// FreshRoots is how many of the vault's newest roots a proof may be made against, checked when
	// a request is accepted and again before it is sent, so its root still has insertions to spare
	// when the transaction lands; 200 of the 256 the vault keeps when unset.
	FreshRoots uint32
	// ExitKeys is how many exits queued ahead of a relayed exit in the ledger it lands in still
	// leave its footprint room for it to queue; 4 when unset.
	ExitKeys uint32
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
	if c.RaceFailures == 0 {
		c.RaceFailures = 5
	}
	if c.RaceWindow == 0 {
		c.RaceWindow = time.Hour
	}
	if c.GuardedFor == 0 {
		c.GuardedFor = time.Hour
	}
	if c.LedgerSeconds == 0 {
		c.LedgerSeconds = 5
	}
	if c.FreshRoots == 0 {
		c.FreshRoots = 200
	}
	if c.ExitKeys == 0 {
		c.ExitKeys = 4
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
	races   *breaker
	results outcomes
	clock   *ledgerClock
	known   spentSet
	told    verdicts
	// nfNext is the next ledger whose new_nullifier events the spent set takes in; only Run uses it.
	nfNext uint32
	// following counts the transactions being followed to their outcome.
	following sync.WaitGroup
	// exitSlot holds a token while none of this relayer's exits that queue is in flight.
	exitSlot chan struct{}

	mu       sync.Mutex
	inflight map[fr.Element]bool
	statuses map[string]txStatus
	order    []string
	held     int
	// heldBy follows each held request by the random ID its reply carried, since a held request
	// has no transaction hash until it is sent.
	heldBy    map[string]*heldRequest
	heldOrder []string

	chainMu sync.RWMutex
	inst    *vault.Instance
	// roots holds the age of each root the vault keeps, 0 for the newest.
	roots       map[fr.Element]uint32
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
		brk:   &breaker{failures: cfg.BreakerFailures, window: cfg.BreakerWindow, pause: cfg.BreakerPause},
		races: &breaker{failures: cfg.RaceFailures, window: cfg.RaceWindow, pause: cfg.GuardedFor},
		clock: &ledgerClock{fallback: float64(cfg.LedgerSeconds)},
		known: spentSet{max: maxKnownSpent}, told: verdicts{ttl: verdictLifetime, max: maxVerdicts},
		inflight: map[fr.Element]bool{}, statuses: map[string]txStatus{}, heldBy: map[string]*heldRequest{},
		exitSlot: make(chan struct{}, 1),
	}
	r.exitSlot <- struct{}{}
	for _, ok := range past {
		r.results.add(ok)
	}
	for k, c := range cooling {
		r.cool.restore(k, c.until, c.strikes)
	}
	return r, nil
}

const (
	// maxKnownSpent bounds the spent nullifiers kept in memory.
	maxKnownSpent = 1_000_000
	// verdictLifetime is how long a refusal is answered from memory; maxVerdicts bounds them.
	verdictLifetime = 10 * time.Minute
	maxVerdicts     = 10_000
)

// guarded reports the mode relaying takes while clients keep winning races against it: deadlines
// need twice the margin, and a transaction is checked against the chain once more right before
// it is sent.
func (r *Relayer) guarded() bool {
	return r.races.open(r.now())
}

func (r *Relayer) deadlineMargin() uint64 {
	if r.guarded() {
		return 2 * uint64(r.cfg.DeadlineMargin)
	}
	return uint64(r.cfg.DeadlineMargin)
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
	if err := r.db.forgetCooldowns(ctx, r.now().Unix()-strikeMemory); err != nil {
		return err
	}
	if err := r.readRoots(ctx); err != nil {
		return err
	}
	_, err = r.Quote(ctx)
	return err
}

// nullifierWindow is the most ledgers one read of new_nullifier events covers, and
// nullifierReads the most reads one round makes.
const (
	nullifierWindow = 2_000
	nullifierReads  = 20
)

// FollowNullifiers takes into the spent set the nullifiers the vault's new_nullifier events name,
// from the oldest ledger the RPC keeps on the first round and from where it stopped after that.
func (r *Relayer) FollowNullifiers(ctx context.Context) error {
	src := follow.RPCSource{Client: r.rpc, Contract: r.cfg.Vault, Topics: newNullifierTopics(), PageLimit: 1000}
	for range nullifierReads {
		h, err := r.rpc.GetHealth(ctx)
		if err != nil {
			return err
		}
		if h.OldestLedger > h.LatestLedger {
			return fmt.Errorf("relayer: the RPC reports its oldest ledger %d past its latest %d", h.OldestLedger, h.LatestLedger)
		}
		from := max(r.nfNext, h.OldestLedger)
		if from > h.LatestLedger {
			return nil
		}
		to := min(from+nullifierWindow-1, h.LatestLedger)
		raw, err := src.Events(ctx, from, to)
		if err != nil {
			return err
		}
		for _, e := range raw {
			ev, err := vault.Decode(e)
			if err != nil {
				return err
			}
			if n, ok := ev.Body.(vault.NewNullifier); ok {
				r.known.add(n.Nullifier)
			}
		}
		r.nfNext = to + 1
	}
	return nil
}

func newNullifierTopics() []protocol.TopicFilter {
	sym := xdr.ScSymbol("new_nullifier")
	name := xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &sym}
	return []protocol.TopicFilter{{{ScVal: &name}}}
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
	roots := make(map[fr.Element]uint32, len(ring.Roots))
	for i, root := range ring.Roots {
		if !root.IsZero() {
			roots[root] = (ring.Newest + vault.RootHistory - uint32(i)) % vault.RootHistory
		}
	}
	r.chainMu.Lock()
	r.roots = roots
	r.chainMu.Unlock()
	return nil
}

// freshRoot reports whether a root is among the vault's newest FreshRoots: one older would leave a
// transaction made against it to fail when insertions push it out of the vault's history before
// it lands. The root history is read again first when reread is set, and when the root is newer
// than the last read.
func (r *Relayer) freshRoot(ctx context.Context, root fr.Element, reread bool) (bool, error) {
	r.chainMu.RLock()
	age, known := r.roots[root]
	r.chainMu.RUnlock()
	if known && !reread {
		return age < r.cfg.FreshRoots, nil
	}
	if err := r.readRoots(ctx); err != nil {
		return false, err
	}
	r.chainMu.RLock()
	defer r.chainMu.RUnlock()
	age, known = r.roots[root]
	return known && age < r.cfg.FreshRoots, nil
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
	if !r.cfg.Key.Verify(p.A, p.B, p.C, inputs) {
		return fail(http.StatusUnprocessableEntity, CodeRejected)
	}
	ok, err := r.freshRoot(ctx, p.Root, false)
	switch {
	case err != nil:
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	case !ok:
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
	if uint64(req.Ext.Deadline) < uint64(h.LatestLedger)+r.deadlineMargin() {
		return fail(http.StatusUnprocessableEntity, CodeRejected)
	}
	spent, err := r.spent(ctx, req.Proof.Nullifiers)
	if err != nil {
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	if spent {
		r.known.add(req.Proof.Nullifiers[0], req.Proof.Nullifiers[1])
		return settledFail(http.StatusUnprocessableEntity, CodeRejected)
	}
	if req.Ext.ExtAmount.Sign() < 0 {
		ok, err := r.CanReceive(ctx, req.Ext.Recipient, new(big.Int).Neg(req.Ext.ExtAmount))
		if err != nil {
			return fail(http.StatusServiceUnavailable, CodeUnavailable)
		}
		if !ok {
			return settledFail(http.StatusUnprocessableEntity, CodeRejected)
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
	keys := []string{nullifierKey(req.Proof.Nullifiers[0].Hex()), nullifierKey(req.Proof.Nullifiers[1].Hex()), requestKey(req)}
	if req.Ext.ExtAmount.Sign() < 0 {
		keys = append(keys, destinationKey(req.Ext.Recipient))
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
	// settled marks an answer the same proof would get again, which is kept for a while.
	settled bool
}

func (f *failure) Error() string { return f.code }

func fail(status int, code string) *failure { return &failure{status: status, code: code} }

// settledFail is fail for an answer that does not change when the same proof is sent again soon.
func settledFail(status int, code string) *failure {
	return &failure{status: status, code: code, settled: true}
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
	minDeadline := uint64(latest) + r.deadlineMargin()
	if req.NotBefore != nil {
		if *req.NotBefore > now+24*3600 {
			return fail(http.StatusBadRequest, CodeBadRequest)
		}
		if *req.NotBefore > now {
			minDeadline = uint64(r.clock.ledgerAt(*req.NotBefore+int64(r.cfg.Jitter.Seconds()))) + r.deadlineMargin()
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
	if errors.Is(err, ErrWithheld) {
		return settledFail(http.StatusUnprocessableEntity, CodeRejected)
	}
	if err != nil {
		return fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	if !allow {
		f := settledFail(http.StatusForbidden, CodeRefused)
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
	// A proof already used, or already refused once it had cost the network, is answered from
	// memory, so replaying public proofs cannot spend the budget honest requests need.
	if r.known.any(req.Proof.Nullifiers) {
		return Accepted{}, fail(http.StatusUnprocessableEntity, CodeRejected)
	}
	if f := r.told.recall(proofKey(req), r.now()); f != nil {
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
	hash, f := r.costlySteps(ctx, req)
	if f != nil && f.settled {
		r.told.remember(proofKey(req), *f, r.now())
	}
	return hash, f
}

func (r *Relayer) costlySteps(ctx context.Context, req Request) (string, *failure) {
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
	s, found, _ := r.Status(ctx, hash)
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

// CheckDiagnostics simulates a call the vault always refuses, a function it does not have, and
// reports whether the RPC returned diagnostic events for it. Without them the cause of a failed
// relay cannot be told: the relayer then runs on, counting every such failure as a race that rests
// its notes and destination rather than as its own, and raises a Warning.
func (r *Relayer) CheckDiagnostics(ctx context.Context) (bool, error) {
	addr, err := vault.ScAddress(r.cfg.Vault)
	if err != nil {
		return false, err
	}
	source := r.channels.any()
	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount: &txnbuild.SimpleAccount{AccountID: source, Sequence: 0}, IncrementSequenceNum: true, BaseFee: txnbuild.MinBaseFee,
		Preconditions: txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
		Operations: []txnbuild.Operation{&txnbuild.InvokeHostFunction{HostFunction: xdr.HostFunction{
			Type:           xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
			InvokeContract: &xdr.InvokeContractArgs{ContractAddress: addr, FunctionName: "no_such_function"},
		}}},
	})
	if err != nil {
		return false, err
	}
	encoded, err := tx.Base64()
	if err != nil {
		return false, err
	}
	sim, err := r.rpc.SimulateTransaction(ctx, protocol.SimulateTransactionRequest{Transaction: encoded})
	if err != nil {
		return false, err
	}
	if sim.Error != "" && len(sim.EventsXDR) > 0 {
		return true, nil
	}
	r.alerts.Raise(ctx, alert.Warning, "rpc_no_diagnostics", "the RPC returned no diagnostic events for a call that fails, so the cause of a failed relay cannot be told; every such failure counts as a race and rests its notes and destination. Use an RPC that returns diagnostic events.")
	return false, nil
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
	release, slot := true, false
	defer func() {
		if release {
			r.channels.release(ch)
			if slot {
				r.exitSlot <- struct{}{}
			}
		}
	}()
	if !r.simulateLimit.Allow() {
		return "", fail(http.StatusTooManyRequests, CodeRateLimited)
	}
	op, err := r.transact(req, ch.ID)
	if err != nil {
		return "", fail(http.StatusBadRequest, CodeBadRequest)
	}
	prepared, slot, err := r.prepare(ctx, ch, op, req)
	if err != nil {
		if errors.Is(err, submit.ErrSimulation) {
			return "", settledFail(http.StatusUnprocessableEntity, CodeRejected)
		}
		return "", fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	if r.guarded() {
		if f := r.fresh(ctx, req); f != nil {
			return "", f
		}
	}
	current, err := r.freshRoot(ctx, req.Proof.Root, true)
	if err != nil {
		return "", fail(http.StatusServiceUnavailable, CodeUnavailable)
	}
	if !current {
		return "", settledFail(http.StatusUnprocessableEntity, CodeRejected)
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
	rec := Record{Hash: signed.Hash, Kind: "transfer", Fee: req.Ext.Fee.String(), Channel: ch.ID, Request: requestKey(req),
		Nullifiers: [2]string{req.Proof.Nullifiers[0].Hex(), req.Proof.Nullifiers[1].Hex()}, SimulatedAt: prepared.SimulatedAt}
	if req.Ext.ExtAmount.Sign() < 0 {
		rec.Kind, rec.Destination, rec.Screening = "unshield", req.Ext.Recipient, "allow"
	}
	if err := r.db.sent(ctx, rec); err != nil {
		r.alerts.Raise(r.ctx, alert.Critical, "relay_record_failed", "relay record of %s not stored: %v", signed.Hash, err)
	}
	r.following.Add(1)
	go r.follow(signed, ch, slot, req.Proof.Nullifiers, rec)
	return signed.Hash, nil
}

// prepare simulates a relayed transaction, with room for the other path of the exit queue, and
// holds the exit slot for one whose simulation queued its exit: this relayer has one exit that
// queues in flight at a time, so its own exits never compete for the queue's tail in a ledger. One
// that has to wait for the slot is simulated again once it holds it, against the tail the exit
// before it left. slot reports that the caller holds the slot.
func (r *Relayer) prepare(ctx context.Context, ch *submit.Account, op txnbuild.Operation, req Request) (p *submit.Prepared, slot bool, err error) {
	for {
		queued := false
		// The bound stops at the deadline itself: a ledger bound excludes its own ledger, so the
		// transaction can never land where the vault would answer Expired.
		p, err = r.engine.PrepareUntil(ctx, ch, op, req.Ext.Deadline, r.exitRoom(req, &queued))
		switch {
		case err != nil || !queued:
			if slot {
				r.exitSlot <- struct{}{}
			}
			return p, false, err
		case slot:
			return p, true, nil
		}
		select {
		case <-r.exitSlot:
			return p, true, nil
		default:
		}
		select {
		case <-r.exitSlot:
			slot = true
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

// exitRoom gives a relayed transaction that pays anything the entries of the exit queue's other
// path, as vault.TransactRoom names them, with the resources that path may take. The queue's tail
// is the one the simulation wrote an exit at, or the vault's tail now when it paid at once.
// queued reports a simulation that queued the exit.
func (r *Relayer) exitRoom(req Request, queued *bool) submit.Extend {
	return func(ctx context.Context, fp xdr.LedgerFootprint) (submit.Extra, error) {
		if req.Ext.ExtAmount.Sign() == 0 && req.Ext.Fee.Sign() == 0 {
			return submit.Extra{}, nil
		}
		inst, _, _ := r.view()
		tail, ok := vault.QueuedExit(r.cfg.Vault, fp)
		*queued = ok
		if !ok || inst == nil {
			fresh, _, _, err := rpc.VaultInstance(ctx, r.rpc, r.cfg.Vault)
			if err != nil {
				return submit.Extra{}, err
			}
			inst = &fresh
			if !ok {
				tail = fresh.Status.ExitTail
			}
		}
		keys, err := vault.TransactRoom(r.cfg.Vault, inst.Config.Token, r.cfg.Asset, req.Ext, tail, r.cfg.ExitKeys)
		if err != nil {
			return submit.Extra{}, err
		}
		token, err := vault.ScAddress(inst.Config.Token)
		if err != nil {
			return submit.Extra{}, err
		}
		// Queueing writes an exit, and paying at once the balances the asset contract keeps.
		newBytes := uint32(vault.ExitEntryBytes)
		for _, k := range keys {
			if k.Type == xdr.LedgerEntryTypeContractData && k.ContractData.Contract.Equals(token) {
				newBytes += vault.BalanceEntryBytes
			}
		}
		return submit.Extra{ReadWrite: keys, Instructions: vault.SwitchInstructions, WriteBytes: newBytes, NewBytes: newBytes,
			RentLedgers: vault.EntryTTL, EventBytes: vault.SwitchEventBytes}, nil
	}
}

func (r *Relayer) follow(s *submit.Signed, ch *submit.Account, slot bool, nfs [2]fr.Element, rec Record) {
	defer r.following.Done()
	res, err := r.engine.Track(r.ctx, s)
	r.channels.release(ch)
	if slot {
		r.exitSlot <- struct{}{}
	}
	r.unclaim(nfs)
	if err != nil {
		r.log.Warn("tracking stopped", "tx", s.Hash, "error", err.Error())
		return
	}
	r.finish(res, rec)
}

// finish records a relayed transaction's outcome. Only here is a relay logged, so no log line
// carries the time of the request that caused it. A failure on chain is judged by its cause: one a
// client can bring about, by spending the notes first or by making the destination stop
// receiving, rests the notes and the destination and puts relaying in its guarded mode; one that
// points at the relayer itself counts toward pausing relaying altogether.
func (r *Relayer) finish(res submit.Result, sent Record) {
	rec := Record{Hash: res.Hash, Ledger: res.Ledger, NetworkFee: res.FeeCharged, ResourceFee: res.ResourceFeeCharged}
	switch res.Outcome {
	case submit.Success:
		rec.Outcome, rec.ExitID = outcomeSuccess, r.queuedExit(res.Events)
		r.setStatus(res.Hash, txStatus{Status: "success", ExitID: rec.ExitID})
		r.costs.Add(res.ResourceFeeCharged)
		r.results.add(true)
		r.known.add(sentNullifiers(sent)...)
		r.log.Info("confirmed", "tx", res.Hash, "ledger", res.Ledger, "network_fee", res.FeeCharged)
	case submit.Failed:
		rec.Outcome = outcomeFailed
		r.results.add(false)
		c := r.classify(res, sent)
		code := CodeRejected
		if c == causeConflict {
			// The request rests nowhere and may be sent again.
			code = CodeUnavailable
		}
		r.setStatus(res.Hash, txStatus{Status: "failed", Code: code})
		r.log.Warn("failed on chain", "tx", res.Hash, "result", res.Code, "cause", c.String(), "network_fee", res.FeeCharged)
		r.coolDown(sent, c)
		if c == causeUnclear {
			r.alerts.Raise(r.ctx, alert.Warning, "rpc_no_diagnostics", "the RPC returned no diagnostic events for failed transaction %s, so its cause cannot be told; it counts as a race and rests its notes and destination. Use an RPC that returns diagnostic events.", res.Hash)
		}
		switch c {
		case causeSpent, causeReceive, causeRace, causeUnclear, causeConflict:
			if c == causeSpent {
				r.known.add(sentNullifiers(sent)...)
			}
			if r.races.failed(r.now()) {
				r.alerts.Raise(r.ctx, alert.Warning, "relaying_guarded", "%d relays lost races within %s; relaying stays on with twice the deadline margin and a last check before each send for %s",
					r.cfg.RaceFailures, r.cfg.RaceWindow, r.cfg.GuardedFor)
			}
		default:
			r.alerts.Raise(r.ctx, alert.Warning, "relay_failed", "relayed transaction %s failed on chain: %s (%s)", res.Hash, res.Code, c)
			if r.brk.failed(r.now()) {
				r.alerts.Raise(r.ctx, alert.Critical, "relaying_paused", "%d relayed transactions failed on chain within %s for reasons of the relayer's own; relaying pauses for %s",
					r.cfg.BreakerFailures, r.cfg.BreakerWindow, r.cfg.BreakerPause)
			}
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

func sentNullifiers(rec Record) []fr.Element {
	var out []fr.Element
	for _, h := range rec.Nullifiers {
		if nf, err := fr.SetHex(h); err == nil && h != "" {
			out = append(out, nf)
		}
	}
	return out
}

// cause is why a relayed transaction failed on chain.
type cause int

const (
	// causeRelayer is a failure of the relayer's own making: its sequence, fee or resources.
	causeRelayer cause = iota
	// causeVault is a vault error a checked request should not meet, or one that cannot be told.
	causeVault
	// causeSpent is notes another transaction spent first.
	causeSpent
	// causeReceive is a destination that stopped receiving, or grew, after it was checked.
	causeReceive
	// causeRace is the chain moving under the call between its simulation and its ledger: the root
	// it was proved against pushed out of the vault's history, or the fee address's entries changed.
	causeRace
	// causeUnclear is a failure the RPC returned no diagnostic events for, which cannot be told.
	causeUnclear
	// causeConflict is a call that failed on the host's storage: the exit queue, or another entry
	// it touched, moved under it past the room its footprint was given. Sent again after a new
	// simulation, the same request can succeed.
	causeConflict
)

func (c cause) String() string {
	return [...]string{"relayer", "vault", "notes spent first", "destination stopped receiving", "the chain moved under the call", "no diagnostics",
		"the exit queue moved under the call"}[c]
}

// The vault's error codes a client can bring about after its request was checked. Codes below
// 100 are the asset contract's, which reach the vault's callers unchanged.
const (
	vaultUnknownRoot    = 121
	vaultNullifierSpent = 123
	vaultCannotReceive  = 144
	firstVaultCode      = 100
)

// classify tells why a relayed transaction failed. It trusts the contract error the network
// reports; reads of the chain only tell apart the parties a failed transfer may concern, and
// stand in for the error when the RPC reports none.
func (r *Relayer) classify(res submit.Result, sent Record) cause {
	if res.Code != xdr.TransactionResultCodeTxFailed.String() {
		return causeRelayer
	}
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()
	if res.InvokeCode != nil {
		switch *res.InvokeCode {
		case xdr.InvokeHostFunctionResultCodeInvokeHostFunctionTrapped:
		case xdr.InvokeHostFunctionResultCodeInvokeHostFunctionResourceLimitExceeded:
			return r.resourceCause(ctx, sent)
		default:
			return causeRelayer
		}
	}
	e := res.ContractError
	switch {
	case e == nil && res.Conflict:
		return causeConflict
	case e == nil:
		if nfs := sentNullifiers(sent); len(nfs) == 2 {
			if spent, err := r.spent(ctx, [2]fr.Element{nfs[0], nfs[1]}); err == nil && spent {
				return causeSpent
			}
		}
		if !res.Diagnosed {
			return causeUnclear
		}
		return causeVault
	case e.Contract == r.cfg.Vault && e.Code == vaultNullifierSpent:
		return causeSpent
	case e.Contract == r.cfg.Vault && e.Code == vaultUnknownRoot:
		return causeRace
	case e.Contract == r.cfg.Vault && e.Code == vaultCannotReceive:
		// The vault checks the fee address too; only the destination is the client's to change.
		if ok, err := r.CanReceive(ctx, r.cfg.FeeAddress, new(big.Int)); err == nil && !ok {
			return causeRelayer
		}
		return causeReceive
	case e.Code < firstVaultCode && sent.Destination != "":
		// A transfer the asset contract refused: the destination's doing, unless the vault itself
		// may not pay.
		if ok, err := r.vaultCanPay(ctx); err == nil && !ok {
			return causeRelayer
		}
		return causeReceive
	}
	return causeVault
}

// resourceCause tells a call that ran out of the resources its simulation measured. Anyone can
// grow their own account between the simulation and the call's ledger, so it is a race when the
// destination's entries or the fee address's changed after the simulation, and the relayer's own
// failure otherwise.
func (r *Relayer) resourceCause(ctx context.Context, sent Record) cause {
	if sent.SimulatedAt == 0 {
		return causeRelayer
	}
	if sent.Destination != "" && r.changedSince(ctx, sent.Destination, sent.SimulatedAt) {
		return causeReceive
	}
	if r.changedSince(ctx, r.cfg.FeeAddress, sent.SimulatedAt) {
		return causeRace
	}
	return causeRelayer
}

// changedSince reports whether the classic entries an address receives the vault's asset in
// changed after a ledger.
func (r *Relayer) changedSince(ctx context.Context, address string, ledger uint32) bool {
	account, err := vault.AccountOf(address)
	if err != nil || account[0] != 'G' {
		return false
	}
	keys, err := vault.ReceiveKeys(r.cfg.Asset, account)
	if err != nil {
		return false
	}
	entries, _, err := rpc.Entries(ctx, r.rpc, keys)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.LastModified > ledger {
			return true
		}
	}
	return false
}

// vaultCanPay reports whether the issuer lets the vault hold, and so send, its asset.
func (r *Relayer) vaultCanPay(ctx context.Context) (bool, error) {
	inst, _, _ := r.view()
	if inst == nil {
		return false, errors.New("relayer: no vault state")
	}
	key, err := vault.BalanceKey(inst.Config.Token, r.cfg.Vault)
	if err != nil {
		return false, err
	}
	e, _, err := rpc.One(ctx, r.rpc, key)
	if errors.Is(err, rpc.ErrMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	v, err := rpc.ContractValue(e)
	if err != nil {
		return false, err
	}
	_, authorized, err := vault.DecodeBalance(v)
	return authorized, err
}

// coolDown rests what a failed relay carried, in memory and in the database, so a restart does
// not forget it: the request itself and, unless the relayer was at fault or the chain moved under
// the call, its notes, for a day; and after a receive failure, or one that cannot be told, the
// destination, for longer each time it fails again. A conflict on the exit queue rests nothing.
func (r *Relayer) coolDown(rec Record, c cause) {
	if c == causeConflict {
		return
	}
	now := r.now()
	until := now.Add(r.cfg.Cooldown).Unix()
	var keys []string
	// The exact request is never sent again, whatever else the cause: a failure the relayer
	// itself pays for must not be repeatable at will. A conflict needs another exit or call to
	// land first in the same ledger, which costs whoever sends it.
	if rec.Request != "" {
		keys = append(keys, rec.Request)
	}
	if c != causeRelayer && c != causeRace {
		for _, nf := range rec.Nullifiers {
			if nf != "" {
				keys = append(keys, nullifierKey(nf))
			}
		}
	}
	if len(keys) > 0 {
		r.cool.add(keys, until)
		if err := r.db.coolDown(r.ctx, keys, until); err != nil {
			r.alerts.Raise(r.ctx, alert.Warning, "cooldown_not_stored", "a cooldown was kept in memory only: %v", err)
		}
	}
	if (c != causeReceive && c != causeUnclear) || rec.Destination == "" {
		return
	}
	key := destinationKey(rec.Destination)
	rest, strikes := r.cool.strike(key, now.Unix())
	if err := r.db.strike(r.ctx, key, rest, strikes); err != nil {
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

// errLookupBudget reports a status lookup refused because the lookups that reach the database are
// over budget, which is not the same as an unknown transaction.
var errLookupBudget = errors.New("relayer: status lookups over budget")

// Status reports a transaction this relayer submitted. A hash not in memory is looked up in the
// records on a budget of its own; it reports false for a hash it never submitted.
func (r *Relayer) Status(ctx context.Context, hash string) (txStatus, bool, error) {
	r.mu.Lock()
	s, ok := r.statuses[hash]
	r.mu.Unlock()
	if ok {
		return s, true, nil
	}
	if !r.lookups.Allow() {
		return txStatus{}, false, errLookupBudget
	}
	outcome, exitID, found, err := r.db.lookup(ctx, hash)
	if err != nil {
		return txStatus{}, false, err
	}
	if !found {
		return txStatus{}, false, nil
	}
	switch outcome {
	case outcomeSuccess:
		return txStatus{Status: "success", ExitID: exitID}, true, nil
	case outcomeFailed:
		return txStatus{Status: "failed", Code: CodeRejected}, true, nil
	case outcomeExpired:
		return txStatus{Status: "failed", Code: CodeUnavailable}, true, nil
	}
	return txStatus{Status: "pending"}, true, nil
}

// channelPool hands each channel account to one transaction at a time.
type channelPool struct {
	mu    sync.Mutex
	all   []*submit.Account
	free  []*submit.Account
	freed chan struct{}
	total int
}

func newChannelPool(accounts []*submit.Account) *channelPool {
	return &channelPool{free: slices.Clone(accounts), all: slices.Clone(accounts), freed: make(chan struct{}, len(accounts)), total: len(accounts)}
}

// any names one channel account, for calls that are simulated only.
func (p *channelPool) any() string {
	return p.all[0].ID
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

// ErrWithheld reports a destination the screening service does not clear without a person, which a
// relay cannot wait for. The relay is refused without a public reason; the screening record holds
// it.
var ErrWithheld = errors.New("relayer: screening withheld the destination")

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
	case "withheld":
		return false, 0, ErrWithheld
	}
	return false, 0, fmt.Errorf("screening answered %q", out.Result)
}
