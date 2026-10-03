package screening

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
)

// SelfReportMessage is the text a compromised key signs under SEP-53.
func SelfReportMessage(network, address, date string) string {
	return "Cyphras compromised address report\nNetwork: " + network + "\nAddress: " + address + "\nDate: " + date
}

// VerifySEP53 checks an ed25519 signature over SHA-256("Stellar Signed Message:\n" || message).
func VerifySEP53(address, message string, signature []byte) error {
	raw, err := strkey.Decode(strkey.VersionByteAccountID, address)
	if err != nil {
		return errors.New("not an account address")
	}
	if len(signature) != ed25519.SignatureSize {
		return errors.New("bad signature length")
	}
	digest := sha256.Sum256([]byte("Stellar Signed Message:\n" + message))
	if !ed25519.Verify(ed25519.PublicKey(raw), digest[:], signature) {
		return errors.New("bad signature")
	}
	return nil
}

// Public serves the policy, the statistics, self-reports and the pre-deposit check. Nothing here
// records anything about a request. Per-client limits live in nginx; the budgets here guard only
// what a request costs past the checks that cost nothing.
func (s *Screener) Public(reports, checks *httpapi.Limiter) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		h := s.Health()
		status := http.StatusOK
		if !h.Ready {
			status = http.StatusServiceUnavailable
		}
		httpapi.JSON(w, status, h)
	})
	mux.HandleFunc("GET /v1/policy", func(w http.ResponseWriter, r *http.Request) {
		httpapi.JSON(w, http.StatusOK, map[string]any{
			"policy_version": s.cfg.PolicyVersion, "vault": s.cfg.Vault, "network": s.cfg.Network, "sources": s.check.Statuses(),
		})
	})
	mux.HandleFunc("GET /v1/stats", func(w http.ResponseWriter, r *http.Request) {
		st, err := s.db.stats(r.Context())
		if err != nil {
			httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		httpapi.JSON(w, http.StatusOK, st)
	})
	mux.HandleFunc("POST /v1/self-report", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Address   string `json:"address"`
			Date      string `json:"date"`
			Signature string `json:"signature"`
		}
		if err := httpapi.ReadJSON(w, r, 4096, &body); err != nil {
			httpapi.Fail(w, http.StatusBadRequest, "bad_request")
			return
		}
		day, err := time.Parse(time.DateOnly, body.Date)
		now := s.now().UTC()
		if err != nil || day.After(now.Add(24*time.Hour)) || day.Before(now.Add(-30*24*time.Hour)) {
			httpapi.Fail(w, http.StatusBadRequest, "bad_request")
			return
		}
		sig, err := base64.StdEncoding.DecodeString(body.Signature)
		if err != nil {
			httpapi.Fail(w, http.StatusBadRequest, "bad_request")
			return
		}
		if VerifySEP53(body.Address, SelfReportMessage(s.cfg.Network, body.Address, body.Date), sig) != nil {
			httpapi.Fail(w, http.StatusBadRequest, "bad_signature")
			return
		}
		if !reports.Allow() {
			httpapi.Fail(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		fresh, err := s.db.addSelfReport(r.Context(), body.Address, body.Date, body.Signature, now)
		if err != nil {
			httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		if fresh {
			s.record(r.Context(), Decision{Kind: "self_report", Address: body.Address, Outcome: "block", Reason: ptr(uint32(ReasonFraud))})
			if err := s.reports.Refresh(r.Context()); err != nil {
				s.log.Warn("self-report list refresh failed", "error", err.Error())
			}
		}
		httpapi.JSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	})
	mux.HandleFunc("GET /v1/check", func(w http.ResponseWriter, r *http.Request) {
		address := r.URL.Query().Get("address")
		if !strkey.IsValidEd25519PublicKey(address) {
			httpapi.Fail(w, http.StatusBadRequest, "bad_request")
			return
		}
		if !checks.Allow() {
			httpapi.Fail(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		// The lists only: a public question must not cost Horizon lookups. Funders are checked when
		// the deposit is made.
		v, err := s.check.Check(r.Context(), address, 0, s.now())
		if err != nil {
			httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		out := map[string]any{"allow": !v.Refused, "review": v.Refer}
		if v.Refused {
			out["reason"] = v.Reason
		}
		httpapi.JSON(w, http.StatusOK, out)
	})
	return httpapi.Public(mux)
}

func ptr[T any](v T) *T { return &v }

// Internal serves the relayer's destination screen. It is reachable only on the internal network
// and needs the relayer's token; the proxy does not route it.
func (s *Screener) Internal(tokenSHA256 [32]byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/screen", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(sum[:], tokenSHA256[:]) != 1 {
			httpapi.Fail(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		var body struct {
			Address string `json:"address"`
		}
		if err := httpapi.ReadJSON(w, r, 1024, &body); err != nil {
			httpapi.Fail(w, http.StatusBadRequest, "bad_request")
			return
		}
		v, err := s.requestCheck.Check(r.Context(), body.Address, 1, s.now().Add(-FunderWindow))
		if err != nil {
			if !errors.Is(err, ErrUnavailable) {
				httpapi.Fail(w, http.StatusBadRequest, "bad_request")
				return
			}
			s.alerts.Raise(r.Context(), alert.Warning, "screen_unavailable", "a destination could not be screened: %v", err)
			httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		switch {
		case v.Refused:
			// Only refusals are kept here; the relayer's own record holds the result of every relay.
			if err := s.db.countUnshieldRefusal(r.Context(), v.Reason); err != nil {
				s.log.Error("refusal count failed", "error", err.Error())
			}
			s.record(r.Context(), Decision{Kind: "unshield", Address: body.Address, Outcome: "refuse", Reason: &v.Reason, Detail: v.Detail, Sources: v.Sources})
			httpapi.JSON(w, http.StatusOK, map[string]any{"result": "refuse", "reason": v.Reason})
		case !v.Clear():
			// A funder's match or a history read only in part needs a person, and there is none to
			// wait for here: the relay is refused without a public reason, which stays in the record.
			s.record(r.Context(), Decision{Kind: "unshield", Address: body.Address, Outcome: "withhold", Detail: v.Detail, Sources: v.Sources})
			httpapi.JSON(w, http.StatusOK, map[string]any{"result": "withheld"})
		default:
			httpapi.JSON(w, http.StatusOK, map[string]any{"result": "allow"})
		}
	})
	return mux
}
