package node

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/ratelimit"
)

// MaxRequestBytes caps a sealed request body.
const MaxRequestBytes = 64 << 10

// FeedStaleAfter is how long a pulling node may go without a successful feed
// poll before it reports itself unhealthy.
const FeedStaleAfter = 2 * time.Minute

// Handler serves the inbound API under prefix. Every failure — bad route,
// rate limit, authentication, decoding — is the same empty 404, so a scanner
// sees nothing that distinguishes this from a closed web server.
func (s *Service) Handler(prefix string, perMinute int) http.Handler {
	lim := ratelimit.New(perMinute, time.Minute)
	mux := http.NewServeMux()
	mux.HandleFunc("/", notFound)
	mux.HandleFunc(prefix+"/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			notFound(w, r)
			return
		}
		s.serve(w, r, api.OpSubmit, "")
	})
	mux.HandleFunc(prefix+"/v1/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.serve(w, r, api.OpGet, r.PathValue("id"))
		case http.MethodDelete:
			s.serve(w, r, api.OpCancel, r.PathValue("id"))
		default:
			notFound(w, r)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ServeMux would answer unclean paths with a telltale 301 redirect.
		if !lim.Allow(ratelimit.ClientIP(r)) || r.URL.Path != path.Clean(r.URL.Path) {
			notFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

// HealthHandler serves GET /healthz to loopback callers: 200 "ok", or 503 when
// the node pulls a feed and has not read it successfully for FeedStaleAfter.
// It belongs on a loopback-only listener, never on the public one.
func (s *Service) HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" || r.Method != http.MethodGet || !fromLoopback(r) {
			notFound(w, r)
			return
		}
		if !s.Healthy(time.Now()) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "feed stale")
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
}

// Healthy reports whether the node is doing its job at now: always true for
// a node that does not pull, otherwise true while the feed is being read.
func (s *Service) Healthy(now time.Time) bool {
	if !s.pulling.Load() {
		return true
	}
	return now.Sub(time.Unix(0, s.lastPoll.Load())) < FeedStaleAfter
}

// notFound replaces http.NotFound, whose "404 page not found" body identifies a Go server.
func notFound(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func fromLoopback(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && ap.Addr().Unmap().IsLoopback()
}

func (s *Service) serve(w http.ResponseWriter, r *http.Request, op api.Op, pathID string) {
	raw, err := readEnvelope(w, r)
	if err != nil {
		s.reject(w, r, "unreadable envelope")
		return
	}
	req, err := s.codec.OpenRequest(raw)
	if err != nil {
		s.reject(w, r, "envelope rejected")
		return
	}
	// The route is unauthenticated; the sealed op and job id are authoritative
	// and must agree with it so a captured request cannot be re-pointed.
	if req.Op != op || req.JobID != pathID {
		s.reject(w, r, "route mismatch")
		return
	}
	out, err := s.codec.SealResponse(s.handle(r.Context(), req, MaxInboundWait))
	if err != nil {
		s.log.Error("seal response", "error", err)
		notFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out) //nolint:gosec // sealed JSON envelope, not markup
}

func (s *Service) reject(w http.ResponseWriter, r *http.Request, reason string) {
	s.log.Debug("request rejected", "reason", reason, "remote", ratelimit.ClientIP(r), "method", r.Method)
	notFound(w, r)
}

// readEnvelope takes the sealed request from the body (POST) or from an
// "Authorization: NST <base64>" header (GET, DELETE).
func readEnvelope(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Method == http.MethodPost {
		return io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	}
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "NST ")
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return base64.StdEncoding.DecodeString(v)
}
