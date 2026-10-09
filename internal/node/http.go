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

// denyFunc rejects a request with the empty 404 and records it against the client.
type denyFunc func(w http.ResponseWriter, r *http.Request, reason string)

// Handler serves the inbound API under prefix. Every failure — bad route,
// rate limit, authentication, decoding — is the same empty 404, so a scanner
// sees nothing that distinguishes this from a closed web server.
//
// perMinute bounds rejected requests per client; authenticated requests are
// never counted, so scanning cannot lock out the controller even when both
// arrive through the same proxy. trusted lists the proxies whose
// X-Forwarded-For identifies the client.
func (s *Service) Handler(prefix string, perMinute int, trusted []netip.Prefix) http.Handler {
	lim := ratelimit.New(perMinute, time.Minute)
	deny := func(w http.ResponseWriter, r *http.Request, reason string) {
		ip := ratelimit.ClientIP(r, trusted)
		lim.Allow(ip)
		s.log.Debug("request rejected", "reason", reason, "remote", ip, "method", r.Method)
		notFound(w, r)
	}
	unknownRoute := func(w http.ResponseWriter, r *http.Request) { deny(w, r, "unknown route") }
	mux := http.NewServeMux()
	mux.HandleFunc("/", unknownRoute)
	mux.HandleFunc(prefix+"/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			unknownRoute(w, r)
			return
		}
		s.serve(w, r, api.OpSubmit, "", deny)
	})
	mux.HandleFunc(prefix+"/v1/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.serve(w, r, api.OpGet, r.PathValue("id"), deny)
		case http.MethodDelete:
			s.serve(w, r, api.OpCancel, r.PathValue("id"), deny)
		default:
			unknownRoute(w, r)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lim.Exceeded(ratelimit.ClientIP(r, trusted)) {
			notFound(w, r)
			return
		}
		// ServeMux would answer unclean paths with a telltale 301 redirect.
		if r.URL.Path != path.Clean(r.URL.Path) {
			deny(w, r, "unclean path")
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

func (s *Service) serve(w http.ResponseWriter, r *http.Request, op api.Op, pathID string, deny denyFunc) {
	raw, err := readEnvelope(w, r)
	if err != nil {
		deny(w, r, "unreadable envelope")
		return
	}
	req, err := s.codec.OpenRequest(raw)
	if err != nil {
		deny(w, r, "envelope rejected")
		return
	}
	// The route is unauthenticated; the sealed op and job id are authoritative
	// and must agree with it so a captured request cannot be re-pointed.
	if req.Op != op || req.JobID != pathID {
		deny(w, r, "route mismatch")
		return
	}
	out, err := s.codec.SealResponse(s.handle(r.Context(), req, MaxInboundWait))
	if err != nil {
		s.log.Error("seal response", "error", err)
		notFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
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
