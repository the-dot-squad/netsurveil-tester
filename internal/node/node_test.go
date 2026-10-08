package node_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
	"github.com/the-dot-squad/netsurveil-tester/internal/envelope"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
	"github.com/the-dot-squad/netsurveil-tester/internal/netguard"
	"github.com/the-dot-squad/netsurveil-tester/internal/node"
	"github.com/the-dot-squad/netsurveil-tester/test/fixtures/bucket"
	"github.com/the-dot-squad/netsurveil-tester/test/fixtures/client"
)

var secret = bytes.Repeat([]byte{7}, 32)

const nodeID = "test-node"

func newCodec(t *testing.T, key []byte) *api.Codec {
	t.Helper()
	c, err := api.NewCodec(key, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newService(t *testing.T) *node.Service {
	t.Helper()
	return newServiceWith(t, nil, jobs.DefaultLimits)
}

// newServiceWith uses run instead of the real runner to execute checks when
// run is not nil; validation always goes through the real runner.
func newServiceWith(t *testing.T, run jobs.RunFunc, limits jobs.Limits) *node.Service {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := check.NewRunner(check.Env{Guard: netguard.New(false), NodeID: nodeID, Version: "test"}, log)
	if run == nil {
		run = runner.Run
	}
	store := jobs.New(run, limits)
	t.Cleanup(store.Close)
	return node.New(newCodec(t, secret), runner, store, "test", log)
}

// blockingRun stands in for a check that runs until its job is cancelled.
func blockingRun(ctx context.Context, s check.Spec) check.Result {
	<-ctx.Done()
	return check.Result{Type: s.Type, Target: s.Target, Verdict: check.Error, Mechanism: "cancelled"}
}

// A loopback target is refused by the guard instantly, giving a fast, offline check.
var forbiddenCheck = check.Spec{Type: "tcp", Target: "127.0.0.1", Options: json.RawMessage(`{"ports":[80]}`)}

func TestDirectRoundTrip(t *testing.T) {
	srv := httptest.NewServer(newService(t).Handler("/p", 1000))
	defer srv.Close()
	c, err := client.New(client.Config{NodeID: nodeID, Secret: secret, NodeURL: srv.URL + "/p"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	job, err := c.Run(ctx, []check.Spec{forbiddenCheck})
	if err != nil {
		t.Fatal(err)
	}
	if job.State != jobs.Done || len(job.Results) != 1 || job.Results[0].Mechanism != "forbidden_target" {
		t.Fatalf("unexpected job: %+v", job)
	}
	got, err := c.Status(ctx, job.ID)
	if err != nil || got.ID != job.ID {
		t.Fatalf("status: %+v %v", got, err)
	}
	if _, err := c.Cancel(ctx, job.ID); err != nil {
		t.Fatalf("cancel finished job: %v", err)
	}
	if _, err := c.Status(ctx, "nope"); err == nil || !strings.Contains(err.Error(), "unknown job") {
		t.Fatalf("unknown job: %v", err)
	}
	if _, err := c.Run(ctx, []check.Spec{{Type: "bogus"}}); err == nil || !strings.Contains(err.Error(), "unknown check type") {
		t.Fatalf("validation error not surfaced: %v", err)
	}
}

func TestDirectBusy(t *testing.T) {
	srv := httptest.NewServer(newServiceWith(t, blockingRun, jobs.Limits{MaxChecks: 2, CheckConcurrency: 1, MaxActiveJobs: 1, TTL: time.Minute}).Handler("", 1000))
	defer srv.Close()
	c, _ := client.New(client.Config{NodeID: nodeID, Secret: secret, NodeURL: srv.URL})
	ctx := context.Background()
	first, err := c.Submit(ctx, []check.Spec{forbiddenCheck}, false)
	if err != nil || first.State != jobs.Running {
		t.Fatalf("first: %+v %v", first, err)
	}
	if _, err := c.Submit(ctx, []check.Spec{forbiddenCheck}, false); err == nil || !strings.Contains(err.Error(), "too many active jobs") {
		t.Fatalf("second submit: %v", err)
	}
	job, err := c.Cancel(ctx, first.ID)
	if err != nil || job.State != jobs.Cancelled {
		t.Fatalf("cancel: %+v %v", job, err)
	}
}

func TestRejections(t *testing.T) {
	srv := httptest.NewServer(newService(t).Handler("", 1000))
	defer srv.Close()

	wrong, _ := client.New(client.Config{NodeID: nodeID, Secret: bytes.Repeat([]byte{8}, 32), NodeURL: srv.URL})
	if _, err := wrong.Run(context.Background(), []check.Spec{forbiddenCheck}); err == nil {
		t.Fatal("wrong secret accepted")
	}

	box, _ := envelope.New(secret, nodeID)
	seal := func(req api.Request, at time.Time) []byte {
		pt, _ := json.Marshal(req)
		b, _ := box.SealAt(envelope.Request, pt, at)
		return b
	}
	post := func(path string, body []byte) int {
		resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	get := func(path, auth string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	submit := api.Request{RID: "r1", Op: api.OpSubmit, Checks: []check.Spec{forbiddenCheck}}
	fresh := seal(submit, time.Now())
	if code := post("/v1/jobs", fresh); code != http.StatusOK {
		t.Fatalf("fresh request: %d", code)
	}
	if code := post("/v1/jobs", fresh); code != http.StatusNotFound {
		t.Errorf("replay: %d", code)
	}
	if code := post("/v1/jobs", seal(submit, time.Now().Add(-5*time.Minute))); code != http.StatusNotFound {
		t.Errorf("expired: %d", code)
	}
	tampered := bytes.Replace(seal(submit, time.Now()), []byte(`"ct":"`), []byte(`"ct":"AA`), 1)
	if code := post("/v1/jobs", tampered); code != http.StatusNotFound {
		t.Errorf("tampered: %d", code)
	}
	getReq := seal(api.Request{RID: "r2", Op: api.OpGet, JobID: "aaa"}, time.Now())
	if code := get("/v1/jobs/bbb", "NST "+base64.StdEncoding.EncodeToString(getReq)); code != http.StatusNotFound {
		t.Errorf("re-pointed route: %d", code)
	}
	if code := post("/v1/jobs", seal(api.Request{RID: "r3", Op: api.OpGet, JobID: "x"}, time.Now())); code != http.StatusNotFound {
		t.Errorf("op mismatch: %d", code)
	}
	if code := get("/v1/jobs/x", ""); code != http.StatusNotFound {
		t.Errorf("missing auth: %d", code)
	}
	if code := get("/healthz", ""); code != http.StatusNotFound {
		t.Errorf("healthz on the public listener: %d", code)
	}
}

func TestNoFingerprint(t *testing.T) {
	h := newService(t).Handler("/p", 1000)
	cases := []struct {
		method, target, remote string
	}{
		{http.MethodGet, "/", "203.0.113.5:4000"},
		{http.MethodGet, "/p/healthz", "127.0.0.1:4000"},
		{http.MethodGet, "/p//v1/jobs", "203.0.113.5:4000"},
		{http.MethodGet, "/p/v1/../v1/jobs", "127.0.0.1:4000"},
		{http.MethodPut, "/p/v1/jobs/x", "203.0.113.5:4000"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.target, nil)
		req.RemoteAddr = c.remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
			t.Errorf("%s %s from %s: %d %q", c.method, c.target, c.remote, rec.Code, rec.Body.String())
		}
	}
}

func TestRateLimitLooksLikeNotFound(t *testing.T) {
	srv := httptest.NewServer(newService(t).Handler("", 2))
	defer srv.Close()
	c, _ := client.New(client.Config{NodeID: nodeID, Secret: secret, NodeURL: srv.URL})
	var errs []string
	for range 3 {
		_, err := c.Status(context.Background(), "nope")
		errs = append(errs, err.Error())
	}
	if !strings.Contains(errs[1], "unknown job") || !strings.Contains(errs[2], "HTTP 404") {
		t.Fatalf("errors %q", errs)
	}
}

func TestHealthHandler(t *testing.T) {
	svc := newService(t)
	h := svc.HealthHandler()
	call := func(method, target, remote string) (int, string) {
		req := httptest.NewRequest(method, target, nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := call(http.MethodGet, "/healthz", "127.0.0.1:5000"); code != http.StatusOK || body != "ok" {
		t.Errorf("loopback: %d %q", code, body)
	}
	if code, _ := call(http.MethodGet, "/healthz", "[::1]:5000"); code != http.StatusOK {
		t.Errorf("ipv6 loopback: %d", code)
	}
	for _, c := range []struct{ method, target, remote string }{
		{http.MethodGet, "/healthz", "203.0.113.5:5000"},
		{http.MethodPost, "/healthz", "127.0.0.1:5000"},
		{http.MethodGet, "/v1/jobs", "127.0.0.1:5000"},
	} {
		if code, body := call(c.method, c.target, c.remote); code != http.StatusNotFound || body != "" {
			t.Errorf("%s %s from %s: %d %q", c.method, c.target, c.remote, code, body)
		}
	}
}

func TestHealthTracksFeed(t *testing.T) {
	svc := newService(t)
	if !svc.Healthy(time.Now()) {
		t.Fatal("a node that does not pull must be healthy")
	}
	bkt := bucket.New()
	bkt.Put("/f", nil)
	srv := httptest.NewServer(bkt)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Pull(ctx, []string{srv.URL + "/f"}, srv.Client()); close(done) }()
	defer func() { cancel(); <-done }()

	stale := func() bool { return !svc.Healthy(time.Now().Add(node.FeedStaleAfter + time.Minute)) }
	deadline := time.Now().Add(5 * time.Second)
	for !stale() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !stale() {
		t.Fatal("a feed unread for longer than FeedStaleAfter is reported healthy")
	}
	if !svc.Healthy(time.Now()) {
		t.Fatal("pulling node with a readable feed is unhealthy")
	}
}

// pullHarness runs svc.Pull against an in-memory bucket until the test ends.
type pullHarness struct {
	bkt  *bucket.Bucket
	feed *bucket.Feed
	stop func()
}

func startPull(t *testing.T, svc *node.Service, extraMirrors ...string) *pullHarness {
	t.Helper()
	bkt := bucket.New()
	srv := httptest.NewServer(bkt)
	t.Cleanup(srv.Close)
	const feedKey = "/netsurveil/feeds/k.txt"
	bkt.Put(feedKey, nil)
	feed := &bucket.Feed{Bucket: bkt, Codec: newCodec(t, secret), Key: feedKey, ReplyBases: []string{srv.URL}, PollInterval: 50 * time.Millisecond}
	urls := append(extraMirrors, srv.URL+feedKey)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { svc.Pull(ctx, urls, srv.Client()) })
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); wg.Wait() }) }
	t.Cleanup(stop)
	return &pullHarness{bkt: bkt, feed: feed, stop: stop}
}

// await polls the response for rid until done reports true for it, or fails.
func (h *pullHarness) await(t *testing.T, rid, key string, done func(*jobs.Job, error) bool) (*jobs.Job, error) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		job, ok, err := h.feed.Response(rid, key)
		if ok && done(job, err) {
			return job, err
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no matching response for %s", rid)
	return nil, nil
}

func running(j *jobs.Job, err error) bool  { return err == nil && j.State == jobs.Running }
func terminal(j *jobs.Job, err error) bool { return err != nil || j.State != jobs.Running }

func TestFeedRoundTrip(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	h := startPull(t, newService(t), dead.URL+"/netsurveil/feeds/k.txt")
	h.feed.ReplyBases = append([]string{dead.URL}, h.feed.ReplyBases...)

	// Lines the node must skip without replying: stale, forged, garbage, and one without a reply URL.
	forger := &bucket.Feed{Codec: newCodec(t, bytes.Repeat([]byte{8}, 32)), ReplyBases: h.feed.ReplyBases}
	submit := api.Request{RID: "skip", Op: api.OpSubmit, Checks: []check.Spec{forbiddenCheck}}
	stale, _ := h.feed.Request(submit, "/r/stale", time.Now().Add(-5*time.Minute))
	forged, _ := forger.Request(submit, "/r/forged", time.Now())
	noReply, _ := (&bucket.Feed{Codec: h.feed.Codec}).Request(submit, "", time.Now())
	duplicate, _ := h.feed.Request(submit, "/r/duplicate", time.Now())
	for _, line := range [][]byte{stale, forged, []byte("not an envelope"), noReply, duplicate, duplicate} {
		h.bkt.Append(h.feed.Key, line)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	job, err := h.feed.Run(ctx, []check.Spec{forbiddenCheck, forbiddenCheck})
	if err != nil {
		t.Fatal(err)
	}
	if job.State != jobs.Done || len(job.Results) != 2 || job.Results[0].Mechanism != "forbidden_target" {
		t.Fatalf("job %+v", job)
	}
	for _, key := range []string{"/r/stale", "/r/forged"} {
		if n := h.bkt.Puts(key); n != 0 {
			t.Errorf("%s: node replied %d times to a line it must ignore", key, n)
		}
	}
	// A running snapshot, if the job had not finished yet, then the final job: never more.
	if n := h.bkt.Puts("/r/duplicate"); n < 1 || n > 2 {
		t.Errorf("duplicate line answered with %d responses", n)
	}
}

func TestFeedBusyAnswersAtOnce(t *testing.T) {
	svc := newServiceWith(t, blockingRun, jobs.Limits{MaxChecks: 2, CheckConcurrency: 1, MaxActiveJobs: 1, TTL: time.Minute})
	h := startPull(t, svc)

	ridA, keyA, _ := h.feed.Queue(api.Request{Op: api.OpSubmit, Checks: []check.Spec{forbiddenCheck}})
	if _, err := h.await(t, ridA, keyA, running); err != nil {
		t.Fatal(err)
	}

	ridB, keyB, _ := h.feed.Queue(api.Request{Op: api.OpSubmit, Checks: []check.Spec{forbiddenCheck}})
	_, err := h.await(t, ridB, keyB, func(_ *jobs.Job, err error) bool { return err != nil })
	if !strings.Contains(err.Error(), "too many active jobs") {
		t.Fatalf("busy reply: %v", err)
	}

	// Shutting down cancels the running job and still delivers its final state.
	h.stop()
	job, ok, err := h.feed.Response(ridA, keyA)
	if !ok || err != nil || job.State != jobs.Cancelled {
		t.Fatalf("final answer after shutdown: %+v %v %v", job, ok, err)
	}
}

func TestFeedCancelsOverdueJob(t *testing.T) {
	node.SetFeedJobWait(t, 300*time.Millisecond)
	h := startPull(t, newServiceWith(t, blockingRun, jobs.DefaultLimits))
	rid, key, _ := h.feed.Queue(api.Request{Op: api.OpSubmit, Checks: []check.Spec{forbiddenCheck}})
	job, err := h.await(t, rid, key, terminal)
	if err != nil || job.State != jobs.Cancelled || job.Results[0] == nil {
		t.Fatalf("overdue job: %+v %v", job, err)
	}
}

func TestFeedAcceptsOnlySubmit(t *testing.T) {
	h := startPull(t, newService(t))
	type queued struct{ op, rid, key string }
	var all []queued
	for _, req := range []api.Request{{Op: api.OpGet, JobID: "x"}, {Op: api.OpCancel, JobID: "x"}} {
		rid, key, _ := h.feed.Queue(req)
		all = append(all, queued{string(req.Op), rid, key})
	}
	for _, q := range all {
		_, err := h.await(t, q.rid, q.key, func(_ *jobs.Job, err error) bool { return err != nil })
		if !strings.Contains(err.Error(), "not accepted from the feed") {
			t.Errorf("%s: %v", q.op, err)
		}
	}
}
