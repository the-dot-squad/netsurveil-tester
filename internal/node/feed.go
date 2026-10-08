package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
)

const (
	feedFetchTimeout = 20 * time.Second
	maxFeedBytes     = 2 << 20
	maxFeedLine      = 64 << 10
	seenTTL          = 5 * time.Minute // outlives the request window, so a line is opened once
	minPollCycle     = 5 * time.Second
	pollJitter       = 3 * time.Second
	maxBackoff       = 30 * time.Second
	replyTimeout     = 30 * time.Second
	replyAttempts    = 3
	// shutdownReply bounds delivery of final answers once the node is stopping.
	shutdownReply = 10 * time.Second
)

// feedJobWait is how long a feed submit may run before the node cancels it and
// reports its final state. A variable so tests can shorten it.
var feedJobWait = 10 * time.Minute

// feed reads one node's request feed from a list of mirror URLs. It stays on
// the mirror that last answered and moves to the next one after a failure.
type feed struct {
	urls   []string
	etags  []string
	cur    int
	client *http.Client
}

// fetch returns the feed body from the current mirror. changed is false when
// the mirror reports the feed unchanged since the last fetch from it.
func (f *feed) fetch(ctx context.Context) (body []byte, changed bool, err error) {
	i := f.cur
	body, etag, changed, err := f.get(ctx, f.urls[i], f.etags[i])
	if err != nil {
		f.cur = (i + 1) % len(f.urls)
		return nil, false, fmt.Errorf("mirror %d: %w", i, err)
	}
	f.etags[i] = etag
	return body, changed, nil
}

func (f *feed) get(ctx context.Context, target, etag string) ([]byte, string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, feedFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", false, errors.New("invalid feed URL")
	}
	req.Header.Set("User-Agent", check.UserAgent)
	req.Header.Set("Cache-Control", "no-cache")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, "", false, withoutURL(err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, false, nil
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
		if err != nil {
			return nil, "", false, withoutURL(err)
		}
		if len(body) > maxFeedBytes {
			return nil, "", false, fmt.Errorf("feed exceeds %d bytes", maxFeedBytes)
		}
		return body, resp.Header.Get("ETag"), true, nil
	}
	return nil, "", false, fmt.Errorf("status %d", resp.StatusCode)
}

// Pull polls the node's request feed, one sealed request per line, until ctx
// ends, then waits for the requests it started to send their final answers.
// Each new line is opened once; lines that fail authentication or are stale
// are skipped silently. Responses are PUT to the reply URLs carried inside
// each request.
func (s *Service) Pull(ctx context.Context, feedURLs []string, client *http.Client) {
	f := &feed{urls: feedURLs, etags: make([]string, len(feedURLs)), client: client}
	seen := map[[sha256.Size]byte]time.Time{}
	var items sync.WaitGroup
	defer items.Wait()
	backoff := time.Second
	s.lastPoll.Store(time.Now().UnixNano())
	s.pulling.Store(true)
	s.log.Info("feed pull started", "feeds", len(feedURLs))
	for ctx.Err() == nil {
		polled := time.Now()
		body, changed, err := f.fetch(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Warn("feed poll failed", "error", err, "retry_in", backoff)
			sleep(ctx, backoff+jitter(backoff/2))
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = time.Second
		s.lastPoll.Store(time.Now().UnixNano())
		if changed {
			s.dispatch(ctx, &items, client, body, seen)
		}
		for k, at := range seen {
			if time.Since(at) > seenTTL {
				delete(seen, k)
			}
		}
		// Jittered with a floor, so polling never forms a tight loop or a fixed-period beacon.
		sleep(ctx, max(0, minPollCycle-time.Since(polled))+jitter(pollJitter))
	}
}

// dispatch opens every feed line not seen before and serves each authentic
// request in its own goroutine. Authentication happens here, so forged or
// garbage lines never cost more than one decryption attempt.
func (s *Service) dispatch(ctx context.Context, items *sync.WaitGroup, client *http.Client, body []byte, seen map[[sha256.Size]byte]time.Time) {
	for line := range bytes.SplitSeq(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || len(line) > maxFeedLine {
			continue
		}
		key := sha256.Sum256(line)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = time.Now()
		req, err := s.codec.OpenRequest(line)
		if err != nil {
			s.log.Debug("feed line rejected")
			continue
		}
		items.Go(func() { s.serveFeedItem(ctx, client, req) })
	}
}

// serveFeedItem runs one authenticated feed request. A submit is answered
// with its running snapshot, then once more with a terminal state: a job still
// running after feedJobWait, or when the node shuts down, is cancelled first.
func (s *Service) serveFeedItem(ctx context.Context, client *http.Client, req api.Request) {
	if err := validReply(req.Reply); err != nil {
		s.log.Warn("feed request has no usable reply", "error", err)
		return
	}
	if req.Op != api.OpSubmit {
		resp := s.response(req)
		resp.Error = fmt.Sprintf("op %q is not accepted from the feed", req.Op)
		s.reply(ctx, client, req.Reply, resp)
		return
	}
	req.Wait = false
	resp := s.handle(ctx, req, 0)
	s.reply(ctx, client, req.Reply, resp)
	if resp.Job == nil || resp.Job.State != jobs.Running {
		return
	}
	id := resp.Job.ID
	wctx, cancel := context.WithTimeout(ctx, feedJobWait)
	job, _ := s.store.Wait(wctx, id)
	cancel()
	if job.State == jobs.Running {
		s.store.Cancel(id)
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cancelSettle)
		job, _ = s.store.Wait(sctx, id)
		cancel()
	}
	resp.Job = &job
	rctx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), shutdownReply)
		defer cancel()
	}
	s.reply(rctx, client, req.Reply, resp)
}

func validReply(urls []string) error {
	if len(urls) == 0 || len(urls) > api.MaxReplyURLs {
		return fmt.Errorf("need 1 to %d reply URLs, got %d", api.MaxReplyURLs, len(urls))
	}
	for i, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("reply URL %d is not an absolute http(s) URL", i)
		}
	}
	return nil
}

// reply seals resp and PUTs it to the first reply URL that accepts it.
func (s *Service) reply(ctx context.Context, client *http.Client, urls []string, resp api.Response) {
	body, err := s.codec.SealResponse(resp)
	if err != nil {
		s.log.Error("seal feed response", "error", err)
		return
	}
	for attempt := range replyAttempts {
		if attempt > 0 {
			sleep(ctx, time.Duration(attempt)*2*time.Second)
		}
		for _, u := range urls {
			if err = putObject(ctx, client, u, body); err == nil {
				return
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	s.log.Warn("feed response not delivered", "rid", resp.RID, "error", err)
}

func putObject(ctx context.Context, client *http.Client, target string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, replyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid reply URL")
	}
	req.Header.Set("User-Agent", check.UserAgent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return withoutURL(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// withoutURL drops the request URL from transport errors: feed URLs are
// configuration and reply URLs carry signatures, so neither belongs in logs.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d)))
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
