// Package bucket is an in-memory stand-in for the S3 objects a pull-mode node
// reads and writes, plus the controller side of the feed. It is used only by
// tests; in production the website writes the feed to S3 (docs/S3_FEED.md).
package bucket

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
)

const maxObject = 4 << 20

// Bucket serves objects by URL path, the way a path-style S3 endpoint does:
// GET with ETag and If-None-Match, and PUT. It is safe for concurrent use.
type Bucket struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    map[string]int
}

// New returns an empty bucket.
func New() *Bucket {
	return &Bucket{objects: map[string][]byte{}, puts: map[string]int{}}
}

func (b *Bucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		body, ok := b.Get(r.URL.Path)
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		etag := etagOf(body)
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(body)
	case http.MethodPut:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxObject))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b.Put(r.URL.Path, body)
		w.Header().Set("ETag", etagOf(body))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Put stores body under key, replacing any previous object.
func (b *Bucket) Put(key string, body []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects[key] = append([]byte(nil), body...)
	b.puts[key]++
}

// Get returns a copy of the object at key.
func (b *Bucket) Get(key string) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	body, ok := b.objects[key]
	return append([]byte(nil), body...), ok
}

// Puts reports how many times key has been written.
func (b *Bucket) Puts(key string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.puts[key]
}

// Append adds one line to the object at key.
func (b *Bucket) Append(key string, line []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects[key] = append(append(b.objects[key], line...), '\n')
}

func etagOf(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// Feed plays the website for one node: it appends sealed requests to the
// node's feed object and reads back the sealed responses the node PUTs.
type Feed struct {
	Bucket *Bucket
	Codec  *api.Codec
	// Key is the feed object's path, e.g. /netsurveil/feeds/<key>.txt.
	Key string
	// ReplyBases are the base URLs under which the node reaches the bucket.
	// Each request carries one reply URL per base, in this order.
	ReplyBases []string
	// PollInterval is how often Run checks for a result (default 100ms).
	PollInterval time.Duration
}

// Request seals a request whose responses go to resultKey. at sets the envelope timestamp.
func (f *Feed) Request(req api.Request, resultKey string, at time.Time) ([]byte, error) {
	for _, base := range f.ReplyBases {
		req.Reply = append(req.Reply, base+resultKey)
	}
	sealed, _, err := f.Codec.SealRequestAt(req, at)
	return sealed, err
}

// Queue appends req to the feed with a fresh RID and returns the RID and the
// key its responses are written to.
func (f *Feed) Queue(req api.Request) (rid, resultKey string, err error) {
	req.RID = api.NewRID()
	resultKey = fmt.Sprintf("/netsurveil/results/%s/%s.json", f.Codec.NodeID(), req.RID)
	line, err := f.Request(req, resultKey, time.Now())
	if err != nil {
		return "", "", err
	}
	f.Bucket.Append(f.Key, line)
	return req.RID, resultKey, nil
}

// Response opens the latest response stored under resultKey. ok is false
// while the node has not answered.
func (f *Feed) Response(rid, resultKey string) (job *jobs.Job, ok bool, err error) {
	raw, ok := f.Bucket.Get(resultKey)
	if !ok {
		return nil, false, nil
	}
	job, err = f.Codec.OpenResponse(raw, rid)
	return job, true, err
}

// Run queues a submit for checks and waits until the node reports the job finished.
func (f *Feed) Run(ctx context.Context, checks []check.Spec) (*jobs.Job, error) {
	rid, resultKey, err := f.Queue(api.Request{Op: api.OpSubmit, Checks: checks})
	if err != nil {
		return nil, err
	}

	poll := f.PollInterval
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("no final result for %s: %w", rid, ctx.Err())
		case <-t.C:
		}
		job, ok, err := f.Response(rid, resultKey)
		if err != nil {
			return nil, err
		}
		if ok && job.State != jobs.Running {
			return job, nil
		}
	}
}
