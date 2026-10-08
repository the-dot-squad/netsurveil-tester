package client_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
	"github.com/the-dot-squad/netsurveil-tester/test/fixtures/client"
)

var secret = bytes.Repeat([]byte{5}, 32)

const nodeID = "n1"

// fakeNode opens each request like a node and answers with respond.
func fakeNode(t *testing.T, respond func(r *http.Request, req api.Request) (api.Response, int)) *httptest.Server {
	t.Helper()
	codec, err := api.NewCodec(secret, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw []byte
		if r.Method == http.MethodPost {
			raw, _ = io.ReadAll(r.Body)
		} else {
			v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "NST ")
			if !ok {
				t.Errorf("%s %s without an NST authorization header", r.Method, r.URL.Path)
			}
			raw, _ = base64.StdEncoding.DecodeString(v)
		}
		req, err := codec.OpenRequest(raw)
		if err != nil {
			t.Errorf("open request: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		resp, code := respond(r, req)
		if code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		resp.Node = nodeID
		out, _ := codec.SealResponse(resp)
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newClient(t *testing.T, url string) *client.Client {
	t.Helper()
	c, err := client.New(client.Config{NodeID: nodeID, Secret: secret, NodeURL: url + "/prefix/", PollInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRunPollsUntilDone(t *testing.T) {
	var polls atomic.Int32
	srv := fakeNode(t, func(r *http.Request, req api.Request) (api.Response, int) {
		resp := api.Response{RID: req.RID}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/prefix/v1/jobs":
			if !req.Wait || req.Op != api.OpSubmit || len(req.Checks) != 1 {
				t.Errorf("submit request %+v", req)
			}
			resp.Job = &jobs.Job{ID: "j1", State: jobs.Running}
		case r.Method == http.MethodGet && r.URL.Path == "/prefix/v1/jobs/j1" && req.JobID == "j1":
			state := jobs.Running
			if polls.Add(1) == 3 {
				state = jobs.Done
			}
			resp.Job = &jobs.Job{ID: "j1", State: state}
		default:
			t.Errorf("unexpected %s %s %+v", r.Method, r.URL.Path, req)
			return resp, http.StatusNotFound
		}
		return resp, http.StatusOK
	})
	job, err := newClient(t, srv.URL).Run(context.Background(), []check.Spec{{Type: "info"}})
	if err != nil || job.State != jobs.Done || polls.Load() != 3 {
		t.Fatalf("job %+v err %v polls %d", job, err, polls.Load())
	}
}

func TestCancelUsesDelete(t *testing.T) {
	srv := fakeNode(t, func(r *http.Request, req api.Request) (api.Response, int) {
		if r.Method != http.MethodDelete || req.Op != api.OpCancel || req.JobID != "a/b" || r.URL.EscapedPath() != "/prefix/v1/jobs/a%2Fb" {
			t.Errorf("cancel request %s %s %+v", r.Method, r.URL.EscapedPath(), req)
		}
		return api.Response{RID: req.RID, Job: &jobs.Job{ID: req.JobID, State: jobs.Cancelled}}, http.StatusOK
	})
	job, err := newClient(t, srv.URL).Cancel(context.Background(), "a/b")
	if err != nil || job.State != jobs.Cancelled {
		t.Fatalf("%+v %v", job, err)
	}
}

func TestErrors(t *testing.T) {
	cases := []struct {
		name    string
		respond func(*http.Request, api.Request) (api.Response, int)
		want    string
	}{
		{"rejected", func(*http.Request, api.Request) (api.Response, int) { return api.Response{}, http.StatusNotFound }, "HTTP 404"},
		{"wrong rid", func(_ *http.Request, req api.Request) (api.Response, int) {
			return api.Response{RID: req.RID + "x", Job: &jobs.Job{}}, http.StatusOK
		}, "does not belong"},
		{"node error", func(_ *http.Request, req api.Request) (api.Response, int) {
			return api.Response{RID: req.RID, Error: "unknown job"}, http.StatusOK
		}, "node: unknown job"},
	}
	for _, c := range cases {
		srv := fakeNode(t, c.respond)
		if _, err := newClient(t, srv.URL).Status(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

func TestRunStopsWithContext(t *testing.T) {
	srv := fakeNode(t, func(_ *http.Request, req api.Request) (api.Response, int) {
		return api.Response{RID: req.RID, Job: &jobs.Job{ID: "j", State: jobs.Running}}, http.StatusOK
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	job, err := newClient(t, srv.URL).Run(ctx, []check.Spec{{Type: "info"}})
	if !errors.Is(err, context.DeadlineExceeded) || job == nil || job.State != jobs.Running {
		t.Fatalf("%+v %v", job, err)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := client.New(client.Config{NodeID: nodeID, Secret: secret}); err == nil {
		t.Error("missing URL accepted")
	}
	if _, err := client.New(client.Config{NodeID: nodeID, Secret: []byte("short"), NodeURL: "http://x"}); err == nil {
		t.Error("short secret accepted")
	}
}
