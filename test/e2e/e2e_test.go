//go:build e2e

// Package e2e drives a node inside the simulated censored network defined in
// docker-compose.e2e.yml and asserts the verdict for every censorship pattern.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
	"github.com/the-dot-squad/netsurveil-tester/internal/config"
	"github.com/the-dot-squad/netsurveil-tester/internal/envelope"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
	"github.com/the-dot-squad/netsurveil-tester/test/fixtures/bucket"
	"github.com/the-dot-squad/netsurveil-tester/test/fixtures/client"
)

const (
	target = "172.30.0.20"
	// feedKey must match the path in the node's FEED_URLS.
	feedKey = "/netsurveil/feeds/e2e.txt"
)

// feed plays the website against the in-process bucket the node pulls its feed from.
var feed *bucket.Feed

func TestMain(m *testing.M) {
	secret, err := config.ParseSecret(os.Getenv("NST_SECRET"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "NST_SECRET:", err)
		os.Exit(2)
	}
	codec, err := api.NewCodec(secret, os.Getenv("NST_NODE_ID"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", os.Getenv("NST_BUCKET_LISTEN"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "bucket listen:", err)
		os.Exit(2)
	}
	bkt := bucket.New()
	bkt.Put(feedKey, nil)
	srv := &http.Server{Handler: bkt, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	feed = &bucket.Feed{Bucket: bkt, Codec: codec, Key: feedKey, ReplyBases: []string{os.Getenv("NST_BUCKET_URL")}, PollInterval: 250 * time.Millisecond}

	code := m.Run()
	_ = srv.Close()
	os.Exit(code)
}

// The clean resolver; without it, controls would ask the public internet about .test names.
const controls = `"control_resolvers":["172.30.0.10:5353"]`

type scenario struct {
	name      string
	spec      check.Spec
	verdict   check.Verdict
	mechanism string
	verify    func(t *testing.T, r *check.Result)
}

func spec(typ, tgt, opts string) check.Spec {
	s := check.Spec{Type: typ, Target: tgt}
	if opts != "" {
		s.Options = json.RawMessage("{" + opts + "}")
	}
	return s
}

func scenarios() []scenario {
	return []scenario{
		{name: "dns sinkhole", spec: spec("dns", "blocked.test", controls+`,"injection_probe":"off"`), verdict: check.Blocked, mechanism: "dns_sinkhole"},
		{name: "dns nxdomain hijack", spec: spec("dns", "nx.test", controls+`,"injection_probe":"off"`), verdict: check.Blocked, mechanism: "dns_nxdomain"},
		{name: "dns clean", spec: spec("dns", "allowed.test", controls+`,"injection_probe":"off","resolvers":["172.30.0.10"]`), verdict: check.OK},
		{name: "web dns sinkhole", spec: spec("web", "https://blocked.test/", controls), verdict: check.Blocked, mechanism: "dns_sinkhole"},
		{name: "web http ok", spec: spec("web", "http://allowed.test:8080/", controls), verdict: check.OK},
		{name: "web https ok", spec: spec("web", "https://allowed.test:8443/", controls+`,"insecure":true`), verdict: check.OK},
		{name: "web untrusted cert", spec: spec("web", "https://allowed.test:8443/", controls), verdict: check.Anomaly, mechanism: "tls_invalid_cert"},
		{name: "web block page", spec: spec("web", "http://allowed.test:8082/", controls), verdict: check.Blocked, mechanism: "http_blockpage"},
		{name: "web 451", spec: spec("web", "http://allowed.test:8080/status/451", controls), verdict: check.Blocked, mechanism: "http_451"},
		{name: "web redirect to sinkhole", spec: spec("web", "http://allowed.test:8080/redirect-sinkhole", controls), verdict: check.Blocked, mechanism: "http_redirect_sinkhole"},
		{name: "web keyword reset", spec: spec("web", "http://allowed.test:8080/forbidden-keyword", controls), verdict: check.Blocked, mechanism: "http_rst"},
		{
			name: "tcp ports", spec: spec("tcp", target, `"ports":[7000,7001,7002,7003],"timeout_ms":2000`),
			verdict: check.Blocked, mechanism: "tcp_timeout",
			verify: func(t *testing.T, r *check.Result) {
				var ev struct {
					Ports []struct {
						Port  int    `json:"port"`
						State string `json:"state"`
					} `json:"ports"`
				}
				decode(t, r, &ev)
				want := map[int]string{7000: "open", 7001: "refused", 7002: "timeout", 7003: "open"}
				for _, p := range ev.Ports {
					if want[p.Port] != p.State {
						t.Errorf("port %d: state %q, want %q", p.Port, p.State, want[p.Port])
					}
				}
			},
		},
		{name: "sni reset", spec: spec("sni", "blocked-sni.test", `"ip":"`+target+`","port":9443,"control_sni":"allowed.test","timeout_ms":3000`), verdict: check.Blocked, mechanism: "tls_sni_rst"},
		{name: "sni allowed", spec: spec("sni", "other.test", `"ip":"`+target+`","port":9443,"control_sni":"allowed.test","timeout_ms":3000`), verdict: check.OK},
		{name: "quic dropped", spec: spec("quic", "https://allowed.test:8443/", `"insecure":true,"timeout_ms":3000`), verdict: check.Blocked, mechanism: "quic_drop"},
		{name: "quic ok", spec: spec("quic", "https://allowed.test:8444/", `"insecure":true,"timeout_ms":3000`), verdict: check.OK},
		{
			name:    "throttle bandwidth cap",
			spec:    spec("throttle", "http://allowed.test:8081/blob?bytes=10000000", `"control_url":"http://allowed.test:8080/blob?bytes=10000000","duration_s":4`),
			verdict: check.Throttled, mechanism: "bandwidth_cap",
		},
		{
			name:    "throttle stall",
			spec:    spec("throttle", "http://allowed.test:8083/blob?bytes=10000000", `"control_url":"http://allowed.test:8080/blob?bytes=10000000","duration_s":5`),
			verdict: check.Throttled, mechanism: "stall_after_bytes",
		},
		{name: "ping", spec: spec("ping", target, `"count":3,"interval_ms":200`), verdict: check.OK},
		{name: "web large page quoting a block phrase", spec: spec("web", "http://allowed.test:8080/article", controls), verdict: check.OK},
		{name: "web check timeout", spec: check.Spec{Type: "web", Target: "http://allowed.test:7002/", Options: json.RawMessage("{" + controls + "}"), TimeoutS: 3}, verdict: check.Error, mechanism: "check_timeout"},
		{name: "loopback refused", spec: spec("tcp", "127.0.0.1", `"ports":[8080]`), verdict: check.Error, mechanism: "forbidden_target"},
	}
}

func env(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("%s is not set", k)
	}
	return v
}

func secret(t *testing.T) []byte {
	t.Helper()
	s, err := config.ParseSecret(env(t, "NST_SECRET"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newClient(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.New(client.Config{NodeID: env(t, "NST_NODE_ID"), Secret: secret(t), NodeURL: env(t, "NST_NODE_URL"), PollInterval: 250 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func decode(t *testing.T, r *check.Result, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Evidence, v); err != nil {
		t.Fatalf("evidence: %v", err)
	}
}

// runner is satisfied by the direct client and by the feed controller.
type runner interface {
	Run(ctx context.Context, checks []check.Spec) (*jobs.Job, error)
}

func run(t *testing.T, c runner, specs []check.Spec) *jobs.Job {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	job, err := c.Run(ctx, specs)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != jobs.Done || len(job.Results) != len(specs) {
		t.Fatalf("job %s: state %s with %d/%d results", job.ID, job.State, len(job.Results), len(specs))
	}
	return job
}

func assertScenarios(t *testing.T, sc []scenario, job *jobs.Job) {
	for i, s := range sc {
		r := job.Results[i]
		t.Run(s.name, func(t *testing.T) {
			if r.Verdict != s.verdict || r.Mechanism != s.mechanism {
				ev, _ := json.Marshal(r)
				t.Fatalf("got %s/%s, want %s/%s\n%s", r.Verdict, r.Mechanism, s.verdict, s.mechanism, ev)
			}
			if s.verify != nil {
				s.verify(t, r)
			}
		})
	}
}

func TestCensorshipScenariosDirect(t *testing.T) {
	c := newClient(t)
	for batch := range slices.Chunk(scenarios(), jobs.DefaultLimits.MaxChecks) {
		specs := make([]check.Spec, len(batch))
		for i, s := range batch {
			specs[i] = s.spec
		}
		assertScenarios(t, batch, run(t, c, specs))
	}
}

func TestPathAndInfo(t *testing.T) {
	sc := []scenario{
		{name: "traceroute icmp", spec: spec("traceroute", target, `"max_hops":5,"probes":1,"wait_ms":500`), verdict: check.OK},
		{name: "traceroute tcp open port", spec: spec("traceroute", target, `"mode":"tcp","port":7000,"max_hops":5,"probes":1,"wait_ms":500`), verdict: check.OK},
		{name: "traceroute tcp dropped port", spec: spec("traceroute", target, `"mode":"tcp","port":7002,"max_hops":3,"probes":1,"wait_ms":300`), verdict: check.Unreachable, mechanism: "path_drop"},
	}
	specs := []check.Spec{sc[0].spec, sc[1].spec, sc[2].spec, {Type: "info"}}
	job := run(t, newClient(t), specs)
	assertScenarios(t, sc, job)

	info := job.Results[3]
	var ev struct {
		NodeID  string `json:"node_id"`
		Version string `json:"version"`
	}
	decode(t, info, &ev)
	if ev.NodeID != os.Getenv("NST_NODE_ID") || ev.Version == "" {
		t.Errorf("info evidence: %s", info.Evidence)
	}
	// The stack has no egress, so a successful public IP lookup would mean traffic left the host.
	if info.Verdict != check.Unreachable || info.Mechanism != "public_lookup_failed" {
		t.Errorf("info reached the internet or failed oddly: %s/%s %s", info.Verdict, info.Mechanism, info.Evidence)
	}
}

func TestFeedMode(t *testing.T) {
	sc := scenarios()
	picked := []scenario{sc[0], sc[11], sc[len(sc)-1]}
	specs := []check.Spec{picked[0].spec, picked[1].spec, picked[2].spec}
	assertScenarios(t, picked, run(t, feed, specs))
}

func TestCancel(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	job, err := c.Submit(ctx, []check.Spec{spec("throttle", "http://allowed.test:8083/blob?bytes=10000000",
		`"control_url":"http://allowed.test:8080/blob?bytes=10000000","duration_s":20`)}, false)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != jobs.Running {
		t.Fatalf("state %s", job.State)
	}
	if job, err = c.Cancel(ctx, job.ID); err != nil || job.State != jobs.Cancelled {
		t.Fatalf("cancel: %v %+v", err, job)
	}
}

func TestBusy(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	slow := []check.Spec{spec("tcp", target, `"ports":[7002],"timeout_ms":10000`)}
	var ids []string
	defer func() {
		for _, id := range ids {
			_, _ = c.Cancel(ctx, id)
		}
	}()
	for {
		job, err := c.Submit(ctx, slow, false)
		if err != nil {
			if !strings.Contains(err.Error(), jobs.ErrBusy.Error()) {
				t.Fatalf("after %d jobs: %v", len(ids), err)
			}
			break
		}
		ids = append(ids, job.ID)
		if len(ids) > 64 {
			t.Fatal("node never reported busy")
		}
	}
	if len(ids) == 0 {
		t.Fatal("busy before any job ran")
	}
}

func TestRejections(t *testing.T) {
	nodeURL := env(t, "NST_NODE_URL")
	box, err := envelope.New(secret(t), env(t, "NST_NODE_ID"))
	if err != nil {
		t.Fatal(err)
	}
	post := func(body []byte) int {
		resp, err := http.Post(nodeURL+"/v1/jobs", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	seal := func(b *envelope.Box, at time.Time) []byte {
		pt, _ := json.Marshal(api.Request{RID: "e2e", Op: api.OpSubmit, Checks: []check.Spec{spec("tcp", "127.0.0.1", "")}})
		out, err := b.SealAt(envelope.Request, pt, at)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	fresh := seal(box, time.Now())
	if code := post(fresh); code != http.StatusOK {
		t.Fatalf("valid request: %d", code)
	}
	wrongKey, _ := envelope.New(bytes.Repeat([]byte{0xee}, config.SecretSize), env(t, "NST_NODE_ID"))
	wrongNode, _ := envelope.New(secret(t), "other-node")
	cases := map[string][]byte{
		"replayed":   fresh,
		"expired":    seal(box, time.Now().Add(-10*time.Minute)),
		"future":     seal(box, time.Now().Add(10*time.Minute)),
		"tampered":   bytes.Replace(seal(box, time.Now()), []byte(`"ct":"`), []byte(`"ct":"AAAA`), 1),
		"wrong key":  seal(wrongKey, time.Now()),
		"wrong node": seal(wrongNode, time.Now()),
		"garbage":    []byte(`{"v":1}`),
	}
	for name, body := range cases {
		if code := post(body); code != http.StatusNotFound {
			t.Errorf("%s: HTTP %d, want 404", name, code)
		}
	}
}
