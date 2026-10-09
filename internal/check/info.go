package check

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

// Cloudflare trace endpoints, raced for the public IP. The bare IPs avoid
// local DNS; the hostname survives networks that block TLS to those IPs.
var traceURLs = []string{
	"https://1.1.1.1/cdn-cgi/trace",
	"https://1.0.0.1/cdn-cgi/trace",
	"https://www.cloudflare.com/cdn-cgi/trace",
}

// Enrichment is queried for the IP found above, so the answer describes this
// node even when the request travels through a DNS-redirecting proxy.
const (
	ipinfoBase = "https://ipinfo.io/"
	ripeBase   = "https://stat.ripe.net/data/prefix-overview/data.json?resource="
)

type infoEvidence struct {
	NodeID         string   `json:"node_id"`
	Version        string   `json:"version"`
	OS             string   `json:"os"`
	Arch           string   `json:"arch"`
	PublicIP       string   `json:"public_ip,omitempty"`
	PublicIPSource string   `json:"public_ip_source,omitempty"`
	Country        string   `json:"country,omitempty"`
	City           string   `json:"city,omitempty"`
	Org            string   `json:"org,omitempty"`
	Colo           string   `json:"cloudflare_colo,omitempty"`
	Resolvers      []string `json:"resolvers,omitempty"`
	RawICMP        bool     `json:"raw_icmp"`
	Errors         []string `json:"errors,omitempty"`
}

func prepareInfo(env *Env, target string, raw json.RawMessage, _ time.Duration) (execFunc, error) {
	if target != "" && target != "self" {
		return nil, errors.New(`target must be empty or "self"`)
	}
	if err := decodeOptions(raw, &struct{}{}); err != nil {
		return nil, err
	}
	return func(ctx context.Context) outcome {
		ev := &infoEvidence{NodeID: env.NodeID, Version: env.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, Resolvers: systemResolvers()}
		if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
			ev.RawICMP = true
			_ = c.Close()
		}
		client := env.Guard.HTTPClient(false)
		lookupPublicInfo(ctx, client, ev, traceURLs, ipinfoBase, ripeBase)
		if ev.PublicIP == "" {
			return outcome{verdict: Unreachable, mechanism: "public_lookup_failed", evidence: ev}
		}
		return outcome{verdict: OK, evidence: ev}
	}, nil
}

// lookupPublicInfo fills the public IP from the first trace endpoint that
// answers, then the network operator and location for that IP.
func lookupPublicInfo(ctx context.Context, client *http.Client, ev *infoEvidence, traces []string, ipinfo, ripe string) {
	tr, errs := raceTrace(ctx, client, traces)
	for _, err := range errs {
		ev.Errors = append(ev.Errors, err.Error())
	}
	if tr.ip == "" {
		return
	}
	ev.PublicIP, ev.PublicIPSource, ev.Country, ev.Colo = tr.ip, tr.source, tr.loc, tr.colo

	var ii struct{ City, Country, Org string }
	var asn string
	var iiErr, ripeErr error
	var wg sync.WaitGroup
	wg.Go(func() {
		body, err := fetchSmall(ctx, client, ipinfo+tr.ip+"/json")
		if err == nil {
			err = json.Unmarshal(body, &ii)
		}
		iiErr = err
	})
	wg.Go(func() { asn, ripeErr = ripeHolder(ctx, client, ripe+tr.ip) })
	wg.Wait()

	ev.City = ii.City
	if ev.Country == "" {
		ev.Country = ii.Country
	}
	ev.Org = ii.Org
	if ev.Org == "" {
		ev.Org = asn
	}
	if ev.Org == "" {
		for _, err := range []error{iiErr, ripeErr} {
			if err != nil {
				ev.Errors = append(ev.Errors, err.Error())
			}
		}
	}
}

type traceResult struct{ ip, loc, colo, source string }

// raceTrace queries every endpoint at once and returns the first valid
// answer, cancelling the rest, plus the failures seen before it.
func raceTrace(ctx context.Context, client *http.Client, urls []string) (traceResult, []error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type reply struct {
		tr  traceResult
		err error
	}
	replies := make(chan reply, len(urls))
	for _, u := range urls {
		go func() {
			body, err := fetchSmall(ctx, client, u)
			if err != nil {
				replies <- reply{err: err}
				return
			}
			tr := parseTrace(body)
			if _, perr := netip.ParseAddr(tr.ip); perr != nil {
				replies <- reply{err: errors.New(u + ": no ip in trace")}
				return
			}
			tr.source = u
			replies <- reply{tr: tr}
		}()
	}
	var errs []error
	for range urls {
		r := <-replies
		if r.err == nil {
			return r.tr, errs
		}
		errs = append(errs, r.err)
	}
	return traceResult{}, errs
}

func parseTrace(body []byte) traceResult {
	var tr traceResult
	for line := range strings.SplitSeq(string(body), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ip":
			tr.ip = v
		case "loc":
			tr.loc = v
		case "colo":
			tr.colo = v
		}
	}
	return tr
}

// ripeHolder returns the announcing network as "AS<n> <holder>".
func ripeHolder(ctx context.Context, client *http.Client, url string) (string, error) {
	body, err := fetchSmall(ctx, client, url)
	if err != nil {
		return "", err
	}
	var r struct {
		Data struct {
			ASNs []struct {
				ASN    int    `json:"asn"`
				Holder string `json:"holder"`
			} `json:"asns"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", err
	}
	if len(r.Data.ASNs) == 0 {
		return "", errors.New(url + ": no announcing ASN")
	}
	a := r.Data.ASNs[0]
	return strings.TrimSpace(fmt.Sprintf("AS%d %s", a.ASN, a.Holder)), nil
}

func fetchSmall(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(url + ": " + resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<10))
}

func systemResolvers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}
