package check

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

// Addressed by IP so the lookup works even when local DNS is tampered with.
const (
	cloudflareTraceURL = "https://1.1.1.1/cdn-cgi/trace"
	ipinfoURL          = "https://ipinfo.io/json"
)

type infoEvidence struct {
	NodeID    string   `json:"node_id"`
	Version   string   `json:"version"`
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	PublicIP  string   `json:"public_ip,omitempty"`
	Country   string   `json:"country,omitempty"`
	City      string   `json:"city,omitempty"`
	Org       string   `json:"org,omitempty"`
	Colo      string   `json:"cloudflare_colo,omitempty"`
	Resolvers []string `json:"resolvers,omitempty"`
	RawICMP   bool     `json:"raw_icmp"`
	Errors    []string `json:"errors,omitempty"`
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
		var mu sync.Mutex
		var wg sync.WaitGroup
		fail := func(err error) {
			mu.Lock()
			ev.Errors = append(ev.Errors, err.Error())
			mu.Unlock()
		}
		wg.Go(func() {
			body, err := fetchSmall(ctx, client, cloudflareTraceURL)
			if err != nil {
				fail(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for line := range strings.SplitSeq(string(body), "\n") {
				k, v, _ := strings.Cut(line, "=")
				switch k {
				case "ip":
					ev.PublicIP = v
				case "loc":
					ev.Country = v
				case "colo":
					ev.Colo = v
				}
			}
		})
		wg.Go(func() {
			body, err := fetchSmall(ctx, client, ipinfoURL)
			if err != nil {
				fail(err)
				return
			}
			var r struct{ IP, City, Country, Org string }
			if err := json.Unmarshal(body, &r); err != nil {
				fail(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			ev.Org, ev.City = r.Org, r.City
			if ev.PublicIP == "" {
				ev.PublicIP = r.IP
			}
			if ev.Country == "" {
				ev.Country = r.Country
			}
		})
		wg.Wait()
		if ev.PublicIP == "" {
			return outcome{verdict: Unreachable, mechanism: "public_lookup_failed", evidence: ev}
		}
		return outcome{verdict: OK, evidence: ev}
	}, nil
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
