package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	defaultThrottleControl = "https://speed.cloudflare.com/__down?bytes=10000000"
	bucketWidth            = 250 * time.Millisecond
	stallThreshold         = 2 * time.Second
	minJudgedBytes         = 256 << 10
	capRatio               = 0.2
)

type throttleOptions struct {
	ControlURL string `json:"control_url"`
	MaxBytes   int64  `json:"max_bytes"`
	DurationS  int    `json:"duration_s"`
	Insecure   bool   `json:"insecure"`
}

type transferSample struct {
	URL        string  `json:"url"`
	Status     int     `json:"status,omitempty"`
	Bytes      int64   `json:"bytes"`
	TTFBMs     int64   `json:"ttfb_ms,omitempty"`
	TransferMs int64   `json:"transfer_ms,omitempty"`
	Mbps       float64 `json:"mbps"`
	Complete   bool    `json:"complete"`
	Buckets    []int64 `json:"buckets_250ms"`
	Error      string  `json:"error,omitempty"`
	err        error
	reset      bool
}

type throttleEvidence struct {
	Target  transferSample `json:"target"`
	Control transferSample `json:"control"`
	Ratio   float64        `json:"ratio,omitempty"`
	Note    string         `json:"note,omitempty"`
}

func prepareThrottle(env *Env, target string, raw json.RawMessage, budget time.Duration) (execFunc, error) {
	o := throttleOptions{ControlURL: defaultThrottleControl, MaxBytes: 5 << 20, DurationS: 10}
	if err := decodeOptions(raw, &o); err != nil {
		return nil, err
	}
	if _, err := parseWebURL(target); err != nil {
		return nil, err
	}
	if u, err := url.Parse(o.ControlURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("control_url must be an http(s) URL")
	}
	if o.MaxBytes < 64<<10 || o.MaxBytes > 10<<20 || o.DurationS < 2 || o.DurationS > 20 {
		return nil, errors.New("max_bytes 64KiB-10MiB, duration_s 2-20")
	}
	targetURL, _ := parseWebURL(target)
	dur := time.Duration(o.DurationS) * time.Second
	// The control and the target transfer run one after the other.
	if err := fitBudget(resolveSlack+2*dur, budget); err != nil {
		return nil, err
	}

	return func(ctx context.Context) outcome {
		client := env.Guard.HTTPClient(o.Insecure)
		ev := &throttleEvidence{}
		// Sequential so the two transfers do not compete for the same link.
		ev.Control = measureTransfer(ctx, client, o.ControlURL, o.MaxBytes, dur)
		ev.Target = measureTransfer(ctx, client, targetURL.String(), o.MaxBytes, dur)
		if ev.Control.Mbps > 0 {
			ev.Ratio = round2(ev.Target.Mbps / ev.Control.Mbps)
		}
		v, mech := judgeThrottle(ev.Target, ev.Control)
		if v == OK && ev.Target.Complete && ev.Target.Bytes < minJudgedBytes {
			ev.Note = "target transfer too small to judge bandwidth"
		}
		out := outcome{verdict: v, mechanism: mech, evidence: ev}
		if ev.Target.err != nil && ev.Target.Bytes == 0 {
			out.stages = []Stage{{Name: "http", Error: ev.Target.Error}}
		}
		return out
	}, nil
}

func measureTransfer(ctx context.Context, client *http.Client, rawURL string, maxBytes int64, dur time.Duration) transferSample {
	s := transferSample{URL: rawURL, Buckets: []int64{}}
	ctx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		s.setErr(err)
		return s
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		s.setErr(err)
		return s
	}
	defer resp.Body.Close()
	s.Status = resp.StatusCode
	if resp.StatusCode >= 400 {
		s.setErr(fmt.Errorf("http status %d", resp.StatusCode))
		return s
	}

	buf := make([]byte, 32<<10)
	var first, last time.Time
	for s.Bytes < maxBytes {
		n, err := resp.Body.Read(buf[:min(int64(len(buf)), maxBytes-s.Bytes)])
		if n > 0 {
			last = time.Now()
			if first.IsZero() {
				first = last
				s.TTFBMs = first.Sub(start).Milliseconds()
			}
			idx := int(last.Sub(first) / bucketWidth)
			for len(s.Buckets) <= idx {
				s.Buckets = append(s.Buckets, 0)
			}
			s.Buckets[idx] += int64(n)
			s.Bytes += int64(n)
		}
		if errors.Is(err, io.EOF) {
			s.Complete = true
			break
		}
		if err != nil {
			if ctx.Err() == nil {
				s.setErr(err)
				s.reset = classifyErr(err) == kindRST
			}
			break
		}
	}
	if s.Bytes >= maxBytes {
		s.Complete = true
	}
	if first.IsZero() {
		if s.err == nil {
			s.setErr(context.DeadlineExceeded)
		}
		return s
	}
	end := last
	if !s.Complete {
		// Extend the series to the deadline so a stall shows as trailing empty buckets.
		end = time.Now()
		for len(s.Buckets) <= int(end.Sub(first)/bucketWidth) {
			s.Buckets = append(s.Buckets, 0)
		}
	}
	s.TransferMs = end.Sub(first).Milliseconds()
	if secs := end.Sub(first).Seconds(); secs > 0 {
		s.Mbps = round2(float64(s.Bytes) * 8 / secs / 1e6)
	}
	return s
}

func (s *transferSample) setErr(err error) {
	s.err, s.Error = err, err.Error()
}

// judgeThrottle compares a target transfer with a control transfer from the
// same node. A stall after some bytes is the signature of TLS-aware throttling;
// a large sustained gap to the control is a bandwidth cap.
func judgeThrottle(target, control transferSample) (Verdict, string) {
	if target.err != nil && target.Bytes == 0 {
		return judgeStageErr("http", target.err)
	}
	if target.reset && !target.Complete {
		return Blocked, "http_rst_midstream"
	}
	if !target.Complete && target.Bytes > 0 && trailingIdle(target.Buckets) >= stallThreshold {
		return Throttled, "stall_after_bytes"
	}
	if control.Bytes == 0 || control.Mbps <= 0 {
		return Error, "control_failed"
	}
	if target.Complete && target.Bytes < minJudgedBytes {
		return OK, ""
	}
	if target.Mbps < capRatio*control.Mbps {
		return Throttled, "bandwidth_cap"
	}
	return OK, ""
}

func trailingIdle(buckets []int64) time.Duration {
	n := 0
	for i := len(buckets) - 1; i >= 0 && buckets[i] == 0; i-- {
		n++
	}
	return time.Duration(n) * bucketWidth
}
