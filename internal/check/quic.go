package check

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

type quicOptions struct {
	Insecure  bool `json:"insecure"`
	AssumeH3  bool `json:"assume_h3"`
	TimeoutMs int  `json:"timeout_ms"`
}

type quicEvidence struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	TCPOK       bool   `json:"tcp_tls_ok"`
	TCPError    string `json:"tcp_tls_error,omitempty"`
	AltSvc      string `json:"alt_svc,omitempty"`
	AdvertiseH3 bool   `json:"advertises_h3"`
	QUICOK      bool   `json:"quic_ok"`
	QUICMs      int64  `json:"quic_ms"`
	QUICError   string `json:"quic_error,omitempty"`
	QUICVersion string `json:"quic_version,omitempty"`
}

func prepareQUIC(env *Env, target string, raw json.RawMessage, _ time.Duration) (execFunc, error) {
	o := quicOptions{TimeoutMs: 8000}
	if err := decodeOptions(raw, &o); err != nil {
		return nil, err
	}
	u, err := parseWebURL(target)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, errors.New("quic target must be https")
	}
	if o.TimeoutMs < 1000 || o.TimeoutMs > 15000 {
		return nil, errors.New("timeout_ms must be within 1000-15000")
	}
	port, _ := strconv.Atoi(portOf(u))
	timeout := time.Duration(o.TimeoutMs) * time.Millisecond

	return func(ctx context.Context) outcome {
		addrs, fail := resolveTarget(ctx, env, u.Hostname())
		if fail != nil {
			return *fail
		}
		ip := preferV4(addrs)
		ev := &quicEvidence{IP: ip.String(), Port: port}
		out := outcome{evidence: ev}

		start := time.Now()
		altSvc, err := fetchAltSvc(ctx, env, u, net.JoinHostPort(ip.String(), strconv.Itoa(port)), o.Insecure, timeout)
		out.stages = append(out.stages, stage("tcp_tls", start, err))
		ev.TCPOK, ev.AltSvc = err == nil, altSvc
		if err != nil {
			ev.TCPError = err.Error()
		}
		ev.AdvertiseH3 = strings.Contains(altSvc, "h3")

		start = time.Now()
		version, err := quicHandshake(ctx, &net.UDPAddr{IP: ip.AsSlice(), Port: port}, u.Hostname(), timeout)
		out.stages = append(out.stages, stage("quic", start, err))
		ev.QUICMs = time.Since(start).Milliseconds()
		ev.QUICOK, ev.QUICVersion = err == nil, version
		if err != nil {
			ev.QUICError = err.Error()
		}

		switch {
		case ev.QUICOK:
			out.verdict = OK
		case !ev.TCPOK:
			out.verdict, out.mechanism = Unreachable, "tcp_and_quic_failed"
		case ev.AdvertiseH3 || o.AssumeH3:
			out.verdict, out.mechanism = Blocked, "quic_drop"
			if classifyErr(err) != kindTimeout {
				out.mechanism = "quic_error"
			}
		default:
			out.verdict, out.mechanism = Unreachable, "quic_unsupported"
		}
		return out
	}, nil
}

func fetchAltSvc(ctx context.Context, env *Env, u *url.URL, addr string, insecure bool, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()
	client := env.Guard.PinnedHTTPClient(insecure, net.JoinHostPort(u.Hostname(), portOf(u)), addr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.Header.Get("Alt-Svc"), nil
}

// quicHandshake completes a QUIC handshake offering h3. Certificate validity is
// not judged here; the question is whether QUIC traffic passes at all.
func quicHandshake(ctx context.Context, addr *net.UDPAddr, host string, timeout time.Duration) (string, error) {
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return "", err
	}
	tr := &quic.Transport{Conn: udp}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := tr.Dial(ctx, addr, &tls.Config{ServerName: host, NextProtos: []string{"h3"}, InsecureSkipVerify: true}, &quic.Config{HandshakeIdleTimeout: timeout}) //nolint:gosec // reachability only
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	return conn.ConnectionState().Version.String(), nil
}
