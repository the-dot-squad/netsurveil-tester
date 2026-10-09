package check

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/the-dot-squad/netsurveil-tester/internal/netguard"
)

const maxBodyBytes = 256 << 10

// UserAgent is the desktop browser identity every outbound HTTP request presents.
const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

var errRedirectSinkhole = errors.New("redirected to a sinkhole or private address")

type webOptions struct {
	Insecure bool `json:"insecure"`
	dnsControls
}

type webEvidence struct {
	URL  string      `json:"url"`
	IP   string      `json:"ip,omitempty"`
	DNS  []dnsAnswer `json:"dns,omitempty"`
	TLS  *tlsInfo    `json:"tls,omitempty"`
	HTTP *httpInfo   `json:"http,omitempty"`
}

type tlsInfo struct {
	Version   string `json:"version"`
	ALPN      string `json:"alpn,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	CertValid bool   `json:"cert_valid"`
	CertError string `json:"cert_error,omitempty"`
	Fallback  bool   `json:"std_tls_fallback,omitempty"`
}

type httpInfo struct {
	Status     int      `json:"status,omitempty"`
	Title      string   `json:"title,omitempty"`
	BodyLen    int      `json:"body_len"`
	BodySHA256 string   `json:"body_sha256,omitempty"`
	Server     string   `json:"server,omitempty"`
	Redirects  []string `json:"redirects,omitempty"`
}

func prepareWeb(env *Env, target string, raw json.RawMessage, _ time.Duration) (execFunc, error) {
	var o webOptions
	if err := decodeOptions(raw, &o); err != nil {
		return nil, err
	}
	if err := o.validate(); err != nil {
		return nil, err
	}
	u, err := parseWebURL(target)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) outcome { return runWeb(ctx, env, u, o) }, nil
}

func parseWebURL(target string) (*url.URL, error) {
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return nil, errors.New("target must be an http(s) URL or hostname")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid port")
		}
	}
	return u, nil
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

func runWeb(ctx context.Context, env *Env, u *url.URL, o webOptions) outcome {
	host, port := u.Hostname(), portOf(u)
	ev := &webEvidence{URL: u.String()}
	out := outcome{evidence: ev}
	finish := func(v Verdict, mech string) outcome {
		out.verdict, out.mechanism = v, mech
		return out
	}

	var ip netip.Addr
	var dnsAnomaly string
	if lit, err := netip.ParseAddr(host); err == nil {
		ip = lit.Unmap()
	} else {
		local := systemLookup(ctx, host, 0)
		controls := raceControls(ctx, o.lookups(env, host, 0))
		ev.DNS = append([]dnsAnswer{local}, controls...)
		st := Stage{Name: "dns", OK: local.ok(), Ms: local.Ms, Error: local.Error}
		if local.RCode == "NXDOMAIN" {
			st.Error = "NXDOMAIN"
		}
		out.stages = append(out.stages, st)

		v, mech := judgeDNS([]dnsAnswer{local}, controls, nil)
		switch v {
		case OK:
		case Anomaly:
			dnsAnomaly = mech
		default:
			return finish(v, mech)
		}
		addrs := parseAddrs(local.Addrs)
		var allowed []netip.Addr
		for _, a := range addrs {
			if env.Guard.Allowed(a) {
				allowed = append(allowed, a)
			}
		}
		if len(allowed) == 0 {
			if anyNonPublic(addrs) {
				return finish(Blocked, "dns_private_answer")
			}
			out.err = netguard.ErrForbidden.Error()
			return finish(Error, "forbidden_target")
		}
		ip = preferV4(allowed)
	}
	if !env.Guard.Allowed(ip) {
		out.err = netguard.ErrForbidden.Error()
		return finish(Error, "forbidden_target")
	}
	ev.IP = ip.String()
	addr := net.JoinHostPort(ip.String(), port)
	dialer := env.Guard.Dialer(8 * time.Second)

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	out.stages = append(out.stages, stage("tcp", start, err))
	if err != nil {
		return finish(judgeStageErr("tcp", err))
	}

	if u.Scheme == "https" {
		start = time.Now()
		info, err := tlsProbe(ctx, dialer, conn, addr, host)
		out.stages = append(out.stages, stage("tls", start, err))
		if err != nil {
			return finish(judgeStageErr("tls", err))
		}
		ev.TLS = info
	} else {
		_ = conn.Close()
	}

	start = time.Now()
	// Servers that refused the Chrome fingerprint in the tls stage get the standard stack.
	hinfo, body, hdr, err := httpFetch(ctx, env, u, addr, ip, ev.TLS == nil || !ev.TLS.Fallback)
	ev.HTTP = hinfo
	out.stages = append(out.stages, stage("http", start, err))
	if err != nil {
		if errors.Is(err, errRedirectSinkhole) {
			return finish(Blocked, "http_redirect_sinkhole")
		}
		return finish(judgeStageErr("http", err))
	}

	switch {
	case hinfo.Status == http.StatusUnavailableForLegalReasons:
		return finish(Blocked, "http_451")
	case looksLikeBlockPage(body, hdr):
		return finish(Blocked, "http_blockpage")
	case hinfo.Status == http.StatusForbidden && looksLikeForbiddenBlock(body):
		return finish(Blocked, "http_blockpage")
	case ev.TLS != nil && !ev.TLS.CertValid && !o.Insecure:
		return finish(Anomaly, "tls_invalid_cert")
	case dnsAnomaly != "" && (ev.TLS == nil || !ev.TLS.CertValid):
		// A valid certificate for the name proves the differing DNS answer genuine.
		return finish(Anomaly, dnsAnomaly)
	}
	return finish(OK, "")
}

// tlsProbe performs a Chrome-fingerprinted handshake on conn (and closes it).
// Server-side quirks with the uTLS fingerprint are confirmed with the standard
// stack before being reported, so only interference survives as an error.
func tlsProbe(ctx context.Context, dialer *net.Dialer, conn net.Conn, addr, host string) (*tlsInfo, error) {
	sni := host
	if _, err := netip.ParseAddr(host); err == nil {
		sni = ""
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	uc := utls.UClient(conn, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloChrome_Auto) // certificate verified in describeTLS
	err := uc.HandshakeContext(ctx)
	if err == nil {
		st := uc.ConnectionState()
		_ = uc.Close()
		return describeTLS(st.Version, st.NegotiatedProtocol, st.PeerCertificates, host), nil
	}
	_ = uc.Close()
	if k := classifyErr(err); k != kindOther && k != kindAlert {
		return nil, err
	}

	conn2, err2 := dialer.DialContext(ctx, "tcp", addr)
	if err2 != nil {
		return nil, err
	}
	_ = conn2.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(conn2, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // verified below
	defer tc.Close()
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	st := tc.ConnectionState()
	info := describeTLS(st.Version, st.NegotiatedProtocol, st.PeerCertificates, host)
	info.Fallback = true
	return info, nil
}

func describeTLS(version uint16, alpn string, certs []*x509.Certificate, host string) *tlsInfo {
	info := &tlsInfo{Version: tls.VersionName(version), ALPN: alpn}
	if len(certs) == 0 {
		info.CertError = "no certificate presented"
		return info
	}
	leaf := certs[0]
	info.Subject, info.Issuer = leaf.Subject.String(), leaf.Issuer.String()
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err != nil {
		info.CertError = err.Error()
	} else {
		info.CertValid = true
	}
	return info
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// chromeDialTLS returns a DialTLSContext presenting the Chrome fingerprint, so
// the HTTP stage looks like the tls stage to DPI. ALPN offers only http/1.1
// because the transport cannot speak h2 over a non-crypto/tls connection.
func chromeDialTLS(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
		if err != nil {
			return nil, err
		}
		for _, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
			}
		}
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		sni := host
		if _, err := netip.ParseAddr(host); err == nil {
			sni = ""
		}
		uc := utls.UClient(conn, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloCustom) // certificate judged in the tls stage
		if err := uc.ApplyPreset(&spec); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if err := uc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return uc, nil
	}
}

// httpFetch GETs u with the first connection pinned to addr (the address the
// DNS stage chose), over the Chrome fingerprint unless chromeTLS is false.
// Redirect hops are recorded; a hop to a sinkhole, or to a private address
// when the target itself was public, is an injected redirect.
func httpFetch(ctx context.Context, env *Env, u *url.URL, addr string, targetIP netip.Addr, chromeTLS bool) (*httpInfo, []byte, http.Header, error) {
	info := &httpInfo{}
	client := env.Guard.PinnedHTTPClient(true, net.JoinHostPort(u.Hostname(), portOf(u)), addr) // certificate judged in the tls stage
	if chromeTLS {
		tr := client.Transport.(*http.Transport)
		tr.DialTLSContext = chromeDialTLS(tr.DialContext)
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		info.Redirects = append(info.Redirects, req.URL.String())
		if ip, err := netip.ParseAddr(req.URL.Hostname()); err == nil {
			if isSinkhole(ip) || (!netguard.IsPublic(ip) && netguard.IsPublic(targetIP)) {
				return errRedirectSinkhole
			}
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return info, nil, nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return info, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	info.Status = resp.StatusCode
	info.Server = resp.Header.Get("Server")
	info.BodyLen = len(body)
	if err != nil && len(body) == 0 {
		return info, nil, resp.Header, fmt.Errorf("reading body: %w", err)
	}
	sum := sha256.Sum256(body)
	info.BodySHA256 = hex.EncodeToString(sum[:8])
	if m := titleRe.FindSubmatch(body); m != nil {
		t := strings.TrimSpace(string(m[1]))
		if len(t) > 200 {
			t = t[:200]
		}
		info.Title = t
	}
	return info, body, resp.Header, nil
}
