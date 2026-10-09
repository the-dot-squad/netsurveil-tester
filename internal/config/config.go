// Package config parses and validates the node's environment configuration.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	// SecretSize is the required length of a node secret in bytes.
	SecretSize = 32
	// MaxFeedURLs bounds FEED_URLS.
	MaxFeedURLs = 8
)

var (
	nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	prefixPattern = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)
)

// DefaultHealthAddr is the loopback listener that serves /healthz.
const DefaultHealthAddr = "127.0.0.1:8099"

// Node is the nst-node runtime configuration.
type Node struct {
	ID              string
	Secret          []byte
	ListenAddr      string // empty disables inbound mode
	HealthAddr      string // loopback listener for /healthz; empty disables it
	PathPrefix      string
	FeedURLs        []string // mirrors of the node's request feed; empty disables pull mode
	AllowPrivate    bool
	RateLimitPerMin int
	TrustedProxies  []netip.Prefix // proxies whose X-Forwarded-For names the client
	LogLevel        string         // debug, info, warn or error
}

// LoadNode reads node configuration through getenv (usually os.Getenv).
func LoadNode(getenv func(string) string) (Node, error) {
	cfg := Node{
		ID:         strings.TrimSpace(getenv("NODE_ID")),
		PathPrefix: strings.TrimSpace(getenv("HTTP_PATH_PREFIX")),
	}
	if !ValidNodeID(cfg.ID) {
		return cfg, errors.New("NODE_ID must match [A-Za-z0-9._-]{1,64}")
	}

	var err error
	if cfg.Secret, err = ParseSecret(getenv("NODE_SECRET")); err != nil {
		return cfg, fmt.Errorf("NODE_SECRET: %w", err)
	}

	if cfg.ListenAddr, err = listenAddr(getenv("LISTEN_ADDR"), getenv("NODE_PORT")); err != nil {
		return cfg, err
	}
	cfg.HealthAddr = addrOrOff(getenv("HEALTH_ADDR"), DefaultHealthAddr)
	if cfg.HealthAddr != "" {
		host, _, err := net.SplitHostPort(cfg.HealthAddr)
		if ip, perr := netip.ParseAddr(host); err != nil || perr != nil || !ip.IsLoopback() {
			return cfg, errors.New(`HEALTH_ADDR must be a loopback IP:port such as 127.0.0.1:8099, or "off"`)
		}
	}

	switch lvl := strings.ToLower(strings.TrimSpace(getenv("LOG_LEVEL"))); lvl {
	case "":
		cfg.LogLevel = "info"
	case "debug", "info", "warn", "error":
		cfg.LogLevel = lvl
	default:
		return cfg, errors.New("LOG_LEVEL must be debug, info, warn or error")
	}

	if cfg.PathPrefix != "" && !prefixPattern.MatchString(cfg.PathPrefix) {
		return cfg, errors.New("HTTP_PATH_PREFIX must look like /segment[/segment...] without a trailing slash")
	}

	if cfg.FeedURLs, err = parseFeedURLs(getenv("FEED_URLS")); err != nil {
		return cfg, fmt.Errorf("FEED_URLS: %w", err)
	}

	if cfg.ListenAddr == "" && len(cfg.FeedURLs) == 0 {
		return cfg, errors.New("nothing to do: enable NODE_PORT, set FEED_URLS, or both")
	}

	if cfg.AllowPrivate, err = parseBool(getenv("ALLOW_PRIVATE_TARGETS"), false); err != nil {
		return cfg, fmt.Errorf("ALLOW_PRIVATE_TARGETS: %w", err)
	}
	if cfg.RateLimitPerMin, err = parsePositiveInt(getenv("RATE_LIMIT_PER_MIN"), 30); err != nil {
		return cfg, fmt.Errorf("RATE_LIMIT_PER_MIN: %w", err)
	}
	if cfg.TrustedProxies, err = parsePrefixes(getenv("TRUSTED_PROXIES")); err != nil {
		return cfg, fmt.Errorf("TRUSTED_PROXIES: %w", err)
	}
	return cfg, nil
}

// listenAddr picks the inbound listener: LISTEN_ADDR when set (an advanced
// override for binding one interface), otherwise ":"+NODE_PORT, default
// :8080. "off" in either disables inbound mode.
func listenAddr(addr, port string) (string, error) {
	if strings.TrimSpace(addr) != "" {
		return addrOrOff(addr, ""), nil
	}
	switch port = strings.TrimSpace(port); port {
	case "":
		return ":8080", nil
	case "off":
		return "", nil
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", errors.New(`NODE_PORT must be a port number (1-65535) or "off"`)
	}
	return ":" + port, nil
}

// parsePrefixes splits a comma-separated list of IPs and CIDRs.
func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for raw := range strings.SplitSeq(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if ip, err := netip.ParseAddr(raw); err == nil {
			ip = ip.Unmap()
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP or CIDR", raw)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// addrOrOff returns def for an empty value and "" for "off".
func addrOrOff(v, def string) string {
	switch v = strings.TrimSpace(v); v {
	case "":
		return def
	case "off":
		return ""
	}
	return v
}

// ValidNodeID reports whether id is an acceptable node identifier.
func ValidNodeID(id string) bool { return nodeIDPattern.MatchString(id) }

// ParseSecret decodes a 32-byte secret given as 64 hex chars or standard/URL base64.
func ParseSecret(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("missing")
	}
	if len(s) == 2*SecretSize {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != SecretSize {
				return nil, fmt.Errorf("must decode to %d bytes, got %d", SecretSize, len(b))
			}
			return b, nil
		}
	}
	return nil, errors.New("must be 64 hex chars or base64 of 32 bytes")
}

// parseFeedURLs splits a comma-separated list of absolute http(s) object URLs.
func parseFeedURLs(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for raw := range strings.SplitSeq(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path == "" || u.Path == "/" {
			return nil, fmt.Errorf("%q is not an absolute http(s) object URL", raw)
		}
		if seen[raw] {
			return nil, fmt.Errorf("%q is listed twice", raw)
		}
		seen[raw] = true
		out = append(out, raw)
	}
	if len(out) > MaxFeedURLs {
		return nil, fmt.Errorf("at most %d URLs", MaxFeedURLs)
	}
	return out, nil
}

func parseBool(s string, def bool) (bool, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	return strconv.ParseBool(strings.TrimSpace(s))
}

func parsePositiveInt(s string, def int) (int, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, errors.New("must be a positive integer")
	}
	return n, nil
}
