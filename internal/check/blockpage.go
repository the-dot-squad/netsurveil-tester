package check

import (
	"net/http"
	"strings"
)

// Multi-word, ISP/state-specific phrases only: single tokens such as "blocked"
// appear in ordinary pages and produce false positives.
var blockPhrases = []string{
	"unavailable for legal reasons",
	"this site has been blocked",
	"this website has been blocked",
	"access to this website has been blocked",
	"access to this site has been blocked",
	"access to this resource has been restricted",
	"your internet service provider has blocked",
	"blocked by your network administrator",
	"blocked by your organisation",
	"blocked by your organization",
	"blocked by order of",
	"web filter alert",
	"internet watch foundation",
	"sanctioned by the government",
	"according to the laws of the islamic republic",
	"доступ к ресурсу ограничен",
	"доступ ограничен",
	"این سایت مسدود",
	"دسترسی شما به این سایت",
	"سایت مورد نظر در لیست سیاه",
	"peyvandha.ir",
	"erişim engellendi",
	"bu siteye erişim",
}

var middleboxHints = []string{"webfilter", "fortiguard", "bluecoat", "websense", "netsweeper", "nproxy", "netpass"}

// maxBlockPageBody is the largest body scanned in full. Injected block pages
// are small; a larger page that quotes a block phrase (a news article about
// censorship, say) is judged by its title alone.
const maxBlockPageBody = 32 << 10

func looksLikeBlockPage(body []byte, h http.Header) bool {
	text := body
	if len(body) > maxBlockPageBody {
		text = nil
		if m := titleRe.FindSubmatch(body); m != nil {
			text = m[1]
		}
	}
	s := strings.ToLower(string(text))
	for _, p := range blockPhrases {
		if strings.Contains(s, p) {
			return true
		}
	}
	server, via := strings.ToLower(h.Get("Server")), strings.ToLower(h.Get("Via"))
	for _, hint := range middleboxHints {
		if strings.Contains(server, hint) || strings.Contains(via, hint) {
			return true
		}
	}
	return false
}

// looksLikeForbiddenBlock separates censor-injected 403s (tiny opaque bodies)
// from ordinary WAF and login 403s, which are common and not censorship.
// Callers check looksLikeBlockPage first.
func looksLikeForbiddenBlock(body []byte) bool {
	if len(body) > 0 && len(body) < 512 {
		s := strings.ToLower(string(body))
		return strings.Contains(s, "blocked") || strings.Contains(s, "forbidden") || strings.Contains(s, "denied")
	}
	return false
}
