/*
File:    idn_homograph.go
Version: 1.9.0
Last Updated: 17-Nov-2026 15:10 CET

Description:
  IDN Homograph, Punycode/ACE, Mixed-Script, and Confusable Skeleton detection
  engine for sdproxy.

  Defends against:
    1. Full IDN / ACE (`xn--`) and raw non-ASCII domain blocking (`block_all_idn`).
    2. Malformed Punycode / ACE labels (`xn--` that fail RFC 5891 / IDNA decoding).
    3. Unicode TR39 Mixed-Script labels (e.g. mixing Latin + Cyrillic or Greek
       within a single label, or combining non-ASCII marks).
    4. Whole-Script & Confusable Skeleton Homograph impersonation of built-in
       high-value brands (`vendorMap`, `dgaSafeDomains`, financial/crypto/cloud
       targets) and user-configured `protect` domains.
    5. Pure-ASCII visual lookalike impersonation (`ascii_lookalikes`: `paypa1`,
       `g00gle`, `rnicrosoft`, `vvhatsapp`, `clropbox`, `pay-pa1`) against
       protected brands.

Changes:
  1.9.0 - [SECURITY/FIX] Removed the blanket `if isCanonicalApex { continue }`
          exemption on non-SLD subdomain labels in Step 2 of `AnalyzeIDNHomograph`.
          Because `dgaSafeDomains` (including shared cloud/CDN domains such as
          `cloudfront.net` and `amazonaws.com`) is registered in `idnProtectedDomains`,
          blanket-skipping Step 2 whenever `isCanonicalApex` was true previously
          allowed lookalike subdomain labels impersonating unrelated brands
          (e.g. `paypa1.d123.cloudfront.net` or `g00gle.s3.amazonaws.com`) to
          bypass `ascii_lookalikes` detection.
  1.8.1 - [FIX] Fixed double-quoted `"ģ"` typo back to rune literal `'ģ'` in
          `confusableRuneMap`, and ensured exact canonical brand subdomain labels
          (where `brand.isAllowedSLD(label)` is true) are not falsely flagged as
          lookalike impersonations on non-SLD labels while non-ASCII IDN
          homographs and misspelled/hyphenated lookalikes on subdomain labels
          continue to be blocked.
  1.8.0 - [SECURITY/FIX] Removed the `idnProtectedSLDs[label] == ""` condition on
          non-SLD subdomain labels in Step 2 of `AnalyzeIDNHomograph` so a
          brand's hyphenated SLD variant (e.g. `apple-dns` from `apple-dns.net`)
          cannot be used as a subdomain label under an attacker apex to evade
          impersonation checks against the primary brand (`apple.com`).
  1.7.0 - [SECURITY/FIX] Tracked all canonical and unhyphenated SLD variants in
          `protectedBrand.allowedSLDs` (`registerProtectedDomain`) so multiple
          protected brands that collapse to the same confusable skeleton
          never overwrite each other's canonical SLD whitelist, and guarded
          Step 2 non-SLD subdomain lookalike checks when `idnProtectedDomains[qname]`
          is true.
  1.6.0 - [SECURITY/FIX] Removed the unhyphenated-SLD insertion from
          `idnProtectedSLDs` in `registerProtectedDomain` (introduced in 1.5.0).
  1.5.0 - [SECURITY/FIX] Indexed both hyphenated and unhyphenated brand SLD forms
          in `idnProtectedSLDs` (`registerProtectedDomain`) and skipped pure-ASCII
          subdomain lookalike checks when the queried domain is already under a
          protected canonical brand apex (`isCanonicalApex`).
  1.4.0 - [SECURITY/FIX] Separated exact full-domain whitelisting (`idnProtectedDomains`)
          from canonical brand SLD tracking (`idnProtectedSLDs`).
  1.3.0 - [SECURITY/FIX] Validated non-SLD subdomain labels for pure-ASCII
          confusable lookalike impersonation (`idnASCIILookalikes`) and rejected
          whole-script non-Latin IDN labels that confusably impersonate a
          protected brand even when the brand's exact TLD matches.
        - [FIX] Added `cacheHit` parameter to `applyIDNHomographVerdict`.
  1.2.0 - [SECURITY/FIX] Stripped hyphens (`-`) inside `computeConfusableSkeleton`
          and added `enforceIDNHomographCheck` on `queryCtx`.
  1.1.0 - [FEAT] Added `InitIDNHomograph()` startup initializer and wired
          `cfg.Server.IDNHomograph` configuration options.
*/

package main

import (
	"log"
	"strings"
	"unicode"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// scriptMask represents Unicode script categories in a bitmask per label.
type scriptMask uint16

const (
	scriptNone       scriptMask = 0
	scriptLatin      scriptMask = 1 << 0
	scriptCyrillic   scriptMask = 1 << 1
	scriptGreek      scriptMask = 1 << 2
	scriptArabic     scriptMask = 1 << 3
	scriptHebrew     scriptMask = 1 << 4
	scriptHan        scriptMask = 1 << 5
	scriptHiragana   scriptMask = 1 << 6
	scriptKatakana   scriptMask = 1 << 7
	scriptHangul     scriptMask = 1 << 8
	scriptDevanagari scriptMask = 1 << 9
	scriptThai       scriptMask = 1 << 10
	scriptArmenian   scriptMask = 1 << 11
	scriptGeorgian   scriptMask = 1 << 12
	scriptOther      scriptMask = 1 << 15

	// scriptJapaneseMask permits standard Japanese script combinations (Han + Hiragana + Katakana)
	// within a single IDN label per UTS #39 Highly Restrictive profile.
	scriptJapaneseMask = scriptHan | scriptHiragana | scriptKatakana
	// scriptKoreanMask permits standard Korean script combinations (Han + Hangul).
	scriptKoreanMask = scriptHan | scriptHangul
)

type protectedBrand struct {
	canonicalSLD    string
	unhyphenatedSLD string
	canonicalDomain string
	allowedSLDs     []string
}

func (b protectedBrand) isAllowedSLD(s string) bool {
	if s == b.canonicalSLD || s == b.unhyphenatedSLD {
		return true
	}
	for _, a := range b.allowedSLDs {
		if a == s {
			return true
		}
	}
	return false
}

var (
	idnAction          string
	idnActionCode      int
	idnBlockAll        bool
	idnMixedScript     bool
	idnASCIILookalikes bool

	// idnProtectedSkeletons maps a confusable skeleton string -> canonical brand info.
	idnProtectedSkeletons map[string]protectedBrand
	// idnProtectedDomains holds exact canonical full domains (e.g. "paypal.com") so
	// queries for the genuine brand apex or its subdomains return in O(1).
	idnProtectedDomains map[string]bool
	// idnProtectedSLDs maps a canonical brand SLD (e.g. "paypal") -> its primary
	// canonical domain ("paypal.com").
	idnProtectedSLDs map[string]string
	// idnExemptDomains holds user-configured exempted domains/suffixes.
	idnExemptDomains map[string]bool
)

// defaultProtectedDomains supplements vendorMap and dgaSafeDomains with high-value
// phishing targets (banking, payments, crypto, email, password managers, cloud/auth).
var defaultProtectedDomains = []string{
	// Payments & Banking
	"abnamro.nl",
	"adyen.com",
	"americanexpress.com",
	"asn.nl",
	"bankofamerica.com",
	"barclays.co.uk",
	"barclays.com",
	"bnpparibas.com",
	"bunq.com",
	"capitalone.com",
	"chase.com",
	"citibank.com",
	"citi.com",
	"commerzbank.de",
	"credit-agricole.fr",
	"deutsche-bank.de",
	"discover.com",
	"fidelity.com",
	"hsbc.co.uk",
	"hsbc.com",
	"ing.com",
	"ing.nl",
	"intesa.it",
	"jpmorgan.com",
	"klarna.com",
	"knab.nl",
	"lloydsbank.com",
	"mastercard.com",
	"monzo.com",
	"morganstanley.com",
	"n26.com",
	"natwest.com",
	"paypal.com",
	"rabobank.nl",
	"revolut.com",
	"royalbank.com",
	"santander.com",
	"schwab.com",
	"snsbank.nl",
	"societegenerale.fr",
	"sparkasse.de",
	"stripe.com",
	"triodos.nl",
	"ubs.com",
	"unicredit.eu",
	"vanguard.com",
	"venmo.com",
	"visa.com",
	"wellsfargo.com",
	"wise.com",

	// Crypto & Web3
	"binance.com",
	"bitfinex.com",
	"bitstamp.net",
	"blockchain.com",
	"bybit.com",
	"coinbase.com",
	"coingecko.com",
	"coinmarketcap.com",
	"crypto.com",
	"etherscan.io",
	"gemini.com",
	"kraken.com",
	"kucoin.com",
	"ledger.com",
	"metamask.io",
	"okx.com",
	"opensea.io",
	"phantom.app",
	"trezor.io",
	"trustwallet.com",
	"uniswap.org",

	// Identity, Security, Cloud & Productivity
	"1password.com",
	"auth0.com",
	"bitwarden.com",
	"box.com",
	"cisco.com",
	"crowdstrike.com",
	"dashlane.com",
	"digitalocean.com",
	"discord.com",
	"docusign.com",
	"duo.com",
	"fortinet.com",
	"gitlab.com",
	"gmx.com",
	"gmx.de",
	"godaddy.com",
	"hetzner.com",
	"keepersecurity.com",
	"lastpass.com",
	"linode.com",
	"mailchimp.com",
	"namecheap.com",
	"nordpass.com",
	"nordvpn.com",
	"notion.so",
	"okta.com",
	"onedrive.com",
	"outlook.com",
	"ovh.com",
	"paloaltonetworks.com",
	"postnl.nl",
	"proton.me",
	"protonmail.com",
	"sendgrid.com",
	"shopify.com",
	"signal.org",
	"snowflake.com",
	"squarespace.com",
	"teamviewer.com",
	"twilio.com",
	"vercel.com",
	"vultr.com",
	"web.de",
	"webflow.com",
	"zendesk.com",
	"zoho.com",

	// Government / National Auth (NL / EU / US)
	"belastingdienst.nl",
	"digid.nl",
	"gov.uk",
	"irs.gov",
	"mijnoverheid.nl",
	"overheid.nl",
	"rijksoverheid.nl",
	"usps.com",
}

// confusableRuneMap maps Unicode confusable code points (Cyrillic, Greek,
// Latin-Extended/diacritics, Fullwidth, IPA, and symbols) to their ASCII
// visual equivalents per Unicode UTS #39 confusables.
var confusableRuneMap = map[rune]string{
	// Cyrillic lowercase & uppercase visual lookalikes
	'а': "a", 'А': "a",
	'ă': "a", 'Ă': "a",
	'ä': "a", 'Ä': "a",
	'á': "a", 'Á': "a",
	'à': "a", 'À': "a",
	'â': "a", 'Â': "a",
	'ã': "a", 'Ã': "a",
	'å': "a", 'Å': "a",
	'ā': "a", 'Ā': "a",
	'ą': "a", 'Ą': "a",
	'ɑ': "a", 'α': "a", 'Α': "a",
	'ạ': "a", 'ả': "a", 'ấ': "a", 'ầ': "a", 'ẩ': "a", 'ẫ': "a", 'ậ': "a",
	'ắ': "a", 'ằ': "a", 'ẳ': "a", 'ẵ': "a", 'ặ': "a",

	'б': "b", 'Б': "b",
	'в': "b", 'В': "b",
	'β': "b", 'Β': "b",
	'Ь': "b", 'ь': "b",
	'Ъ': "b", 'ъ': "b",
	'ɓ': "b", 'ß': "ss",

	'с': "c", 'С': "c",
	'ϲ': "c", 'Ϲ': "c",
	'ç': "c", 'Ç': "c",
	'ć': "c", 'Ć': "c",
	'č': "c", 'Č': "c",
	'ĉ': "c", 'Ĉ': "c",
	'ċ': "c", 'Ċ': "c",

	'ԁ': "d", 'Ԁ': "d",
	'ď': "d", 'Ď': "d",
	'đ': "d", 'Đ': "d",
	'ð': "d", 'Ð': "d",
	'ḍ': "d",

	'е': "e", 'Е': "e",
	'ё': "e", 'Ё': "e",
	'є': "e", 'Є': "e",
	'ҽ': "e", 'Ҽ': "e",
	'é': "e", 'É': "e",
	'è': "e", 'È': "e",
	'ê': "e", 'Ê': "e",
	'ë': "e", 'Ë': "e",
	'ē': "e", 'Ē': "e",
	'ĕ': "e", 'Ĕ': "e",
	'ė': "e", 'Ė': "e",
	'ę': "e", 'Ę': "e",
	'ě': "e", 'Ě': "e",
	'ε': "e", 'Ε': "e",
	'ẹ': "e", 'ẻ': "e", 'ẽ': "e", 'ế': "e", 'ề': "e", 'ể': "e", 'ễ': "e", 'ệ': "e",

	'ғ': "f", 'Ғ': "f",
	'ƒ': "f",

	'ɡ': "g", 'ǵ': "g",
	'ğ': "g", 'Ğ': "g",
	'ġ': "g", 'Ġ': "g",
	'ģ': "g", 'Ģ': "g",
	'ĝ': "g", 'Ĝ': "g",

	'һ': "h", 'Һ': "h",
	'н': "h", 'Н': "h",
	'η': "n", 'Η': "h",
	'ĥ': "h", 'Ĥ': "h",
	'ħ': "h", 'Ħ': "h",

	'і': "l", 'І': "l",
	'ї': "l", 'Ї': "l",
	'ӏ': "l", 'Ӏ': "l",
	'ι': "l", 'Ι': "l",
	'í': "l", 'Í': "l",
	'ì': "l", 'Ì': "l",
	'î': "l", 'Î': "l",
	'ï': "l", 'Ï': "l",
	'ī': "l", 'Ī': "l",
	'ĭ': "l", 'Ĭ': "l",
	'į': "l", 'Į': "l",
	'ı': "l", 'İ': "l",
	'ị': "l", 'ỉ': "l", 'ĩ': "l",

	'ј': "j", 'Ј': "j",
	'ĵ': "j", 'Ĵ': "j",

	'к': "k", 'К': "k",
	'κ': "k", 'Κ': "k",
	'ķ': "k", 'Ķ': "k",
	'ĸ': "k", 'ќ': "k", 'Ќ': "k",

	'ⅼ': "l", 'Ⅼ': "l",
	'ĺ': "l", 'Ĺ': "l",
	'ļ': "l", 'Ļ': "l",
	'ľ': "l", 'Ľ': "l",
	'ł': "l", 'Ł': "l",

	'м': "m", 'М': "m",
	'μ': "m", 'Μ': "m",

	'п': "n",
	'ń': "n", 'Ń': "n",
	'ņ': "n", 'Ņ': "n",
	'ň': "n", 'Ň': "n",
	'ñ': "n", 'Ñ': "n",
	'Ν': "n",

	'о': "o", 'О': "o",
	'ӧ': "o", 'Ӧ': "o",
	'ө': "o", 'Ө': "o",
	'ο': "o", 'Ο': "o",
	'ω': "w", 'Ω': "o",
	'ó': "o", 'Ó': "o",
	'ò': "o", 'Ò': "o",
	'ô': "o", 'Ô': "o",
	'ö': "o", 'Ö': "o",
	'õ': "o", 'Õ': "o",
	'ø': "o", 'Ø': "o",
	'ō': "o", 'Ō': "o",
	'ŏ': "o", 'Ŏ': "o",
	'ő': "o", 'Ő': "o",
	'ọ': "o", 'ỏ': "o", 'ố': "o", 'ồ': "o", 'ổ': "o", 'ỗ': "o", 'ộ': "o",
	'ớ': "o", 'ờ': "o", 'ở': "o", 'ỡ': "o", 'ợ': "o", 'ơ': "o",

	'р': "p", 'Р': "p",
	'ρ': "p", 'Ρ': "p",

	'ԛ': "q", 'Ԛ': "q",

	'ŕ': "r", 'Ŕ': "r",
	'ŗ': "r", 'Ŗ': "r",
	'ř': "r", 'Ř': "r",
	'г': "r",

	'ѕ': "s", 'Ѕ': "s",
	'ś': "s", 'Ś': "s",
	'ŝ': "s", 'Ŝ': "s",
	'ş': "s", 'Ş': "s",
	'š': "s", 'Š': "s",
	'ș': "s", 'Ș': "s",

	'т': "t", 'Т': "t",
	'τ': "t", 'Τ': "t",
	'ţ': "t", 'Ţ': "t",
	'ť': "t", 'Ť': "t",
	'ŧ': "t", 'Ŧ': "t",
	'ț': "t", 'Ț': "t",

	'υ': "u", 'Υ': "y",
	'ц': "u",
	'ú': "u", 'Ú': "u",
	'ù': "u", 'Ù': "u",
	'û': "u", 'Û': "u",
	'ü': "u", 'Ü': "u",
	'ũ': "u", 'Ũ': "u",
	'ū': "u", 'Ū': "u",
	'ŭ': "u", 'Ŭ': "u",
	'ů': "u", 'Ů': "u",
	'ű': "u", 'Ű': "u",
	'ų': "u", 'Ų': "u",
	'ụ': "u", 'ủ': "u", 'ứ': "u", 'ừ': "u", 'ử': "u", 'ữ': "u", 'ự': "u", 'ư': "u",

	'ѵ': "v", 'Ѵ': "v",
	'ν': "v",

	'ԝ': "w", 'Ԝ': "w",
	'ŵ': "w", 'Ŵ': "w",
	'ш': "w", 'Ш': "w",
	'щ': "w", 'Щ': "w",

	'х': "x", 'Х': "x",
	'χ': "x", 'Χ': "x",

	'у': "y", 'У': "y",
	'ү': "y", 'Ү': "y",
	'ý': "y", 'Ý': "y",
	'ÿ': "y", 'Ÿ': "y",
	'ŷ': "y", 'Ŷ': "y",
	'γ': "y",

	'z': "z",
	'ź': "z", 'Ź': "z",
	'ż': "z", 'Ż': "z",
	'ž': "z", 'Ž': "z",
	'ζ': "z", 'Ζ': "z",
}

func init() {
	idnProtectedSkeletons = make(map[string]protectedBrand)
	idnProtectedDomains = make(map[string]bool)
	idnProtectedSLDs = make(map[string]string)
	idnExemptDomains = make(map[string]bool)
}

// InitIDNHomograph initializes the IDN Homograph, Punycode/ACE, Mixed-Script,
// and Confusable Skeleton protection subsystem from `cfg.Server.IDNHomograph`.
func InitIDNHomograph() {
	act := strings.ToUpper(strings.TrimSpace(cfg.Server.IDNHomograph.Action))
	switch act {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		hasIDNHomograph = false
		idnAction = "DISABLED"
		return
	case "LOG":
		idnAction = "LOG"
		idnActionCode = 0
	case "DROP":
		idnAction = "DROP"
		idnActionCode = PolicyActionDrop
	case "BLOCK":
		idnAction = "BLOCK"
		idnActionCode = PolicyActionBlock
	default:
		rc, ok := dns.StringToRcode[act]
		if !ok {
			if logSystem {
				log.Printf("[IDN-HOMOGRAPH] WARNING: unknown server.idn_homograph.action %q — disabling feature", cfg.Server.IDNHomograph.Action)
			}
			hasIDNHomograph = false
			idnAction = "DISABLED"
			return
		}
		idnAction = act
		idnActionCode = rc
	}

	idnBlockAll = cfg.Server.IDNHomograph.BlockAllIDN

	idnMixedScript = true
	if cfg.Server.IDNHomograph.MixedScript != nil {
		idnMixedScript = *cfg.Server.IDNHomograph.MixedScript
	}

	idnASCIILookalikes = true
	if cfg.Server.IDNHomograph.ASCIILookalikes != nil {
		idnASCIILookalikes = *cfg.Server.IDNHomograph.ASCIILookalikes
	}

	buildProtectedBrandTables(cfg.Server.IDNHomograph.Protect, cfg.Server.IDNHomograph.Exempt)
	hasIDNHomograph = true

	if logSystem {
		log.Printf("[IDN-HOMOGRAPH] Active (Action: %s, BlockAllIDN: %v, MixedScript: %v, ASCIILookalikes: %v, ProtectedSkeletons: %d, UserProtected: %d, Exempt: %d)",
			idnAction, idnBlockAll, idnMixedScript, idnASCIILookalikes,
			len(idnProtectedSkeletons), len(cfg.Server.IDNHomograph.Protect), len(idnExemptDomains))
	}
}

// runeScript classifies a Unicode code point into its script bitmask.
func runeScript(r rune) scriptMask {
	if r <= 0x7F {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return scriptLatin
		}
		return scriptNone // digits, hyphen, underscore, dot are Common/Inherited
	}
	switch {
	case unicode.Is(unicode.Latin, r):
		return scriptLatin
	case unicode.Is(unicode.Cyrillic, r):
		return scriptCyrillic
	case unicode.Is(unicode.Greek, r):
		return scriptGreek
	case unicode.Is(unicode.Arabic, r):
		return scriptArabic
	case unicode.Is(unicode.Hebrew, r):
		return scriptHebrew
	case unicode.Is(unicode.Han, r):
		return scriptHan
	case unicode.Is(unicode.Hiragana, r):
		return scriptHiragana
	case unicode.Is(unicode.Katakana, r):
		return scriptKatakana
	case unicode.Is(unicode.Hangul, r):
		return scriptHangul
	case unicode.Is(unicode.Devanagari, r):
		return scriptDevanagari
	case unicode.Is(unicode.Thai, r):
		return scriptThai
	case unicode.Is(unicode.Armenian, r):
		return scriptArmenian
	case unicode.Is(unicode.Georgian, r):
		return scriptGeorgian
	case unicode.Is(unicode.Mn, r), unicode.Is(unicode.Mc, r), unicode.Is(unicode.Me, r):
		return scriptOther
	default:
		if unicode.IsLetter(r) {
			return scriptOther
		}
		return scriptNone
	}
}

// isMixedScriptMask reports whether a label's script bitmask violates UTS #39
// Highly Restrictive mixed-script rules.
func isMixedScriptMask(m scriptMask) bool {
	if m == scriptNone {
		return false
	}
	if m&scriptOther != 0 {
		return true
	}
	if m&(m-1) == 0 {
		return false
	}
	if m&^scriptJapaneseMask == 0 {
		return false
	}
	if m&^scriptKoreanMask == 0 {
		return false
	}
	return true
}

// computeConfusableSkeleton normalizes a label (either decoded Unicode or ASCII)
// into its canonical confusable skeleton for homograph comparison.
func computeConfusableSkeleton(label string) string {
	if label == "" {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(label))

	for _, r := range label {
		if r == '-' {
			continue
		}
		if r >= 0xFF01 && r <= 0xFF5E {
			r = r - 0xFEE0
		}
		if r <= 0x7F {
			if r >= 'A' && r <= 'Z' {
				r += 32
			}
			switch r {
			case '0':
				sb.WriteByte('o')
			case '1', 'i', 'l':
				sb.WriteByte('l')
			default:
				sb.WriteByte(byte(r))
			}
			continue
		}
		if mapped, ok := confusableRuneMap[r]; ok {
			sb.WriteString(mapped)
			continue
		}
		lr := unicode.ToLower(r)
		if mapped, ok := confusableRuneMap[lr]; ok {
			sb.WriteString(mapped)
			continue
		}
		sb.WriteRune(lr)
	}

	s := sb.String()
	if strings.Contains(s, "rn") || strings.Contains(s, "vv") || strings.Contains(s, "cl") {
		s = strings.ReplaceAll(s, "rn", "m")
		s = strings.ReplaceAll(s, "vv", "w")
		s = strings.ReplaceAll(s, "cl", "d")
	}
	return s
}

// registerProtectedDomain adds a domain (e.g. "paypal.com") to the protected
// brand tables so its SLD ("paypal") is indexed by its confusable skeleton.
func registerProtectedDomain(raw string, skeletons map[string]protectedBrand, domains map[string]bool, slds map[string]string) {
	for _, part := range strings.Split(raw, ",") {
		clean := lowerTrimDot(strings.TrimSpace(part))
		clean = strings.TrimPrefix(clean, "*.")
		if clean == "" {
			continue
		}

		apex, eTLD := extractETLDPlusOne(clean)
		if apex == "" {
			apex = clean
		}

		sld := apex
		if eTLD != "" && len(apex) > len(eTLD)+1 && strings.HasSuffix(apex, "."+eTLD) {
			sld = apex[:len(apex)-len(eTLD)-1]
		} else if dot := strings.IndexByte(apex, '.'); dot > 0 {
			sld = apex[:dot]
		}

		if strings.HasPrefix(sld, "xn--") {
			if dec, err := idna.ToUnicode(sld); err == nil && dec != "" {
				sld = strings.ToLower(dec)
			}
		}

		if len(sld) < 4 {
			continue
		}

		domains[clean] = true
		domains[apex] = true
		if _, exists := slds[sld]; !exists {
			slds[sld] = apex
		}

		unhyphenated := sld
		if strings.Contains(sld, "-") {
			unhyphenated = strings.ReplaceAll(sld, "-", "")
		}

		skel := computeConfusableSkeleton(sld)
		if skel == "" {
			continue
		}
		if existing, exists := skeletons[skel]; !exists {
			allowed := []string{sld}
			if unhyphenated != sld {
				allowed = append(allowed, unhyphenated)
			}
			skeletons[skel] = protectedBrand{
				canonicalSLD:    sld,
				unhyphenatedSLD: unhyphenated,
				canonicalDomain: apex,
				allowedSLDs:     allowed,
			}
		} else {
			if !existing.isAllowedSLD(sld) {
				existing.allowedSLDs = append(existing.allowedSLDs, sld)
			}
			if unhyphenated != sld && !existing.isAllowedSLD(unhyphenated) {
				existing.allowedSLDs = append(existing.allowedSLDs, unhyphenated)
			}
			if strings.Contains(existing.canonicalSLD, "-") && !strings.Contains(sld, "-") {
				existing.canonicalSLD = sld
				existing.unhyphenatedSLD = unhyphenated
				existing.canonicalDomain = apex
			}
			skeletons[skel] = existing
		}
	}
}

// buildProtectedBrandTables compiles the built-in protected domain lists
// (vendorMap, dgaSafeDomains, defaultProtectedDomains) plus custom userDomains.
func buildProtectedBrandTables(userDomains []string, exemptList []string) {
	skeletons := make(map[string]protectedBrand, 512)
	domains := make(map[string]bool, 512)
	slds := make(map[string]string, 512)
	exempt := make(map[string]bool, len(exemptList))

	for _, ex := range exemptList {
		for _, tok := range strings.Split(ex, ",") {
			c := lowerTrimDot(strings.TrimSpace(tok))
			c = strings.TrimPrefix(c, "*.")
			if c != "" {
				exempt[c] = true
			}
		}
	}

	for _, d := range userDomains {
		registerProtectedDomain(d, skeletons, domains, slds)
	}
	for d := range vendorMap {
		registerProtectedDomain(d, skeletons, domains, slds)
	}
	for _, d := range dgaSafeDomains {
		registerProtectedDomain(d, skeletons, domains, slds)
	}
	for _, d := range defaultProtectedDomains {
		registerProtectedDomain(d, skeletons, domains, slds)
	}

	idnProtectedSkeletons = skeletons
	idnProtectedDomains = domains
	idnProtectedSLDs = slds
	idnExemptDomains = exempt
}

// isIDNExempt performs a zero-allocation label-by-label suffix walk against idnExemptDomains.
func isIDNExempt(qname string) bool {
	if len(idnExemptDomains) == 0 || qname == "" {
		return false
	}
	search := qname
	for {
		if idnExemptDomains[search] {
			return true
		}
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
	}
	return false
}

// hasIDNOrNonASCII performs a fast O(N) byte scan to detect whether qname
// contains any `xn--` Punycode label prefix or any non-ASCII byte (>= 0x80).
// Zero allocations.
func hasIDNOrNonASCII(qname string) (hasPunycode bool, hasNonASCII bool) {
	n := len(qname)
	labelStart := true
	for i := 0; i < n; i++ {
		c := qname[i]
		if c >= 0x80 {
			hasNonASCII = true
		}
		if labelStart {
			if i+4 <= n &&
				(c == 'x' || c == 'X') &&
				(qname[i+1] == 'n' || qname[i+1] == 'N') &&
				qname[i+2] == '-' &&
				qname[i+3] == '-' {
				hasPunycode = true
			}
			labelStart = false
		}
		if c == '.' {
			labelStart = true
		}
	}
	return
}

// AnalyzeIDNHomograph inspects a normalized domain name (lowercased, no trailing dot)
// for IDN/Punycode blocks, malformed ACE labels, mixed-script attacks, and
// confusable homograph impersonation of protected brands.
func AnalyzeIDNHomograph(qname string) (bool, string) {
	if !hasIDNHomograph || qname == "" {
		return false, ""
	}
	if strings.HasSuffix(qname, ".arpa") || strings.HasSuffix(qname, ".local") || strings.HasSuffix(qname, ".localhost") {
		return false, ""
	}
	if ddrHostnames != nil && ddrHostnames[qname] {
		return false, ""
	}
	if isIDNExempt(qname) {
		return false, ""
	}

	hasPunycode, hasNonASCII := hasIDNOrNonASCII(qname)
	isIDN := hasPunycode || hasNonASCII

	if !isIDN && !idnASCIILookalikes {
		return false, ""
	}

	// 1. Optional total IDN / ACE Punycode block
	if isIDN && idnBlockAll {
		if hasPunycode {
			return true, "IDN Blocked (Punycode/ACE: " + qname + ")"
		}
		return true, "IDN Blocked (Non-ASCII: " + qname + ")"
	}

	apex, eTLD := extractETLDPlusOne(qname)
	isCanonicalApex := (apex != "" && idnProtectedDomains[apex]) || idnProtectedDomains[qname]
	if !isCanonicalApex && apex != "" && eTLD != "" && len(apex) > len(eTLD)+1 && strings.HasSuffix(apex, "."+eTLD) {
		apexSLD := apex[:len(apex)-len(eTLD)-1]
		if idnProtectedSLDs[apexSLD] != "" {
			isCanonicalApex = true
		}
	}

	// 2. Inspect each non-eTLD label for Punycode validity, Mixed-Script, and Confusables
	scanPart := qname
	if eTLD != "" && len(qname) > len(eTLD)+1 && strings.HasSuffix(qname, "."+eTLD) {
		scanPart = qname[:len(qname)-len(eTLD)-1]
	}

	rem := scanPart
	for rem != "" {
		label := rem
		if dot := strings.IndexByte(rem, '.'); dot >= 0 {
			label = rem[:dot]
			rem = rem[dot+1:]
		} else {
			rem = ""
		}
		if label == "" {
			continue
		}

		isSLD := rem == ""
		isLabelACE := len(label) >= 4 && strings.HasPrefix(label, "xn--")
		hasLabelNonASCII := false
		for i := 0; i < len(label); i++ {
			if label[i] >= 0x80 {
				hasLabelNonASCII = true
				break
			}
		}

		if isLabelACE || hasLabelNonASCII {
			decoded := label
			if isLabelACE {
				if len(label) == 4 {
					return true, "IDN Malformed Empty Punycode (" + label + ")"
				}
				uLabel, err := idna.ToUnicode(label)
				if err != nil || uLabel == "" || uLabel == label {
					return true, "IDN Malformed Punycode (" + label + ")"
				}
				decoded = strings.ToLower(uLabel)
			}

			var mask scriptMask
			for _, r := range decoded {
				mask |= runeScript(r)
			}

			if idnMixedScript && isMixedScriptMask(mask) {
				return true, "IDN Mixed-Script Attack (" + label + " -> " + decoded + ")"
			}

			skel := computeConfusableSkeleton(decoded)
			if brand, ok := idnProtectedSkeletons[skel]; ok {
				if !brand.isAllowedSLD(decoded) {
					return true, "IDN Homograph Impersonation (" + label + " [" + decoded + "] impersonates " + brand.canonicalDomain + ")"
				}
			}
		} else if idnASCIILookalikes && len(label) >= 4 {
			if isSLD && (isCanonicalApex || idnProtectedSLDs[label] != "") {
				continue
			}
			skel := computeConfusableSkeleton(label)
			if brand, ok := idnProtectedSkeletons[skel]; ok && !brand.isAllowedSLD(label) {
				if !isSLD || idnProtectedSLDs[label] == "" {
					return true, "Homograph Lookalike Impersonation (" + label + " in " + qname + " impersonates " + brand.canonicalDomain + ")"
				}
			}
		}
	}

	// 3. Evaluate the registrable SLD for confusable skeleton collisions against protected brands
	if apex == "" || apex == eTLD || isCanonicalApex {
		return false, ""
	}

	sld := apex
	if eTLD != "" && len(apex) > len(eTLD)+1 && strings.HasSuffix(apex, "."+eTLD) {
		sld = apex[:len(apex)-len(eTLD)-1]
	}
	if sld == "" {
		return false, ""
	}
	if _, isExactSLD := idnProtectedSLDs[sld]; isExactSLD {
		return false, ""
	}

	decodedSLD := sld
	if strings.HasPrefix(sld, "xn--") {
		if uSLD, err := idna.ToUnicode(sld); err == nil && uSLD != "" {
			decodedSLD = strings.ToLower(uSLD)
		}
	}

	if len(decodedSLD) >= 4 {
		skel := computeConfusableSkeleton(decodedSLD)
		if brand, ok := idnProtectedSkeletons[skel]; ok && !brand.isAllowedSLD(decodedSLD) {
			if sld != decodedSLD {
				return true, "IDN Homograph Impersonation (" + apex + " [" + decodedSLD + "] impersonates " + brand.canonicalDomain + ")"
			}
			if idnASCIILookalikes {
				return true, "Homograph Lookalike Impersonation (" + apex + " impersonates " + brand.canonicalDomain + ")"
			}
		}
	}

	return false, ""
}

// applyIDNHomographVerdict executes the configured action (`LOG`, `BLOCK`, `DROP`, or RCODE)
// once an IDN homograph or lookalike violation has been identified.
func (qc *queryCtx) applyIDNHomographVerdict(reason string, cacheHit bool) bool {
	IncrIDNHomographBlock()
	RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, reason)

	if idnAction == "LOG" || (idnAction == "BLOCK" && globalBlockAction == BlockActionLog) {
		if logQueries {
			if logSimple {
				log.Printf("[DNS] [%s] %s -> %s %s | IDN HOMOGRAPH (LOG ONLY): %s",
					qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), reason)
			} else {
				log.Printf("[DNS] [%s] %s -> %s %s | IDN HOMOGRAPH DETECTION (LOG ONLY) (%s) | LOG",
					qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(), reason)
			}
		}
		return false
	}

	dropped := writePolicyAction(qc.w, qc.r, idnActionCode)

	if !cacheHit && cacheSynthFlag && !dropped && !(idnActionCode == PolicyActionBlock && globalBlockAction == BlockActionDrop) {
		synthMsg := buildSynthCacheMsg(qc.r, qc.q, idnActionCode)
		CacheSetSynth(qc.cacheKey, synthMsg)
		msgPool.Put(synthMsg)
	}

	if logQueries {
		var actionLogStr string
		if idnActionCode == PolicyActionBlock {
			actionLogStr = getBlockActionLogStr(qc.q.Qtype)
		} else if idnActionCode == PolicyActionDrop {
			actionLogStr = "DROP"
		} else {
			actionLogStr = RcodeStr(idnActionCode)
		}

		if logSimple {
			logQuerySimple(qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), actionLogStr, reason, cacheHit)
		} else {
			statusMark := "IDN HOMOGRAPH BLOCK"
			if dropped {
				statusMark = "IDN HOMOGRAPH DROP"
			}
			statusMark = qc.annotateAlias(statusMark)

			log.Printf("[DNS] [%s] %s -> %s %s | %s (%s) | %s",
				qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
				statusMark, reason, actionLogStr)
		}
	}

	return true
}

// enforceIDNHomographCheck evaluates `originalQNameTrimmed` and `qNameTrimmed`
// against `AnalyzeIDNHomograph`, respecting `bypassPolicies` and `bypassGlobal`.
func (qc *queryCtx) enforceIDNHomographCheck() bool {
	if !hasIDNHomograph || qc.bypassPolicies || qc.bypassGlobal {
		return false
	}
	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		if violated, reason := AnalyzeIDNHomograph(qc.originalQNameTrimmed); violated {
			return qc.applyIDNHomographVerdict(reason, false)
		}
	}
	if violated, reason := AnalyzeIDNHomograph(qc.qNameTrimmed); violated {
		return qc.applyIDNHomographVerdict(reason, false)
	}
	return false
}
