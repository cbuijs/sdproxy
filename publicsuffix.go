/*
File:    publicsuffix.go
Version: 1.7.0 (Split)
Updated: 2026-04-10

Description:
  Static embedded public-suffix guard for sdproxy.

  isPublicSuffix(d) returns true when d is a TLD or eTLD — a registry
  boundary that must never be used as a synthesised apex entry or as the
  result of a service-label strip.

  Why this matters:
    stripServiceLabel("www.co.uk")  → would produce "co.uk" without this guard.
    consolidateParentDomains: 10 "*.co.uk" children → would synthesise "co.uk"
    without this guard, wrongly categorising every domain under .co.uk.

  Source: ICANN section of the Mozilla Public Suffix List (PSL).
  https://publicsuffix.org/list/public_suffix_list.dat  — ICANN section only.
  Private domains (github.io, amazonaws.com, …) are NOT included here —
  those are handled by sharedhosting.go.

  Implementation strategy:
    Two-tier lookup — O(1) map probes, zero allocations, zero goroutines.

    Tier 1 — wildcardTLDs:
      TLDs where EVERY 2-label form (X.tld) is itself a public suffix.
      Covers PSL wildcard rules (*.ck, *.er, *.mm, *.np) and pragmatic
      wildcards for .uk, .au, .nz, .za which have 50+ second-level
      delegations — far too many to enumerate individually.

    Tier 2 — knownETLDs:
      Explicit 2-label eTLDs for all other major ccTLDs and the handful of
      generic 2-label suffixes (com.br, co.jp, etc.).

Changes:
  1.7.0  - [REFACTOR] Split vendor and TLD mapping logic into vendors.go and tldinfo.go
           to make this file more manageable and focused entirely on PSL logic.
  1.6.0  - [FEAT] Expanded vendorMap to include top ad-tech and tracking 
           entities curated from the DuckDuckGo Tracker Radar dataset. Adds
           recognizability for entities like Oracle (BlueKai/AddThis), 
           Criteo, The Trade Desk, Index Exchange, Magnite, etc.
  1.5.0  - [FEAT] Massively expanded tldInfoMap to comprehensively cover the 
           IANA Root Zone Database. Includes all ccTLDs (with full territory 
           names), all sTLDs, infrastructure, and a huge selection of modern 
           gTLDs. Grouped and sorted alphabetically for clarity.
  1.4.0  - [FEAT] Extended vendorMap to comprehensively identify GAFAM, FANG,
           FAANG, MAMAA, the "Magnificent Seven" (Alphabet, Amazon, Apple,
           Meta, Microsoft, Nvidia, Tesla), BATX/Asian giants, and the top-25
           most connected internet services globally.
  1.3.0  - [FEAT] Added getVendor, getTLDHint, and extractETLDPlusOne helpers.
           Migrated vendorMap and tldInfoMap here, sorted alphabetically
           by category and key for ultimate readability.
  1.2.0  - Added missing ccTLD blocks: .bg, .by, .ee, .gr, .hu, .kz, .lv,
           .ro, .ua, .uz. Reordered knownETLDs blocks alphabetically by TLD
           code. Fixes eTLD protection for e.g. com.ua (Ukraine), com.ro
           (Romania), com.kz (Kazakhstan), etc.
  1.1.0  - Wording: "blocked" → "wrongly categorised" throughout.
           Entries sorted alphabetically within each ccTLD block.
  1.0.0  - Initial static PSL implementation.
*/

package main

import "strings"

// ---------------------------------------------------------------------------
// Tier 1: wildcard TLDs
// ---------------------------------------------------------------------------

// wildcardTLDs holds TLDs where every 2-label combination X.<tld> is itself
// a public suffix. Sourced from PSL wildcard rules plus pragmatic coverage
// for .uk, .au, .nz, .za (all have far too many SLDs to enumerate).
var wildcardTLDs = map[string]struct{}{
	// PSL explicit wildcard rules (*.tld in the ICANN section):
	"ck": {}, // Cook Islands — *.ck; www.ck is the only normal registration
	"er": {}, // Eritrea      — *.er
	"mm": {}, // Myanmar      — *.mm (no active 2nd-level registrations)
	"np": {}, // Nepal        — *.np

	// Pragmatic wildcards — so many 2nd-level delegations that enumeration
	// is impractical and any X.<tld> is almost certainly a registry boundary:
	"au": {}, // com.au, net.au, org.au, edu.au, gov.au, asn.au, id.au, …
	"nz": {}, // co.nz, net.nz, org.nz, govt.nz, ac.nz, school.nz, …
	"uk": {}, // co.uk, org.uk, me.uk, net.uk, ltd.uk, plc.uk, sch.uk, …
	"za": {}, // co.za, net.za, org.za, gov.za, edu.za, ac.za, alt.za, …
}

// ---------------------------------------------------------------------------
// Tier 2: explicit known eTLDs
// ---------------------------------------------------------------------------

// knownETLDs holds 2-label (and a handful of 3-label) public suffixes that
// are NOT covered by wildcardTLDs above.
//
// Entries are lowercased, no trailing dot, in "label.tld" form.
// Sourced from the ICANN section of the Mozilla PSL.
// Sorted alphabetically by TLD code; entries within each block sorted
// alphabetically by the leftmost label.
var knownETLDs = map[string]struct{}{

	// ── UAE (.ae) ────────────────────────────────────────────────────────────
	"ac.ae": {}, "co.ae": {}, "gov.ae": {}, "mil.ae": {},
	"net.ae": {}, "org.ae": {}, "pro.ae": {}, "sch.ae": {},

	// ── Argentina (.ar) ──────────────────────────────────────────────────────
	"com.ar": {}, "edu.ar": {}, "gov.ar": {}, "int.ar": {},
	"mil.ar": {}, "net.ar": {}, "org.ar": {}, "tur.ar": {},

	// ── Austria (.at) ────────────────────────────────────────────────────────
	"ac.at": {}, "co.at": {}, "gv.at": {}, "or.at": {},

	// ── Bangladesh (.bd) ─────────────────────────────────────────────────────
	"ac.bd": {}, "com.bd": {}, "edu.bd": {}, "gov.bd": {},
	"mil.bd": {}, "net.bd": {}, "org.bd": {},

	// ── Belgium (.be) ────────────────────────────────────────────────────────
	"ac.be": {},

	// ── Bulgaria (.bg) ───────────────────────────────────────────────────────
	"com.bg": {}, "net.bg": {}, "org.bg": {},

	// ── Brazil (.br) ─────────────────────────────────────────────────────────
	"adm.br": {}, "adv.br": {}, "agr.br": {}, "am.br":    {},
	"arq.br": {}, "art.br": {}, "ato.br": {}, "b.br":     {},
	"bib.br": {}, "bio.br": {}, "blog.br": {}, "bmd.br":  {},
	"cim.br": {}, "cng.br": {}, "cnt.br": {}, "com.br":   {},
	"coop.br": {}, "ecn.br": {}, "eco.br": {}, "edu.br":  {},
	"emp.br": {}, "eng.br": {}, "esp.br": {}, "etc.br":   {},
	"eti.br": {}, "far.br": {}, "fnd.br": {}, "fot.br":   {},
	"fst.br": {}, "g12.br": {}, "ggf.br": {}, "gov.br":   {},
	"imb.br": {}, "ind.br": {}, "inf.br": {}, "jor.br":   {},
	"jus.br": {}, "leg.br": {}, "lel.br": {}, "mat.br":   {},
	"med.br": {}, "mil.br": {}, "mp.br":  {}, "mus.br":   {},
	"net.br": {}, "nom.br": {}, "not.br": {}, "ntr.br":   {},
	"odo.br": {}, "org.br": {}, "ppg.br": {}, "pro.br":   {},
	"psc.br": {}, "psi.br": {}, "qsl.br": {}, "radio.br": {},
	"rec.br": {}, "slg.br": {}, "srv.br": {}, "taxi.br":  {},
	"teo.br": {}, "tmp.br": {}, "trd.br": {}, "tur.br":   {},
	"vet.br": {}, "vlog.br": {}, "wiki.br": {}, "zlg.br": {},

	// ── Belarus (.by) ────────────────────────────────────────────────────────
	"com.by": {}, "edu.by": {}, "gov.by": {}, "mil.by": {},
	"net.by": {}, "org.by": {},

	// ── Canada (.ca) — provincial SLDs ───────────────────────────────────────
	"ab.ca": {}, "bc.ca": {}, "mb.ca": {}, "nb.ca": {}, "nf.ca": {},
	"nl.ca": {}, "ns.ca": {}, "nt.ca": {}, "nu.ca": {}, "on.ca": {},
	"pe.ca": {}, "qc.ca": {}, "sk.ca": {}, "yk.ca": {},

	// ── China (.cn) ──────────────────────────────────────────────────────────
	// Functional SLDs:
	"ac.cn": {}, "com.cn": {}, "edu.cn": {}, "gov.cn": {},
	"mil.cn": {}, "net.cn": {}, "org.cn": {},
	// Provincial SLDs (sorted):
	"ah.cn": {}, "bj.cn": {}, "cq.cn": {}, "fj.cn": {}, "gd.cn": {},
	"gs.cn": {}, "gx.cn": {}, "gz.cn": {}, "ha.cn": {}, "hb.cn": {},
	"he.cn": {}, "hi.cn": {}, "hk.cn": {}, "hl.cn": {}, "hn.cn": {},
	"jl.cn": {}, "js.cn": {}, "jx.cn": {}, "ln.cn": {}, "mo.cn": {},
	"nm.cn": {}, "nx.cn": {}, "qh.cn": {}, "sc.cn": {}, "sd.cn": {},
	"sh.cn": {}, "sn.cn": {}, "sx.cn": {}, "tj.cn": {}, "tw.cn": {},
	"xj.cn": {}, "xz.cn": {}, "yn.cn": {}, "zj.cn": {},

	// ── Colombia (.co) ───────────────────────────────────────────────────────
	"com.co": {}, "edu.co": {}, "gov.co": {}, "mil.co": {},
	"net.co": {}, "org.co": {},

	// ── Estonia (.ee) ────────────────────────────────────────────────────────
	"com.ee": {}, "edu.ee": {}, "fie.ee": {}, "gov.ee": {},
	"lib.ee": {}, "med.ee": {}, "org.ee": {}, "pri.ee": {}, "riik.ee": {},

	// ── Egypt (.eg) ──────────────────────────────────────────────────────────
	"com.eg": {}, "edu.eg": {}, "gov.eg": {}, "mil.eg": {},
	"net.eg": {}, "org.eg": {},

	// ── Ghana (.gh) ──────────────────────────────────────────────────────────
	"com.gh": {}, "edu.gh": {}, "gov.gh": {}, "mil.gh": {}, "org.gh": {},

	// ── Greece (.gr) ─────────────────────────────────────────────────────────
	"com.gr": {}, "edu.gr": {}, "gov.gr": {}, "net.gr": {}, "org.gr": {},

	// ── Hong Kong (.hk) ──────────────────────────────────────────────────────
	"com.hk": {}, "edu.hk": {}, "gov.hk": {}, "idv.hk": {},
	"net.hk": {}, "org.hk": {},

	// ── Hungary (.hu) ────────────────────────────────────────────────────────
	// PSL enumerates every SLD for .hu — no wildcard rule, all listed
	// explicitly:
	"2000.hu": {}, "agrar.hu": {}, "bolt.hu": {}, "casino.hu": {},
	"city.hu": {}, "co.hu": {}, "erotica.hu": {}, "erotika.hu": {},
	"film.hu": {}, "forum.hu": {}, "games.hu": {}, "hotel.hu": {},
	"info.hu": {}, "ingatlan.hu": {}, "jogasz.hu": {}, "konyvelo.hu": {},
	"lakas.hu": {}, "media.hu": {}, "news.hu": {}, "org.hu": {},
	"priv.hu": {}, "reklam.hu": {}, "sex.hu": {}, "shop.hu": {},
	"sport.hu": {}, "suli.hu": {}, "szex.hu": {}, "tm.hu": {},
	"tozsde.hu": {}, "utazas.hu": {}, "video.hu": {},

	// ── Indonesia (.id) ──────────────────────────────────────────────────────
	"ac.id": {}, "biz.id": {}, "co.id": {}, "go.id": {}, "mil.id": {},
	"net.id": {}, "or.id": {}, "sch.id": {}, "web.id": {},

	// ── Israel (.il) ─────────────────────────────────────────────────────────
	"ac.il": {}, "co.il": {}, "gov.il": {}, "idf.il": {}, "k12.il": {},
	"muni.il": {}, "net.il": {}, "org.il": {},

	// ── India (.in) ──────────────────────────────────────────────────────────
	"ac.in": {}, "co.in": {}, "edu.in": {}, "firm.in": {}, "gen.in": {},
	"gov.in": {}, "ind.in": {}, "mil.in": {}, "net.in": {},
	"nic.in": {}, "org.in": {}, "res.in": {},

	// ── Iran (.ir) ───────────────────────────────────────────────────────────
	"ac.ir": {}, "com.ir": {}, "edu.ir": {}, "gov.ir": {},
	"mil.ir": {}, "net.ir": {}, "org.ir": {},

	// ── Japan (.jp) ──────────────────────────────────────────────────────────
	// Functional SLDs:
	"ac.jp": {}, "ad.jp": {}, "co.jp": {}, "ed.jp": {}, "geo.jp": {},
	"go.jp": {}, "gr.jp": {}, "lg.jp": {}, "ne.jp": {}, "or.jp": {},
	"pref.jp": {}, // parent of all prefectural SLDs (X.pref.jp)
	// PSL exception — metro.tokyo.jp is registrable despite *.tokyo.jp rule:
	"metro.tokyo.jp": {},

	// ── Kenya (.ke) ──────────────────────────────────────────────────────────
	"ac.ke": {}, "co.ke": {}, "go.ke": {}, "me.ke": {},
	"ne.ke": {}, "or.ke": {}, "sc.ke": {},

	// ── South Korea (.kr) ────────────────────────────────────────────────────
	// Functional SLDs:
	"ac.kr": {}, "co.kr": {}, "es.kr": {}, "go.kr": {}, "hs.kr": {},
	"kg.kr": {}, "mil.kr": {}, "ms.kr": {}, "ne.kr": {}, "or.kr": {},
	"pe.kr": {}, "re.kr": {}, "sc.kr": {},
	// Metropolitan / provincial SLDs (sorted):
	"busan.kr": {}, "chungbuk.kr": {}, "chungnam.kr": {}, "daegu.kr": {},
	"daejeon.kr": {}, "gangwon.kr": {}, "gwangju.kr": {}, "gyeongbuk.kr": {},
	"gyeonggi.kr": {}, "gyeongnam.kr": {}, "incheon.kr": {}, "jeju.kr": {},
	"jeonbuk.kr": {}, "jeonnam.kr": {}, "seoul.kr": {}, "ulsan.kr": {},

	// ── Kazakhstan (.kz) ─────────────────────────────────────────────────────
	"com.kz": {}, "edu.kz": {}, "gov.kz": {}, "mil.kz": {},
	"net.kz": {}, "org.kz": {},

	// ── Latvia (.lv) ─────────────────────────────────────────────────────────
	"asn.lv": {}, "com.lv": {}, "conf.lv": {}, "edu.lv": {},
	"gov.lv": {}, "id.lv": {}, "mil.lv": {}, "net.lv": {}, "org.lv": {},

	// ── Mexico (.mx) ─────────────────────────────────────────────────────────
	"com.mx": {}, "edu.mx": {}, "gob.mx": {}, "net.mx": {}, "org.mx": {},

	// ── Malaysia (.my) ───────────────────────────────────────────────────────
	"com.my": {}, "edu.my": {}, "gov.my": {}, "mil.my": {},
	"name.my": {}, "net.my": {}, "org.my": {},

	// ── Nigeria (.ng) ────────────────────────────────────────────────────────
	"com.ng": {}, "edu.ng": {}, "gov.ng": {}, "mil.ng": {},
	"mobi.ng": {}, "name.ng": {}, "net.ng": {}, "org.ng": {},

	// ── Philippines (.ph) ────────────────────────────────────────────────────
	"com.ph": {}, "edu.ph": {}, "gov.ph": {}, "i.ph": {}, "mil.ph": {},
	"net.ph": {}, "ngo.ph": {}, "org.ph": {},

	// ── Pakistan (.pk) ───────────────────────────────────────────────────────
	"biz.pk": {}, "com.pk": {}, "edu.pk": {}, "fam.pk": {}, "gov.pk": {},
	"info.pk": {}, "net.pk": {}, "org.pk": {}, "web.pk": {},

	// ── Romania (.ro) ────────────────────────────────────────────────────────
	"arts.ro": {}, "com.ro": {}, "firm.ro": {}, "info.ro": {}, "nom.ro": {},
	"nt.ro": {}, "org.ro": {}, "rec.ro": {}, "store.ro": {}, "tm.ro": {},
	"www.ro": {}, // PSL explicitly lists www.ro as an eTLD

	// ── Russia (.ru) ─────────────────────────────────────────────────────────
	"ac.ru": {},

	// ── Saudi Arabia (.sa) ───────────────────────────────────────────────────
	"com.sa": {}, "edu.sa": {}, "gov.sa": {}, "med.sa": {},
	"net.sa": {}, "org.sa": {}, "pub.sa": {}, "sch.sa": {},

	// ── Singapore (.sg) ──────────────────────────────────────────────────────
	"com.sg": {}, "edu.sg": {}, "gov.sg": {}, "net.sg": {},
	"org.sg": {}, "per.sg": {},

	// ── Thailand (.th) ───────────────────────────────────────────────────────
	"ac.th": {}, "co.th": {}, "go.th": {}, "in.th": {},
	"mi.th": {}, "net.th": {}, "org.th": {},

	// ── Turkey (.tr) ─────────────────────────────────────────────────────────
	"av.tr": {}, "bel.tr": {}, "biz.tr": {}, "com.tr": {}, "dr.tr": {},
	"edu.tr": {}, "gen.tr": {}, "gov.tr": {}, "info.tr": {}, "k12.tr": {},
	"mil.tr": {}, "name.tr": {}, "net.tr": {}, "org.tr": {}, "pol.tr": {},
	"tel.tr": {}, "tv.tr": {}, "web.tr": {},

	// ── Taiwan (.tw) ─────────────────────────────────────────────────────────
	"club.tw": {}, "com.tw": {}, "ebiz.tw": {}, "edu.tw": {}, "game.tw": {},
	"gov.tw": {}, "idv.tw": {}, "net.tw": {}, "org.tw": {},

	// ── Ukraine (.ua) ────────────────────────────────────────────────────────
	// This block was the primary gap — missing entries caused com.ua to not be
	// recognised as an eTLD, allowing consolidation to wrongly synthesise it
	// and stripServiceLabel to wrongly strip "m.com.ua" → "com.ua".
	"com.ua": {}, "edu.ua": {}, "gov.ua": {}, "in.ua": {},
	"net.ua": {}, "org.ua": {},

	// ── Uzbekistan (.uz) ─────────────────────────────────────────────────────
	"co.uz": {}, "com.uz": {}, "net.uz": {}, "org.uz": {},

	// ── Venezuela (.ve) ──────────────────────────────────────────────────────
	"arts.ve": {}, "co.ve": {}, "com.ve": {}, "edu.ve": {}, "firm.ve": {},
	"gov.ve": {}, "info.ve": {}, "int.ve": {}, "mil.ve": {}, "net.ve": {},
	"org.ve": {}, "rec.ve": {}, "store.ve": {}, "web.ve": {},

	// ── Vietnam (.vn) ────────────────────────────────────────────────────────
	"ac.vn": {}, "biz.vn": {}, "com.vn": {}, "edu.vn": {}, "gov.vn": {},
	"health.vn": {}, "info.vn": {}, "int.vn": {}, "name.vn": {},
	"net.vn": {}, "org.vn": {}, "pro.vn": {},
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// isPublicSuffix reports whether d is a TLD or eTLD — a registry boundary
// that must never appear as a synthesised apex entry or as the result of a
// service-label strip. Inserting a public suffix into the category apex map
// would wrongly categorise every registrable domain under it.
//
// Lookup logic (O(1), zero allocations):
//  1. No dot   → bare TLD → true.
//  2. knownETLDs lookup → explicit 2-label match → true when found.
//  3. wildcardTLDs lookup on the rightmost label of d → true when the TLD
//     has a wildcard rule (every X.<tld> is an eTLD), but ONLY when d itself
//     has exactly 2 labels — "evil.co.uk" has 3 labels so it returns false
//     (registrable domain), while "co.uk" has 2 labels so it returns true.
//  4. Otherwise → false (d is a registrable domain or deeper).
//
// Inputs must be lowercased and have no trailing dot — callers in parental.go
// always normalise before calling.
func isPublicSuffix(d string) bool {
	// 1. Single label (no dot) — bare TLD.
	idx := strings.IndexByte(d, '.')
	if idx < 0 {
		return true
	}

	// 2. Explicit 2-label eTLD lookup.
	if _, ok := knownETLDs[d]; ok {
		return true
	}

	// 3. Wildcard TLD check — only applies when d has exactly 2 labels.
	//    "co.uk"     → 2 labels, tld="uk" → wildcardTLDs hit → true  ✓
	//    "x.co.uk"   → 3 labels           → skip             → false ✓
	if strings.Count(d, ".") == 1 {
		tld := d[idx+1:]
		if _, ok := wildcardTLDs[tld]; ok {
			return true
		}
	}

	return false
}

// extractETLDPlusOne isolates the eTLD+1 (domain apex) and the eTLD itself
// using the publicsuffix map. Used for vendor and TLD stats tracking.
// Example: "www.google.co.uk" -> etldPlusOne="google.co.uk", etld="co.uk".
func extractETLDPlusOne(domain string) (etldPlusOne string, etld string) {
	search := domain
	var prevSearch string
	for {
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			if prevSearch != "" {
				return prevSearch, search
			}
			return domain, domain
		}
		if isPublicSuffix(search) {
			if prevSearch != "" {
				return prevSearch, search
			}
			return search, search
		}
		prevSearch = search
		search = search[idx+1:]
	}
}

