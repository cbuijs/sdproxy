/*
File:    sharedhosting.go
Version: 1.1.0
Updated: 2026-03-19 15:00 CET

Description:
  Static embedded shared-hosting / ISP / CDN / SaaS domain guard for sdproxy.

  isSharedHostingDomain(d) returns true when d is a domain under which
  unrelated third parties host their own content. Synthesising d as a
  category-list apex entry would wrongly categorise ALL customers of that
  platform under the category that happened to appear in the list — not just
  the actual customers present in it.

  Example problem without this guard:
    A games list contains 10 entries like:
      coolgame.itch.io, retrogame.itch.io, puzzler.itch.io, …
    consolidateParentDomains() would synthesise "itch.io", wrongly categorising
    every itch.io project as a game — including art, music, comics, and tools
    that have nothing to do with gaming.

  This is complementary to publicsuffix.go (which protects registry
  boundaries) and the homogeneity check in parental.go (which detects
  multi-category parents at runtime). This file handles the case where a
  shared host appears exclusively in one category's list, so homogeneity
  alone gives no signal.

  Sources:
    - Mozilla PSL private section (curated subset of hosting/ISP/CDN entries):
      https://publicsuffix.org/list/public_suffix_list.dat
    - Known ISPs offering customer subdomains (free.fr, etc.)
    - Known CDN/cloud providers with customer-subdomain namespaces.

  Design constraints:
    - No external libraries, no runtime fetches, compiled into the binary.
    - ICANN-section eTLDs are NOT repeated here — see publicsuffix.go.
    - Private-section domains that are shared platforms are included.
      Pure vanity/personal subdomains of popular TLDs are not — those are
      covered by the homogeneity check.

Changes:
  1.1.0  - Wording: "blocked" → "wrongly categorised" throughout.
           Entries sorted alphabetically within each category block.
  1.0.0  - Initial static shared-hosting list.

  ... Older commit-information removed for brevity.
*/

package main

import "strings"

// sharedHostingDomains lists domains under which unrelated third parties host
// their own content. Entries are lowercased, no trailing dot.
//
// When consolidateParentDomains() finds a candidate parent in this map it
// skips synthesis regardless of child count or category homogeneity —
// synthesising the parent would wrongly categorise innocent customers of
// the platform.
var sharedHostingDomains = map[string]struct{}{

	// ── Blog / CMS / website builders ────────────────────────────────────────
	"blogger.com":      {}, // Blogger (behind blogspot.com CNAMEs)
	"blogspot.com":     {}, // Google Blogger — millions of unrelated blogs
	"cargo.site":       {}, // Cargo portfolio hosting
	"dreamwidth.org":   {}, // Dreamwidth blogs
	"format.com":       {}, // Format portfolio hosting
	"framer.website":   {}, // Framer
	"ghost.io":         {}, // Ghost(Pro) hosted blogs
	"jimdofree.com":    {}, // Jimdo free tier
	"jimdo.com":        {}, // Jimdo website builder
	"livejournal.com":  {}, // LiveJournal blogs
	"medium.com":       {}, // Medium publications (one subdomain per publication)
	"mozello.com":      {}, // Mozello
	"mystrikingly.com": {}, // Strikingly alt domain
	"pagecloud.com":    {}, // PageCloud
	"simplesite.com":   {}, // SimpleSite
	"squarespace.com":  {}, // Squarespace customer preview domains
	"strikingly.com":   {}, // Strikingly website builder
	"substack.com":     {}, // Substack newsletters
	"tumblr.com":       {}, // Tumblr blogs
	"typepad.com":      {}, // TypePad blogs
	"webflow.io":       {}, // Webflow staging domains
	"webnode.com":      {}, // Webnode
	"webself.net":      {}, // WebSelf
	"weebly.com":       {}, // Weebly user sites
	"wixsite.com":      {}, // Wix user sites (new)
	"wix.com":          {}, // Wix user sites (legacy subdomains)
	"wordpress.com":    {}, // WordPress.com hosted blogs

	// ── Code / project / app hosting ─────────────────────────────────────────
	"codepen.io":       {}, // CodePen pens and projects
	"firebaseapp.com":  {}, // Firebase legacy hosting
	"fly.dev":          {}, // Fly.io apps
	"github.io":        {}, // GitHub Pages — user/org/project sites
	"gitlab.io":        {}, // GitLab Pages
	"glitch.me":        {}, // Glitch app hosting
	"netlify.app":      {}, // Netlify
	"now.sh":           {}, // Vercel legacy domain
	"onrender.com":     {}, // Render alt domain
	"pages.dev":        {}, // Cloudflare Pages
	"railway.app":      {}, // Railway
	"render.com":       {}, // Render hosting
	"replit.dev":       {}, // Replit dev domains
	"repl.co":          {}, // Replit
	"stackblitz.io":    {}, // StackBlitz
	"surge.sh":         {}, // Surge.sh static hosting
	"vercel.app":       {}, // Vercel
	"web.app":          {}, // Firebase Hosting

	// ── E-commerce / storefront hosting ──────────────────────────────────────
	"bigcartel.com":    {}, // Big Cartel shops
	"cratejoy.com":     {}, // Cratejoy subscription shops
	"gumroad.com":      {}, // Gumroad creator stores
	"myshopify.com":    {}, // Shopify stores (custom-domain fallback)
	"myshopify.io":     {}, // Shopify CDN
	"payhip.com":       {}, // Payhip
	"sellfy.com":       {}, // Sellfy
	"storenvy.com":     {}, // Storenvy shops

	// ── Education / learning platforms ───────────────────────────────────────
	"kajabi.com":       {}, // Kajabi
	"learnworlds.com":  {}, // LearnWorlds
	"teachable.com":    {}, // Teachable course sites
	"thinkific.com":    {}, // Thinkific

	// ── Generic shared / free / reseller hosting ──────────────────────────────
	"000webhostapp.com": {}, // 000webhost free hosting
	"000webhost.com":    {}, // 000webhost
	"biz.nf":            {}, // Nazuke free hosting
	"site44.com":        {}, // Site44 Dropbox-based hosting
	"yolasite.com":      {}, // Yola website builder

	// ── Indie game / app hosting ──────────────────────────────────────────────
	"gamejolt.com":   {}, // Indie game hosting
	"itch.io":        {}, // Indie game hosting — thousands of unrelated projects
	"kongregate.com": {}, // Browser game hosting
	"newgrounds.com": {}, // Flash/HTML5 games and media hosting

	// ── ISPs / telcos offering customer subdomains ────────────────────────────
	// Australia:
	"bigpond.com":     {}, // Telstra BigPond legacy
	"iinet.net.au":    {}, // iiNet ISP
	"optusnet.com.au": {}, // Optus ISP
	// Canada:
	"rogers.com":     {}, // Rogers ISP
	"shaw.ca":        {}, // Shaw ISP (now Rogers)
	"sympatico.ca":   {}, // Bell Canada legacy ISP
	// France:
	"bbox.fr":        {}, // Bouygues ISP
	"freebox.fr":     {}, // Free Freebox NAS/server domains
	"freeboxos.fr":   {}, // Freebox OS
	"free.fr":        {}, // Free (Iliad) — largest French ISP, customer subdomains
	"lafibre.info":   {}, // Free community domain
	"neuf.fr":        {}, // SFR/Neuf legacy
	"orange.fr":      {}, // Orange France ISP
	"sfr.fr":         {}, // SFR France ISP
	"sfr.net":        {}, // SFR
	"wanadoo.fr":     {}, // Orange/Wanadoo legacy
	// Germany:
	"1und1.de":       {}, // 1&1 ISP
	"hosteurope.de":  {}, // Host Europe
	"ionos.de":       {}, // IONOS hosting
	"strato.de":      {}, // Strato hosting
	"t-online.de":    {}, // Deutsche Telekom
	// Netherlands:
	"home.nl":        {}, // Caiway/Home ISP
	"kpn.com":        {}, // KPN ISP
	"xs4all.nl":      {}, // XS4ALL ISP
	"ziggo.nl":       {}, // Ziggo ISP
	// UK:
	"btopenworld.com":  {}, // BT legacy
	"btinternet.com":   {}, // BT Internet
	"plusnet.com":      {}, // Plusnet
	"sky.com":          {}, // Sky ISP customer domains
	"virginmedia.com":  {}, // Virgin Media
	// USA:
	"att.net":         {}, // AT&T ISP
	"bellsouth.net":   {}, // AT&T/BellSouth legacy
	"charter.net":     {}, // Charter/Spectrum ISP
	"comcast.net":     {}, // Comcast ISP
	"cox.net":         {}, // Cox ISP
	"sbcglobal.net":   {}, // AT&T/SBC legacy
	"verizon.net":     {}, // Verizon ISP

	// ── Cloud providers (AWS / Azure / GCP) customer namespaces ──────────────
	"amazonaws.com":              {}, // S3, EC2, Lambda — customer subdomains
	"appspot.com":                {}, // Google App Engine
	"azureedge.net":              {}, // Azure CDN
	"azurefd.net":                {}, // Azure Front Door
	"azurewebsites.net":          {}, // Azure App Service
	"blob.core.windows.net":      {}, // Azure Blob Storage
	"cloudapp.azure.com":         {}, // Azure cloud apps
	"cloudapp.net":               {}, // Azure legacy
	"cloudfront.net":             {}, // AWS CloudFront CDN — customer distributions
	"elasticbeanstalk.com":       {}, // AWS Elastic Beanstalk apps
	"execute-api.amazonaws.com":  {}, // AWS API Gateway
	"s3-website.amazonaws.com":   {}, // S3 static website hosting
	"storage.googleapis.com":     {}, // GCS public objects
	"trafficmanager.net":         {}, // Azure Traffic Manager

	// ── Other CDN / infrastructure providers ─────────────────────────────────
	"akamaihd.net":          {}, // Akamai CDN
	"akamaized.net":         {}, // Akamai CDN
	"b-cdn.net":             {}, // BunnyCDN
	"cdn77.org":             {}, // CDN77
	"cdnjs.cloudflare.com":  {}, // Cloudflare public CDN — not user content, but
	                             // synthesising it would wrongly categorise many
	                             // legitimate sites that load shared JS libraries
	"fastly.net":            {}, // Fastly CDN — customer CNAMEs
	"pages.cloudflare.com":  {}, // Cloudflare Pages alt domain
	"workers.dev":           {}, // Cloudflare Workers

	// ── Tunnelling / dynamic DNS / reverse proxy ──────────────────────────────
	"ddns.net":           {}, // No-IP dynamic DNS
	"duckdns.org":        {}, // DuckDNS dynamic DNS
	"dynu.net":           {}, // Dynu dynamic DNS
	"dynv6.com":          {}, // dynv6
	"hopto.org":          {}, // No-IP dynamic DNS
	"loca.lt":            {}, // localtunnel short domain
	"localhost.run":      {}, // localhost.run SSH tunnels
	"localtunnel.me":     {}, // localtunnel
	"ngrok-free.app":     {}, // ngrok free tier
	"ngrok.io":           {}, // ngrok tunnels
	"no-ip.biz":          {}, // No-IP
	"no-ip.org":          {}, // No-IP
	"redirectme.net":     {}, // No-IP
	"serveblog.net":      {}, // No-IP
	"serveftp.com":       {}, // No-IP
	"servehttp.com":      {}, // No-IP
	"serveminecraft.net": {}, // No-IP — gaming servers (still a shared namespace)
	"serveo.net":         {}, // Serveo tunnels
	"sytes.net":          {}, // No-IP dynamic DNS
	"trycloudflare.com":  {}, // Cloudflare Tunnel (dev/testing)
	"zapto.org":          {}, // No-IP dynamic DNS

	// ── Wikis / collaborative platforms ──────────────────────────────────────
	"fandom.com":   {}, // Fandom wikis
	"pbwiki.com":   {}, // PBworks legacy
	"pbworks.com":  {}, // PBworks wikis
	"wikia.com":    {}, // Fandom/Wikia wikis (legacy domain)
	"wikidot.com":  {}, // Wikidot
}

// isSharedHostingDomain reports whether d is a domain under which unrelated
// third parties host their own content. Synthesising d as a category-list
// apex entry would wrongly categorise those third parties under whatever
// category their neighbours happened to appear in.
//
// Input must be lowercased with no trailing dot (parental.go always normalises
// before calling). O(1) map lookup — zero allocations.
//
// Works alongside isPublicSuffix() (registry boundaries) and the category
// homogeneity check (multi-category parents). Together the three mechanisms
// cover the full range of false-positive risks in consolidateParentDomains().
func isSharedHostingDomain(d string) bool {
	// Direct map hit — the exact domain is a known shared host.
	if _, ok := sharedHostingDomains[d]; ok {
		return true
	}

	// Suffix walk: check whether d is a subdomain of a known shared host.
	// e.g. "eu-west-1.amazonaws.com" → "amazonaws.com" hit.
	// Cap at 2 strips (3-label → 1-label) — no shared-hosting entry is deeper
	// than 3 labels, and deeper subdomains are legitimate customer namespaces.
	search := d
	for i := 0; i < 2; i++ {
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
		if _, ok := sharedHostingDomains[search]; ok {
			return true
		}
	}

	return false
}

