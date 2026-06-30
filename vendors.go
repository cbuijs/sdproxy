/*
File:    vendors.go
Version: 1.7.0 (Split)
Updated: 2026-04-10

Description:
  Vendor tracking mapping for the sdproxy web UI stats.
  Extracted from publicsuffix.go to improve modularity and reduce file size.
  
  vendorMap binds widely-used apex domains to their owning companies.
  Mapped comprehensively to identify the "Magnificent Seven", GAFAM, FANG, FAANG,
  MAMAA, BATX (Baidu, Alibaba, Tencent, Xiaomi/ByteDance), global Top-25
  most connected tech internet services, and Top DuckDuckGo Tracker Radar entities.
*/

package main

// getVendor maps an eTLD+1 domain to a known internet vendor/service.
func getVendor(etldPlusOne string) string {
	if vendor, ok := vendorMap[etldPlusOne]; ok {
		return vendor
	}
	return ""
}

// vendorMap binds widely-used apex domains to their owning companies.
// Mapped comprehensively to identify the "Magnificent Seven", GAFAM, FANG, FAANG,
// MAMAA, BATX (Baidu, Alibaba, Tencent, Xiaomi/ByteDance) and the global Top-25
// most connected tech internet services.
// Also integrates top DuckDuckGo Tracker Radar entities to attribute ad-networks
// and analytics domains to their parent companies properly.
// Sorted alphabetically by Vendor (category) and then by domain key.
var vendorMap = map[string]string{
	// 33Across - Tracker Radar
	"33across.com": "33Across",

	// Adform - Tracker Radar
	"adform.net": "Adform",

	// Adobe
	"adobe.com":       "Adobe",
	"demdex.net":      "Adobe (Audience Manager)",
	"everesttech.net": "Adobe",
	"omtrdc.net":      "Adobe",

	// Akamai - CDN
	"akamai.net":     "Akamai",
	"akamaiedge.net": "Akamai",
	"akamaized.net":  "Akamai",

	// Alibaba - BATX / Chinese Giant
	"alibaba.com":    "Alibaba",
	"alicdn.com":     "Alibaba",
	"aliexpress.com": "Alibaba",
	"taobao.com":     "Alibaba",
	"tmall.com":      "Alibaba",

	// Alphabet (Google) - GAFAM / Magnificent Seven / FAANG
	"1e100.net":             "Alphabet (Google)",
	"appspot.com":           "Alphabet (Google)",
	"blogger.com":           "Alphabet (Google)",
	"doubleclick.net":       "Alphabet (Google-Analytics)",
	"google-analytics.com":  "Alphabet (Google-Analytics)",
	"google.ca":             "Alphabet (Google)",
	"google.co.in":          "Alphabet (Google)",
	"google.co.jp":          "Alphabet (Google)",
	"google.co.uk":          "Alphabet (Google)",
	"google.com":            "Alphabet (Google)",
	"google.com.au":         "Alphabet (Google)",
	"google.com.br":         "Alphabet (Google)",
	"google.de":             "Alphabet (Google)",
	"google.nl":             "Alphabet (Google)",
	"googleadservices.com":  "Alphabet (Google-Analytics)",
	"googleapis.com":        "Alphabet (Google)",
	"googlesyndication.com": "Alphabet (Google-Analytics)",
	"googletagmanager.com":  "Alphabet (Google-Analytics)",
	"googleusercontent.com": "Alphabet (Google)",
	"gstatic.com":           "Alphabet (Google)",
	"youtu.be":              "Alphabet (Google)",
	"youtube.com":           "Alphabet (Google)",

	// Amazon - GAFAM / Magnificent Seven / FAANG
	"amazon-adsystem.com": "Amazon",
	"amazon.co.jp":        "Amazon",
	"amazon.co.uk":        "Amazon",
	"amazon.com":          "Amazon",
	"amazon.de":           "Amazon",
	"amazonaws.com":       "Amazon",
	"aws.com":             "Amazon (AWS)",
	"cloudfront.net":      "Amazon (CloudFront)",
	"primevideo.com":      "Amazon (Prime)",
	"twitch.tv":           "Amazon",

	// Apple - GAFAM / Magnificent Seven / FAANG
	"aaplimg.com":   "Apple",
	"apple-dns.net": "Apple (DNS)",
	"apple.com":     "Apple",
	"cdn-apple.com": "Apple (CDN)",
	"icloud.com":    "Apple (iCloud)",
	"mzstatic.com":  "Apple",

	// Atlassian - Top 25
	"atlassian.com": "Atlassian",
	"bitbucket.org": "Atlassian (BitBucket)",
	"trello.com":    "Atlassian (Trello)",

	// Automattic - Top 25
	"automattic.com": "Automattic",
	"gravatar.com":   "Automattic (Gravatar)",
	"wordpress.com":  "Automattic (WordPress)",
	"wp.com":         "Automattic (WordPress)",

	// Aylo - Top 25
	"phncdn.com":  "Aylo",
	"pornhub.com": "Aylo",

	// Baidu - BATX / Chinese Giant
	"baidu.com":    "Baidu",
	"bdimg.com":    "Baidu",
	"bdstatic.com": "Baidu",

	// Bilibili - Top 25
	"bilibili.com": "Bilibili",
	"hdslb.com":    "Bilibili",

	// Blizzard - Gaming Giant
	"blizzard.com": "Blizzard",

	// ByteDance (TikTok) - BATX / Top 25
	"bytedance.com":   "ByteDance (TikTok)",
	"byteoversea.com": "ByteDance (TikTok)",
	"tiktok.com":      "ByteDance (TikTok)",
	"tiktokcdn.com":   "ByteDance (TikTok)",
	"tiktokv.com":     "ByteDance (TikTok)",
	"toutiao.com":     "ByteDance (TikTok)",

	// Canva - Top 25
	"canva.com": "Canva",

	// Cloudflare - CDN
	"cloudflare-dns.com": "Cloudflare",
	"cloudflare.com":     "Cloudflare",
	"cloudflare.net":     "Cloudflare",

	// Comscore - Tracker Radar
	"scorecardresearch.com": "Comscore",
	"voicefive.com":         "Comscore",

	// Criteo - Tracker Radar
	"criteo.com": "Criteo",
	"criteo.net": "Criteo",

	// Disney
	"disneyplus.com": "Disney",

	// DoubleVerify - Tracker Radar
	"doubleverify.com": "DoubleVerify",

	// Dropbox
	"dropbox.com": "Dropbox",

	// DuckDuckGo - Top 25
	"duckduckgo.com": "DuckDuckGo",

	// eBay - Top 25
	"ebay.com": "eBay",

	// Electronic Arts - Gaming Giant
	"ea.com": "Electronic Arts",

	// Epic Games - Gaming Giant
	"epicgames.com": "Epic Games",

	// Fandom - Top 25
	"fandom.com": "Fandom",
	"wikia.com":  "Fandom",

	// Fastly - CDN
	"fastly.net": "Fastly",

	// Globo - Top 25
	"globo.com": "Globo",

	// Hotjar - Tracker Radar
	"hotjar.com": "Hotjar",

	// Hulu
	"hulu.com": "Hulu",

	// IBM - Top 25
	"ibm.com":     "IBM",
	"weather.com": "IBM",

	// Index Exchange - Tracker Radar
	"casalemedia.com": "Index Exchange",

	// Integral Ad Science (IAS) - Tracker Radar
	"adsafeprotected.com": "Integral Ad Science (IAS)",

	// LiveRamp - Tracker Radar
	"adroll.com": "LiveRamp (AdRoll)",
	"rlcdn.com":  "LiveRamp",

	// Lotame - Tracker Radar
	"crwdcntrl.net": "Lotame",

	// Magnite (Rubicon Project) - Tracker Radar
	"rubiconproject.com": "Magnite (Rubicon Project)",

	// MediaMath - Tracker Radar
	"mathtag.com":   "MediaMath",
	"mediamath.com": "MediaMath",

	// Meta - GAFAM / Magnificent Seven / FAANG
	"facebook.com":  "Meta (Facebook)",
	"fb.com":        "Meta (Facebook)",
	"fbcdn.net":     "Meta (Facebook)",
	"instagram.com": "Meta (Instagram)",
	"messenger.com": "Meta (Messenger)",
	"whatsapp.com":  "Meta (WhatsApp)",
	"whatsapp.net":  "Meta (WhatsApp)",

	// Microsoft - GAFAM / Magnificent Seven
	"azure.com":             "Microsoft (Azure)",
	"azureedge.net":         "Microsoft (Azure)",
	"bing.com":              "Microsoft (Bing)",
	"clarity.ms":            "Microsoft (Clarity)",
	"github.com":            "Microsoft (GitHub)",
	"githubusercontent.com": "Microsoft (GitHub)",
	"linkedin.com":          "Microsoft (LinkedIn)",
	"live.com":              "Microsoft",
	"lync.com":              "Microsoft (Skype/Teams)",
	"microsoft":             "Microsoft",
	"microsoft.com":         "Microsoft",
	"microsoftonline.com":   "Microsoft",
	"msn.com":               "Microsoft (MSN)",
	"office.com":            "Microsoft (Office)",
	"office365.com":         "Microsoft (Office)",
	"sharepoint.com":        "Microsoft (SharePoint)",
	"skype.com":             "Microsoft (Skype/Teams)",
	"teams.cloud.microsoft": "Microsoft (Skype/Teams)",
	"teams.microsoft.com":   "Microsoft (Skype/Teams)",
	"trafficmanager.net":    "Microsoft",
	"windows.com":           "Microsoft (Windows)",
	"windows.net":           "Microsoft (Windows)",
	"windowsupdate.com":     "Microsoft (Windows)",

	// Naver - Top 25
	"line.me":   "Naver",
	"naver.com": "Naver",
	"naver.net": "Naver",

	// Netflix - FAANG
	"netflix.com":   "Netflix",
	"nflxext.com":   "Netflix",
	"nflximg.net":   "Netflix",
	"nflxvideo.net": "Netflix",

	// Nielsen - Tracker Radar
	"exelator.com": "Nielsen (eXelate)",
	"krxd.net":     "Nielsen (Krux)",

	// Nintendo - Gaming Giant
	"nintendo.com": "Nintendo",
	"nintendo.net": "Nintendo",

	// Nvidia - Magnificent Seven
	"geforce.com": "Nvidia",
	"geforce.net": "Nvidia",
	"nvda.ws":     "Nvidia",
	"nvidia.com":  "Nvidia",

	// OpenAI - Top 25
	"chatgpt.com": "OpenAI",
	"openai.com":  "OpenAI",

	// OpenX - Tracker Radar
	"openx.net": "OpenX",

	// Optimizely - Tracker Radar
	"optimizely.com": "Optimizely",

	// Oracle - Tracker Radar
	"addthis.com": "Oracle",
	"bluekai.com": "Oracle",
	"moatads.com": "Oracle (Moat)",
	"oracle.com":  "Oracle",

	// Outbrain - Tracker Radar
	"outbrain.com":    "Outbrain",
	"outbrainimg.com": "Outbrain",
	"zemanta.com":     "Outbrain",

	// PDD Holdings (Temu) - Top 25
	"temu.com": "PDD Holdings (Temu)",

	// Pinterest - Top 25
	"pinimg.com":    "Pinterest",
	"pinterest.com": "Pinterest",

	// PubMatic - Tracker Radar
	"pubmatic.com": "PubMatic",

	// Quantcast - Tracker Radar
	"quantcount.com": "Quantcast",
	"quantserve.com": "Quantcast",

	// Reddit - Top 25
	"redd.it":         "Reddit",
	"reddit.com":      "Reddit",
	"redditmedia.com": "Reddit",

	// Riot Games - Gaming Giant
	"riotgames.com": "Riot Games",

	// Roblox - Gaming Giant
	"roblox.com": "Roblox",

	// Salesforce
	"salesforce.com": "SalesForce",

	// Samsung - Top 25
	"samsung.com": "Samsung",

	// Shopify - Top 25
	"myshopify.com": "Shopify",
	"shopify.com":   "Shopify",

	// Slack
	"slack.com": "Slack",

	// Smart AdServer - Tracker Radar
	"smartadserver.com": "Smart AdServer",

	// Spotify
	"scdn.co":        "Spotify",
	"spotify.com":    "Spotify",
	"spotifycdn.com": "Spotify",

	// Taboola - Tracker Radar
	"taboola.com": "Taboola",

	// Teads - Tracker Radar
	"teads.tv": "Teads",

	// Telegram - Top 25
	"t.me":         "Telegram",
	"telegram.org": "Telegram",

	// Tencent - BATX / Chinese Giant
	"gtimg.cn":    "Tencent",
	"gtimg.com":   "Tencent",
	"qq.com":      "Tencent",
	"tencent.com": "Tencent",
	"wechat.com":  "Tencent",
	"weibo.com":   "Tencent",

	// Tesla - Magnificent Seven
	"tesla.com":       "Tesla",
	"teslamotors.com": "Tesla",

	// The Trade Desk - Tracker Radar
	"adsrvr.org": "The Trade Desk",

	// Twilio - Tracker Radar
	"segment.com": "Twilio (Segment)",

	// Valve (Steam) - Gaming Giant
	"steamcommunity.com": "Valve (Steam)",
	"steampowered.com":   "Valve (Steam)",

	// VK - Top 25
	"mail.ru": "VK",
	"ok.ru":   "VK",
	"vk.com":  "VK",

	// WGCZ Holding - Top 25
	"xnxx.com":    "WGCZ Holding",
	"xvideos.com": "WGCZ Holding",

	// Wikimedia - Top 25
	"wikimedia.org": "Wikimedia",
	"wikipedia.org": "Wikimedia",

	// X Corp. - Top 25
	"ads-twitter.com": "X Corp",
	"t.co":            "X Corp",
	"twimg.com":       "X Corp",
	"twitter.com":     "X Corp",
	"x.com":           "X Corp",

	// Xandr (AppNexus) - Tracker Radar
	"appnexus.com": "Xandr (AppNexus)",

	// Yahoo - Top 25
	"advertising.com": "Yahoo",
	"yahoo.co.jp":     "Yahoo",
	"yahoo.com":       "Yahoo",
	"yimg.com":        "Yahoo",

	// Yandex - Top 25
	"yandex.net":   "Yandex",
	"yandex.ru":    "Yandex",
	"yastatic.net": "Yandex",

	// Zoom
	"zoom.us": "Zoom",
}

