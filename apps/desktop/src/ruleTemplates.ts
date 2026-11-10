import type { Config, EgressConfig, RuleConfig } from "./types";
import { usableEgresses } from "./configUtils";

/**
 * Ready-made rules: blocklists kept up to date from maintained sources (only
 * when the user presses Update lists), and the names and addresses of big
 * apps and sites, so each can be sent its own way. Each becomes an ordinary
 * rule the user can change afterwards.
 */
export interface RuleTemplate {
  id: string;
  name: string;
  group: TemplateGroup;
  /** What the rule covers, in a line. */
  about: string;
  /** Block rules refuse; the rest send the traffic a way the user picks. */
  does: "reject" | "route";
  /** For `route`: the kind of outbound picked at first. */
  prefer?: "direct" | "proxy";
  domains?: string[];
  cidrs?: string[];
  lists?: string[];
}

export type TemplateGroup = "Protection" | "Apps and sites" | "Region";

export const TEMPLATE_GROUPS: { group: TemplateGroup; hint: string }[] = [
  { group: "Protection", hint: "Blocklists from maintained sources. Press Update lists after adding one, and again now and then to keep it current." },
  { group: "Apps and sites", hint: "Websites and addresses of each service. Send them through an outbound, straight out, or block them." },
  { group: "Region", hint: "A country's sites and addresses, usually sent straight out." },
];

const HAGEZI = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest";

export const RULE_TEMPLATES: RuleTemplate[] = [
  // ---- Protection
  {
    id: "ads",
    name: "Block ads and trackers",
    group: "Protection",
    about: "Ads, trackers and telemetry, including Persian sites' ad networks (HaGeZi Normal, PersianBlocker).",
    does: "reject",
    lists: [`${HAGEZI}/wildcard/multi-onlydomains.txt`, "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt"],
  },
  {
    id: "malware",
    name: "Block malicious sites",
    group: "Protection",
    about: "Malware, phishing, scams and crypto-jacking sites (HaGeZi Threat Intelligence).",
    does: "reject",
    lists: [`${HAGEZI}/wildcard/tif.medium-onlydomains.txt`],
  },
  {
    id: "bad-ips",
    name: "Block malicious IP ranges",
    group: "Protection",
    about: "Networks run by criminals and botnet servers (Spamhaus DROP, HaGeZi Threat Intelligence addresses).",
    does: "reject",
    lists: ["https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json", `${HAGEZI}/ips/tif.txt`],
  },

  // ---- Apps and sites
  {
    id: "telegram",
    name: "Telegram",
    group: "Apps and sites",
    about: "Telegram's sites and its own address ranges (kept current from telegram.org).",
    does: "route",
    prefer: "proxy",
    domains: [
      "telegram.org", "t.me", "telegram.me", "telegra.ph", "telesco.pe", "tdesktop.com", "telegram.dog", "telegram.space", "tg.dev",
      "cdn-telegram.org", "telegram-cdn.org", "fragment.com", "graph.org", "contest.com", "comments.app", "usercontent.dev",
    ],
    cidrs: [
      "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22", "91.105.192.0/23",
      "149.154.160.0/20", "185.76.151.0/24", "2001:b28:f23c::/48", "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48",
      "2a0a:f280::/32",
    ],
    lists: ["https://core.telegram.org/resources/cidr.txt"],
  },
  {
    id: "whatsapp",
    name: "WhatsApp",
    group: "Apps and sites",
    about: "Messages, calls and media.",
    does: "route",
    prefer: "proxy",
    domains: ["whatsapp.com", "whatsapp.net", "wa.me", "whatsapp.biz", "whatsapp.info", "whatsapp.org", "whatsapp.tv", "whatsappbrand.com"],
  },
  {
    id: "instagram",
    name: "Instagram and Threads",
    group: "Apps and sites",
    about: "The app, its photos and videos, and Threads.",
    does: "route",
    prefer: "proxy",
    domains: ["instagram.com", "cdninstagram.com", "ig.me", "instagr.am", "igcdn.com", "igsonar.com", "fbcdn.net", "threads.net", "threads.com"],
  },
  {
    id: "facebook",
    name: "Facebook and Messenger",
    group: "Apps and sites",
    about: "Facebook, Messenger and Meta's other sites.",
    does: "route",
    prefer: "proxy",
    domains: [
      "facebook.com", "fb.com", "fb.me", "fbcdn.net", "fbsbx.com", "facebook.net", "fb.gg", "messenger.com", "m.me", "meta.com", "meta.ai",
      "thefacebook.com",
    ],
  },
  {
    id: "youtube",
    name: "YouTube",
    group: "Apps and sites",
    about: "Videos, the app and YouTube Kids.",
    does: "route",
    prefer: "proxy",
    domains: [
      "youtube.com", "youtu.be", "yt.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com", "ggpht.com", "youtubekids.com",
      "withyoutube.com", "full:youtubei.googleapis.com", "full:youtube.googleapis.com", "full:jnn-pa.googleapis.com",
    ],
  },
  {
    id: "x",
    name: "X (Twitter)",
    group: "Apps and sites",
    about: "Posts, images and videos.",
    does: "route",
    prefer: "proxy",
    domains: ["x.com", "twitter.com", "twimg.com", "t.co", "twttr.com", "ads-twitter.com", "pscp.tv", "periscope.tv", "tweetdeck.com", "cms-twdigitalassets.com"],
  },
  {
    id: "tiktok",
    name: "TikTok",
    group: "Apps and sites",
    about: "Videos, live streams and the app.",
    does: "route",
    prefer: "proxy",
    domains: [
      "tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokv.eu", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com", "ttwstatic.com",
      "ibytedtos.com", "ibyteimg.com", "byteoversea.com", "muscdn.com", "musical.ly", "tik-tokapi.com", "ttlivecdn.com",
    ],
  },
  {
    id: "snapchat",
    name: "Snapchat",
    group: "Apps and sites",
    about: "Snaps, chat and stories.",
    does: "route",
    prefer: "proxy",
    domains: [
      "snapchat.com", "snap.com", "snapkit.com", "snapads.com", "sc-cdn.net", "sc-static.net", "sc-gw.com", "sc-prod.net", "sc-jpl.com",
      "snap-dev.net", "full:feelinsonice-hrd.appspot.com",
    ],
  },
  {
    id: "discord",
    name: "Discord",
    group: "Apps and sites",
    about: "Chat, voice and media.",
    does: "route",
    prefer: "proxy",
    domains: [
      "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com", "discord.co", "discord.dev",
      "discord.new", "discord.gift", "discord.gifts", "discordstatus.com", "dis.gd",
    ],
  },
  {
    id: "signal",
    name: "Signal",
    group: "Apps and sites",
    about: "Messages and calls.",
    does: "route",
    prefer: "proxy",
    domains: ["signal.org", "signal.art", "signal.group", "signal.me", "signal.link", "signal.tube", "whispersystems.org", "signalusers.org"],
  },
  {
    id: "reddit",
    name: "Reddit",
    group: "Apps and sites",
    about: "Posts, images and videos.",
    does: "route",
    prefer: "proxy",
    domains: ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "reddituploads.com", "redditinc.com"],
  },
  {
    id: "linkedin",
    name: "LinkedIn",
    group: "Apps and sites",
    about: "The site and the app.",
    does: "route",
    prefer: "proxy",
    domains: ["linkedin.com", "licdn.com", "lnkd.in"],
  },
  {
    id: "pinterest",
    name: "Pinterest",
    group: "Apps and sites",
    about: "Pins and images.",
    does: "route",
    prefer: "proxy",
    domains: ["pinterest.com", "pinimg.com", "pin.it"],
  },
  {
    id: "twitch",
    name: "Twitch",
    group: "Apps and sites",
    about: "Live streams and chat.",
    does: "route",
    prefer: "proxy",
    domains: ["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net", "ext-twitch.tv", "twitchapps.com", "live-video.net"],
  },
  {
    id: "spotify",
    name: "Spotify",
    group: "Apps and sites",
    about: "Music, podcasts and the app.",
    does: "route",
    prefer: "proxy",
    domains: ["spotify.com", "scdn.co", "spotifycdn.com", "spotifycdn.net", "spoti.fi", "spotify.link", "pscdn.co", "spotilocal.com", "spotify.design", "spotifycharts.com"],
  },
  {
    id: "soundcloud",
    name: "SoundCloud",
    group: "Apps and sites",
    about: "Music and podcasts.",
    does: "route",
    prefer: "proxy",
    domains: ["soundcloud.com", "sndcdn.com"],
  },
  {
    id: "netflix",
    name: "Netflix",
    group: "Apps and sites",
    about: "Films, series and fast.com.",
    does: "route",
    prefer: "proxy",
    domains: ["netflix.com", "netflix.net", "nflxext.com", "nflximg.com", "nflximg.net", "nflxso.net", "nflxvideo.net", "nflxsearch.net", "fast.com"],
  },
  {
    id: "chatgpt",
    name: "ChatGPT",
    group: "Apps and sites",
    about: "ChatGPT, Sora and OpenAI's sites.",
    does: "route",
    prefer: "proxy",
    domains: ["openai.com", "chatgpt.com", "chat.com", "oaistatic.com", "oaiusercontent.com", "sora.com", "full:openaiapi-site.azureedge.net"],
  },
  {
    id: "gemini",
    name: "Gemini",
    group: "Apps and sites",
    about: "Gemini, AI Studio and NotebookLM, without the rest of Google.",
    does: "route",
    prefer: "proxy",
    domains: [
      "gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com", "notebooklm.google.com", "makersuite.google.com",
      "bard.google.com", "deepmind.google", "deepmind.com", "labs.google", "full:alkalimakersuite-pa.clients6.google.com",
      "full:alkalicore-pa.clients6.google.com", "full:waa-pa.clients6.google.com",
    ],
  },
  {
    id: "claude",
    name: "Claude",
    group: "Apps and sites",
    about: "Claude and Anthropic's sites.",
    does: "route",
    prefer: "proxy",
    domains: ["claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com", "clau.de"],
  },
  {
    id: "google",
    name: "Google",
    group: "Apps and sites",
    about: "Search, Gmail, Drive, Maps and Android services (YouTube has its own rule).",
    does: "route",
    prefer: "proxy",
    domains: [
      "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gmail.com", "goo.gl", "g.co", "gvt1.com", "gvt2.com", "gvt3.com",
      "android.com", "withgoogle.com", "google.dev", "googledrive.com", "googlesource.com", "googleblog.com", "gmodules.com",
    ],
  },
  {
    id: "github",
    name: "GitHub",
    group: "Apps and sites",
    about: "Code, downloads and Copilot.",
    does: "route",
    prefer: "proxy",
    domains: ["github.com", "githubusercontent.com", "githubassets.com", "github.io", "ghcr.io", "githubcopilot.com", "github.dev", "githubapp.com", "github.blog"],
  },
  {
    id: "steam",
    name: "Steam",
    group: "Apps and sites",
    about: "The store, community and game downloads.",
    does: "route",
    prefer: "proxy",
    domains: [
      "steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steamusercontent.com", "steamgames.com",
      "steam-chat.com", "valvesoftware.com", "full:steamcdn-a.akamaihd.net",
    ],
  },
  {
    id: "zoom",
    name: "Zoom",
    group: "Apps and sites",
    about: "Meetings and calls.",
    does: "route",
    prefer: "proxy",
    domains: ["zoom.us", "zoom.com", "zoomgov.com"],
  },

  // ---- Region
  {
    id: "iran",
    name: "Iranian sites",
    group: "Region",
    about: "Every .ir site, Iranian sites elsewhere and Iran's address ranges (bootmortis, ipverse).",
    does: "route",
    prefer: "direct",
    domains: [
      "ir", "digikala.com", "digistyle.com", "aparat.com", "filimo.com", "telewebion.com", "varzesh3.com", "torob.com", "sheypoor.com", "eitaa.com",
      "bale.ai", "gap.im", "igap.net", "namasha.com",
    ],
    lists: [
      "https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/domains.txt",
      "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt",
      "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv6-aggregated.txt",
    ],
  },
];

/** The outbound a template's rule starts with: the first of the kind it prefers, else the first at all. */
function startingEgress(config: Config, prefer: RuleTemplate["prefer"]): EgressConfig | undefined {
  const usable = usableEgresses(config).filter((e) => e.type !== "block");
  const direct = (e: EgressConfig) => e.type === "direct";
  const preferred = prefer === "direct" ? usable.find(direct) : prefer === "proxy" ? usable.find((e) => !direct(e)) : undefined;
  return preferred ?? usable[0];
}

/** The rule a template starts the editor with. */
export function ruleFromTemplate(template: RuleTemplate, config: Config): RuleConfig {
  return {
    name: template.name,
    enabled: true,
    domains: template.domains?.slice(),
    cidrs: template.cidrs?.slice(),
    lists: template.lists?.slice(),
    action: template.does === "reject" ? "reject" : { route: startingEgress(config, template.prefer)?.id ?? "" },
  };
}
