# NyanCogs

Cogs for [Red Discord Bot](https://github.com/Cog-Creators/Red-DiscordBot).

## ChannelSummary

ChannelSummary creates attributed Discord channel summaries through an OpenAI-
compatible LLM Agent. It supports recent-message, explicit-start, and duration
ranges. The Agent can search additional history only in the invocation channel
and can use native OpenAI or OpenRouter web search when the selected profile
supports it. Generic Responses and Chat/CLIProxy profiles can instead use the
application-controlled Firecrawl cloud tools.

Install and load it with Red's Downloader:

```text
[p]cog install NyanCogs channelsummary
[p]load channelsummary
```

The bot owner then creates one or more global provider profiles. Profiles store
only endpoint, dialect, token-service name, and model allowlist metadata; API
keys remain in Red's shared API token storage.

```text
[p]summary provider add openai openai_responses https://api.openai.com channelsummary_openai gpt-5.6
[p]summary provider key openai

[p]summary provider add openrouter openrouter_responses https://openrouter.ai channelsummary_openrouter openai/gpt-5.6
[p]summary provider key openrouter

[p]summary provider webkey
[p]summary provider webquota 20
```

`web_enabled` is the guild master switch. `web_mode` is `auto`, `native`, or
`firecrawl`: `auto` keeps native hosted search for OpenAI/OpenRouter and selects
Firecrawl for other profiles when its separately stored key is present. There
is no runtime fallback between backends. Each summary can attempt at most 5
Firecrawl calls and expose at most five search results regardless of higher guild
settings; fetched markdown is capped by `web_fetch_max_chars`.

HTTP is restricted to RFC1918, IPv6 ULA, or loopback destinations. API keys
and selected Discord data traverse the LAN unencrypted; use HTTP only on a
trusted LAN. Prefer HTTPS whenever it is available.

Guild members with guild-level Manage Messages use `/summary settings` to pick
a profile and model, adjust limits through the Select and Modal panel, review
the data-export disclosure, and enable the Cog. Summaries are written in the dominant language of the
messages by default; `summary_language` forces one instead, as a single
identifier with no spaces such as `zh-TW`, `zh-Hant-TW`, or `Japanese`. The equivalent text
setting surface is `[p]summaryset set <key> <value>`; use
`[p]summary help` for every key, range, provider command, and privacy detail.

| Command | Purpose |
|---|---|
| `/summary auto [count]` | Summarize recent messages and search backward for the natural topic start |
| `/summary from <message>` | Summarize from an inclusive same-channel message ID or link |
| `/summary time <duration>` | Summarize a range such as `30m`, `2h`, or `1d` |
| `/summary settings` | Open the Manage Messages Select and Modal configuration panel |
| `[p]summaryset show` | Show all effective guild settings |
| `[p]summaryset set <key> <value>` | Change any documented text setting |
| `[p]summaryset reset <key\|all>` | Reset one setting or the full guild configuration |
| `[p]summaryset enable I_ACCEPT` / `[p]summaryset disable` | Enable after disclosure acceptance, or disable summaries |
| `[p]summaryset checkpoint <show\|reset>` | Inspect or clear this channel's successful-summary checkpoint |

While a summary runs, the bot updates one temporary channel status through
message collection, Agent context completion, and Embed rendering, then removes
it. The progress text never exposes hidden reasoning or raw tool payloads.

All users who can view and read the current channel may run a summary after a
guild enables it. The bot needs View Channel, Read Message History, Send
Messages, and Embed Links. A per-user cooldown, atomic guild request quota,
bounded guild/provider concurrency, and a persistent per-channel new-message
checkpoint limit API cost and repeated output. Defaults require 20 new human
messages after a successful summary before that channel can run another;
members with guild-level Manage Messages are exempt from that checkpoint, but
the cooldown, quota, and concurrency limits still apply to them.

The Embed footer reports what the summary consumed: input and output tokens,
reasoning tokens when the provider separates them, and the price when the
provider reports one. OpenRouter does; OpenAI does not, and no figure is
computed from a local price table.

Summary Embeds preserve validated `<@user_id>` speaker attribution but use
`AllowedMentions.none()`, so they do not notify anyone. Discord jump links are
constructed locally from supplied messages. Native-mode web links are rendered
only from provider citation annotations. Firecrawl-mode links are rendered only
from application-validated URLs in successful same-run Firecrawl search results;
model annotations and manually authored fetch URLs grant no authority. Rendering
performs no network I/O.

Selected message text, stable user and message IDs, timestamps, reply and embed
metadata leave Discord for the selected LLM. In Firecrawl mode, private
Discord-derived search queries and fetch URLs go to Firecrawl. Firecrawl-returned
URLs, titles, snippets, and markdown go to the LLM and may be resent across up
to 20 stateless turns. Firecrawl retention and training are unverified, and its
credits may incur cost. After a guild manager consents, any channel reader may
trigger these exports.

The owner Firecrawl hourly quota is one process-wide shared pool; one enabled
guild can exhaust Firecrawl availability and spend allowance for all guilds;
the guild request quota is not an owner Firecrawl budget control. A process
restart clears the in-memory pool, and multiple processes multiply the cap.
Firecrawl cloud is trusted to control target DNS, redirects, and SSRF; DNS
rebinding and split-horizon behavior remain residual vendor risk.

When images are enabled, the bot downloads each attachment, downscales it so its long edge is
at most `image_max_edge` pixels (3840 by default) and re-encodes it, then sends those bytes inline, so image
content may be resent to the LLM across up to 20 stateless turns while no Discord
CDN URL leaves this bot and EXIF metadata such as camera GPS is discarded before
sending. Provider retention and training are unverified. Attachments are limited
to 20 MiB and 25 MP each, 50 MiB and 100 MP total, and the first 20 eligible ones
in chronological order; the re-encoded images together may add at most 16 MB to a
request, so a lower `image_max_edge` fits more of them into one summary. ChannelSummary
does not persist messages, prompts, searches, provider responses, or summaries.
With an HTTP provider, API keys, selected Discord data, and inlined image bytes
traverse the LAN unencrypted. Use HTTP only on a trusted LAN. Its complete
statement is in
[`channelsummary/info.json`](channelsummary/info.json).

## MessageWatch

MessageWatch reports likely scam messages and hostile exchanges to a moderator
channel. It judges short rolling windows of recent messages with
[TypeSafe Jev](https://docs.typesafe.ai/), a model that returns calibrated
probabilities rather than text. It never deletes, edits, reacts to, or punishes
anything: the entire output is one report a moderator reads and acts on.

```text
[p]cog install NyanCogs messagewatch
[p]load messagewatch
[p]watch key                     # owner only, stores the TypeSafe api_key
[p]watch report #mod-log
[p]watch disclosure              # read it
[p]watch disclosure I_ACCEPT
[p]watch enable #a-channel       # one channel at a time
```

Every channel is opted in separately and sends nothing until it is. An enabled
channel is a standing export: message text goes to TypeSafe continuously, with
nobody triggering it, which is unlike the on-demand `/summary`. Discord user
IDs, display names and avatars are never sent; authors become labels such as
`u1` generated per request and never stored. Attachments, embeds and links are
not fetched or resolved. `[p]watch disable` stops a channel immediately and
drops anything pending for it.

Hostility and heat are judged over a window rather than a message, because an
argument is a property of an exchange. Window size, the report cooldown, and all
three thresholds are per-guild settings; `[p]watch show` prints the effective
values and `[p]watch set <key> <value>` changes one.

Defaults were measured on 2026-09-20 against `jev-1.13.0`. On synthetic cases
scams separated at 0.93 and above against 0.08 for a message *warning about* a
phishing mail, and hostility at 0.95 against 0.03 for a heated technical
argument. On 97 real messages from the target guild the maxima were 0.05, 0.15
and 1.53 out of 3, so the defaults sit far above observed background. False
negatives are not measured: that sample contained no scam and no argument to
catch, so the recall of this cog is unverified.

## EmbedFixer

EmbedFixer replaces supported social links with provider-fixed links sent by the
bot itself. It never impersonates the message author, never deletes the original
post, and never constructs a `discord.Embed`. After Discord confirms the
provider preview, the cog suppresses only the embeds on the original message.

When the author profile can be derived safely from the source URL, the
replacement row follows this format:

```text
[Source platform](fixed URL) • [@author](author profile) • [Provider](fixed URL)
```

Both the source-platform and provider labels link to the same fixed URL. Labels
are selected from the matched platform and provider rather than being hard-coded
to Twitter or FxTwitter. If the source URL does not contain a derivable author
profile, such as a Pixiv artwork URL, the middle author link is omitted.

### Requirements and installation

- Red Discord Bot 3.5.24 or later
- Python 3.11 or later
- No additional Python packages beyond Red's dependencies

Install the cog with Red's Downloader:

```text
[p]repo add NyanCogs https://github.com/Nanako0129/NyanCogs
[p]cog install NyanCogs embedfixer
[p]load embedfixer
```

Replace `[p]` with the bot's command prefix.

### Permissions

The bot needs the following permissions:

| Location | Permissions |
|---|---|
| Original message channel | View Channel, Read Message History, Manage Messages |
| Replacement or funnel channel | View Channel, Send Messages, Embed Links, Read Message History |
| Default reaction controls | Add Reactions; Use External Emojis when a custom external emoji is configured |

When the original and replacement use the same channel, the permissions from
both rows are required. `Manage Webhooks` is not used.

Server setting commands require Administrator or Manage Server. Regular members
may use `/fix`, `/extractmedia`, the message context menus, and their own
`ignoreme`, `usermode`, and `notify` settings when allowed by the guild's channel,
role, domain, and user rules.

### Commands

| Command | Purpose |
|---|---|
| `[p]fix <link>` / `/fix` | Post ordinary fixed provider links |
| `[p]extractmedia <link>` / `/extractmedia` | Add bounded media URLs for supported metadata providers |
| Message → Apps → Fix Embed | Fix links in an existing message |
| Message → Apps → Extract Media | Extract supported media metadata from an existing message |
| `[p]embedfixer` / `[p]ef` | Show the effective mode and basic state |
| `[p]embedfixer ignoreme` | Opt your messages in or out of automatic fixing |
| `[p]embedfixer usermode` | Follow or override the guild delivery mode |
| `[p]embedfixer notify` | Toggle generic reaction notifications |

Use `[p]help embedfixer` for the complete administrator command list. It includes
enablement, delivery mode, channel and role rules, domain/provider selection,
delete and rotate controls, funnel routing, media extraction channels, optional
post content, spoiler policy, FxTwitter translation, other-bot visibility,
ignored users, reset, import, and export.

The legacy mode name `delete_and_resend` is retained for upstream setting
compatibility. In this cog it does not delete the original message; it has the
same direct bot-send behavior as `resend`. Only `reply` changes where the bot
message is attached.

### Behavior and limits

| Area | Behavior |
|---|---|
| Original message | Never deleted; only its embeds may be suppressed after replacement confirmation |
| Sender identity | Always the bot; no webhook, copied avatar, or copied username |
| Ordinary output | Link-only Markdown row; Discord creates the provider preview |
| Metadata extraction | Twitter/X, Pixiv, and Bluesky only |
| Media handling | Emits allowlisted HTTPS media URLs; never downloads, transcodes, or uploads media bytes |
| Translation | Exactly two ASCII letters and FxTwitter only |
| Funnel routing | Same-guild text channels only; NSFW content cannot be routed to a non-NSFW channel |
| Failures | Unsafe or malformed metadata falls back to the ordinary fixed link; the original is not deleted |
| Ownership controls | Only the original author can delete or rotate eligible bot replacements |

Automatic extraction channels still apply ordinary link fixing to other
supported platforms without fetching metadata. Explicit Extract Media operations
reject platforms outside Twitter/X, Pixiv, and Bluesky.

Kemono media extraction, webhook impersonation, source-message deletion,
provider media downloads, and the upstream database/web dashboard are
intentionally not included.

### Privacy

The cog stores guild/user settings and bounded scalar replacement-ownership
records in Red Config. Records contain IDs, provider/domain identifiers, and
timestamps, but not message content, full URLs, or provider responses.

Provider metadata, optional sanitized post text, and media URLs are processed
transiently for extraction and are not stored, cached, or logged by the cog.
Red's user-data deletion hook removes that user's settings, ownership records,
and notification throttles. The complete data statement is in
[`embedfixer/info.json`](embedfixer/info.json).

### Attribution and license

The provider inventory and transformation rules are adapted from
[`seriaati/embed-fixer`](https://github.com/seriaati/embed-fixer) at upstream
commit
[`42be298c49c3c3910859d1f27943abf9c4e95eb8`](https://github.com/seriaati/embed-fixer/tree/42be298c49c3c3910859d1f27943abf9c4e95eb8).
This Red Cog preserves the upstream GPL-3.0 licensing and is distributed under
this repository's [GPL-3.0 license](LICENSE).
