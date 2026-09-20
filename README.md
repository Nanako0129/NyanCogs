**English** | [繁體中文](README.zh-TW.md)

# NyanCogs

Cogs for [Red Discord Bot](https://github.com/Cog-Creators/Red-DiscordBot).

| Cog | What it does |
|---|---|
| [ChannelSummary](#channelsummary) | Attributed channel summaries through an OpenAI-compatible LLM Agent |
| [MessageWatch](#messagewatch) | Reports likely scams and hostile exchanges to a moderator channel |
| [EmbedFixer](#embedfixer) | Replaces supported social links with provider-fixed links |

Design notes for MessageWatch live in [`docs/`](docs/), in English and
Traditional Chinese.

## ChannelSummary

ChannelSummary creates attributed Discord channel summaries through an OpenAI-
compatible LLM Agent. It supports recent-message, explicit-start, and duration
ranges. The Agent can search additional history only in the invocation channel
and can use native OpenAI or OpenRouter web search when the selected profile
supports it. Generic Responses and Chat/CLIProxy profiles can instead use the
application-controlled Firecrawl cloud tools.

### Installation

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

### Web search

`web_enabled` is the guild master switch. `web_mode` selects the backend, and
there is no runtime fallback between them.

| `web_mode` | Behaviour |
|---|---|
| `auto` | Native hosted search for OpenAI/OpenRouter; Firecrawl for other profiles when its separately stored key is present |
| `native` | The provider's own hosted search |
| `firecrawl` | The application-controlled Firecrawl cloud tools |

Each summary can attempt at most 5 Firecrawl calls and expose at most five
search results regardless of higher guild settings; fetched markdown is capped
by `web_fetch_max_chars`.

> ⚠️ **An HTTP provider puts keys on the wire in clear.**

HTTP is restricted to RFC1918, IPv6 ULA, or loopback destinations. With an HTTP
provider, API keys, selected Discord data, and inlined image bytes traverse the
LAN unencrypted. Use HTTP only on a trusted LAN. Prefer HTTPS whenever it is
available.

### Configuration

Guild members with guild-level Manage Messages use `/summary settings` to pick a
profile and model, adjust limits through the Select and Modal panel, review the
data-export disclosure, and enable the cog. The equivalent text surface is
`[p]summaryset set <key> <value>`; `[p]summary help` lists every key, range,
provider command, and privacy detail.

Summaries are written in the dominant language of the messages by default.
`summary_language` forces one instead, as a single identifier with no spaces such
as `zh-TW`, `zh-Hant-TW`, or `Japanese`.

### Commands

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

### Access and rate limits

All users who can view and read the current channel may run a summary after a
guild enables it. The bot needs View Channel, Read Message History, Send
Messages, and Embed Links.

| Control | Effect |
|---|---|
| Per-user cooldown | Limits how often one member can trigger a summary |
| Atomic guild request quota | Caps requests per guild |
| Bounded guild/provider concurrency | Caps simultaneous runs |
| Per-channel new-message checkpoint | Requires 20 new human messages after a successful summary before that channel can run another |

Members with guild-level Manage Messages are exempt from the checkpoint, but the
cooldown, quota, and concurrency limits still apply to them.

The Embed footer reports what the summary consumed: input and output tokens,
reasoning tokens when the provider separates them, and the price when the
provider reports one. OpenRouter does; OpenAI does not, and no figure is computed
from a local price table.

### Link and mention safety

Summary Embeds preserve validated `<@user_id>` speaker attribution but use
`AllowedMentions.none()`, so they do not notify anyone. Rendering performs no
network I/O.

| Link kind | Source of authority |
|---|---|
| Discord jump links | Constructed locally from supplied messages |
| Native-mode web links | Provider citation annotations only |
| Firecrawl-mode web links | Application-validated URLs in successful same-run Firecrawl search results only |

Model annotations and manually authored fetch URLs grant no authority.

### Images

When images are enabled, the bot downloads each attachment, downscales it so its
long edge is at most `image_max_edge` pixels (3840 by default) and re-encodes it,
then sends those bytes inline, so no Discord CDN URL leaves this bot and EXIF
metadata such as camera GPS is discarded before sending.

| Limit | Value |
|---|---|
| Per attachment | 20 MiB and 25 MP |
| Per request, all attachments | 50 MiB and 100 MP |
| Attachments considered | The first 20 eligible ones in chronological order |
| Re-encoded bytes added to one request | At most 16 MB |

A lower `image_max_edge` fits more images into one summary.

### Privacy

Selected message text, stable user and message IDs, timestamps, reply and embed
metadata leave Discord for the selected LLM. Image content may be resent to the
LLM across up to 20 stateless turns. In Firecrawl mode, private Discord-derived
search queries and fetch URLs go to Firecrawl; Firecrawl-returned URLs, titles,
snippets, and markdown go to the LLM and may likewise be resent across up to 20
turns.

Provider retention and training are unverified. Firecrawl retention and training
are unverified, and its credits may incur cost. After a guild manager consents,
any channel reader may trigger these exports.

> ⚠️ **Firecrawl's hourly quota is shared across every guild.**

The owner Firecrawl hourly quota is one process-wide shared pool; one enabled
guild can exhaust Firecrawl availability and spend allowance for all guilds; the
guild request quota is not an owner Firecrawl budget control. A process restart
clears the in-memory pool, and multiple processes multiply the cap.

Firecrawl cloud is trusted to control target DNS, redirects, and SSRF; DNS
rebinding and split-horizon behavior remain residual vendor risk.

ChannelSummary does not persist messages, prompts, searches, provider responses,
or summaries. The complete statement is in
[`channelsummary/info.json`](channelsummary/info.json).

## MessageWatch

MessageWatch reports likely scam messages and hostile exchanges to a moderator
channel. It judges short rolling windows of recent messages with
[TypeSafe Jev](https://docs.typesafe.ai/), a model that returns calibrated
probabilities rather than text, and it never acts on its own.

| Document | Contents |
|---|---|
| [`docs/messagewatch-design.md`](docs/messagewatch-design.md) · [繁體中文](docs/messagewatch-design.zh-TW.md) | Design rationale — why the cog is shaped this way |
| [`docs/jev-integration.md`](docs/jev-integration.md) · [繁體中文](docs/jev-integration.zh-TW.md) | Question design and the measurements behind every threshold |

### Installation

```text
[p]cog install NyanCogs messagewatch
[p]load messagewatch
[p]watch key                     # owner only, stores the TypeSafe api_key
[p]watch report #mod-log         # the guild-wide default
[p]watch route #樹洞 #樹洞管理    # one channel's reports, sent elsewhere
[p]watch disclosure              # read it
[p]watch disclosure I_ACCEPT
[p]watch enable #a-channel       # one channel at a time
```

Every channel is opted in separately and sends nothing until it is.

> ⚠️ **An enabled channel is a standing export.** Message text goes to TypeSafe
> continuously, with nobody triggering it, which is unlike the on-demand
> `/summary`. A venting or confession channel is where this costs the most: what
> people write there is what they expect will not be repeated.

Each request also carries the name of the channel and, where rules are configured for
that channel, those rules and its purpose note. Discord user IDs, display names
and avatars are never sent; authors become labels such as `u1`, generated per
request and never stored. Embeds and links are never fetched or resolved, and
image attachments are fetched only in a channel where a manager turned image
reading on.

`[p]watch disable` drops everything queued for a channel immediately and stops it
being read again. It does not cancel a report already in flight: it takes the
same channel lock `flush` holds, so it waits for a flush that has already
started, and that flush still delivers its report.

### Report buttons

Which buttons a report carries is set per channel and defaults to the two marks.

```text
[p]watch action set #一般討論 ok no del      # marks plus delete
[p]watch action set #樹洞 ok no role         # marks plus a blacklist role
[p]watch action role #樹洞 @樹洞黑名單
[p]watch marks                               # what moderators have marked so far
```

| Button | Effect | Permission required of the presser |
|---|---|---|
| `ok` | Records that the report was right | None beyond reaching the moderator channel |
| `no` | Records that the report was wrong | None beyond reaching the moderator channel |
| `del` | Deletes the flagged message | `manage_messages` |
| `mute` | Times the author out | `moderate_members` |
| `role` | Adds the configured role to the author | `manage_roles` |

Each acting button is recorded in Red's modlog under that moderator's name, and
the report itself gains a line saying who did what.

`ok` and `no` act on nothing. They record whether a report was right, which is
the only precision data this cog can ever accumulate — every threshold in it was
set from synthetic cases and a hand-written test set.

> **Note:** `[p]watch marks` prints those counts and says plainly that they
> measure precision, not recall. A case the cog missed never produced a report to
> mark.

Buttons are addressed entirely through their own `custom_id`, so a report stays
usable after a restart and the cog keeps no record of a pending one.

A report quotes the channel it came from, so a channel can send its findings
somewhere other than the default with `[p]watch route`. A venting channel's
reports carry what someone wrote there, and fewer people should see those than
see a scam alert. Without a route, reports go to the guild-wide channel.

### Image reading

A channel can have its image attachments read, off by default:

```text
[p]set api messagewatch_vision api_key <key>     # bot owner
[p]watch vision api_base https://openrouter.ai   # bot owner
[p]watch vision model <a model with image input> # bot owner
[p]watch images #一般討論 on                      # guild manager
```

Only the **characters in the image** are asked for, verbatim — not a description
of it. A scam here is a screenshot with text in it, the text is the evidence, and
a description is open-ended generation whose errors nobody can check against the
picture. The transcription goes into the same scam judgement that already exists,
so it needs no rule of its own, and it is shown in the report because the
extraction is generated text with nothing calibrated behind it.

> ⚠️ **The transcription travels twice.** It is shown in the report *and* sent on
> to TypeSafe with the message text, so words that existed only inside an image
> reach both providers.

| Property | Value |
|---|---|
| What is asked of the vision model | Verbatim transcription of the characters, nothing else |
| Before sending | Downscaled and re-encoded, which discards EXIF including GPS tags |
| Cache | By attachment id, at most 256 entries in memory; never on disk; dropped on reload and on a data deletion request |
| Default model | None — see below |
| Endpoint scheme | `https://` only |

There is no default model. Picking one without measuring which reads CJK
screenshots best would be a guess dressed as a default, so the cog sends nothing
until a model and an endpoint are set.

`[p]watch vision` is separate from `[p]watch set` because the latter takes only
numbers — every threshold the cog has — and these two are strings. Both are
stored globally and only the bot owner can write them: the API key they spend is
bot-wide and the owner's, so an administrator of any guild the bot has joined who
could set the endpoint would be able to send that bearer token, and every image,
to a host of their own. Reading them stays open to the managers who have to
configure a channel around them.

> ⚠️ **This is the heaviest thing the cog sends, and the only thing it sends
> anywhere other than TypeSafe.** An image can carry a face, a document, or a
> screenshot of someone else's private conversation. It is decided one channel at
> a time and the disclosure says so.

### Per-channel rules

A channel can also be judged against its own posted rules:

```text
[p]watch rule purpose #樹洞 這裡是倒垃圾的地方，發文的人要的是被聽見，不是被指導
[p]watch rule add #樹洞 下指導棋：告訴發文的人應該怎麼做、給建議或行動方案
[p]watch rule list #樹洞
```

Rules are per channel, because a venting channel's rules would be absurd in a
help channel. A channel with no rules asks exactly what it asked before the
feature existed. The rules become the model's answer options rather than part of
the conversation it reads: option labels have to describe what they select, and
keeping the text out of the state means a member cannot write a rule into it.

Reports name the rule and the message. Where the model is sure a rule was broken
but not sure which one, the report says so instead of picking. A message that
merely *talks about* the rules — pointing out that someone else broke one — is
vetoed by a separate question, because with the rules posted in the channel that
is the most common thing that looks like a violation without being one.

| Measured 2026-09-20, `jev-1.13.0`, real channel ruleset | Result |
|---|---|
| Whether a rule was broken at all (12 held-out cases) | 12/12 |
| Which rule was broken | 11/12 — the miss sat between two adjacent rules on a genuinely borderline phrase |
| False positives among the 5 clean replies | 0 |

Nineteen earlier cases were used while iterating and are not independent
evidence.

### Slash commands

Every command is also a slash command: `/watch enable`, `/watch rule add`,
`/watch set`. The tree is hidden from members who lack Manage Server in Discord's
own UI, which is a display filter — the permission checks still run regardless.

> ⚠️ **Slash commands do not appear until the bot owner runs `[p]slash enable`
> and `[p]slash sync`.** Without that they exist in the cog and are invisible in
> Discord, which looks exactly like the feature not working.

### Settings and diagnostics

| Command | Purpose |
|---|---|
| `[p]watch set` | Print every setting with what it means, what it accepts, and its current value |
| `[p]watch set <key>` | Explain that one setting |
| `[p]watch set <key> <value>` | Change one setting |
| `[p]watch show` | Per watched channel: messages pending, when it was last judged, and the last reason nothing happened |

`[p]watch set` prints meanings rather than a list of key names. As a slash
command the key is a dropdown built from the same table, so it cannot offer a
setting the command would reject.

`[p]watch show` is the diagnostic surface. Without it, a channel whose report
channel lost its permissions looks exactly like a quiet week, because every
failure path in this cog returns silently. Failures are also logged to
`red.nyancogs.messagewatch` with a reason and no message content.

### When a window is judged

| Situation | Behaviour |
|---|---|
| A full window accumulates | Judged immediately; consecutive windows overlap by half, so every message is judged in two windows and an exchange straddling a boundary is still judged together |
| A channel goes quiet short of a full window | Judged after `idle_seconds` (600 by default) with no new message, down to two messages |
| One message and nothing else | Not judged — hostility is a property of an exchange, so it waits for a second message |
| `[p]watch set idle_seconds 0` | Turns the sweep off; only a full window is ever judged |

Without the idle sweep a quiet channel is never judged at all: a venting channel
is a post, two replies and then silence, which is exactly the shape the rules are
for.

Window size, the report cooldown, and all three thresholds are per-guild
settings.

### Measured defaults

Measured 2026-09-20 against `jev-1.13.0`.

| Signal | Positive case | Negative case |
|---|---|---|
| Scam | 0.93 and above | 0.08 for a message *warning about* a phishing mail |
| Hostility | 0.95 | 0.03 for a heated technical argument |

On 97 real messages from the target guild the maxima were 0.05, 0.15 and 1.53
out of 3, so the defaults sit far above observed background.

> **Note:** False negatives are not measured. That sample contained no scam and
> no argument to catch, so the recall of this cog is unverified.

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
